package model

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/vocdoni/blind-csp/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.vocdoni.io/dvote/log"
)

var (
	// ErrUserUnknown is returned when the user is not found
	ErrUserelectionUnknown = fmt.Errorf("user is unknown")
	// ErrUserDuplicated is returned when the user is duplicated
	ErrUserelectionDuplicated = fmt.Errorf("user is duplicated")
)

// UserelectionRequest is the request interface for the provided data
type UserelectionRequest struct {
	UserID   string `json:"userId"`
	Handler  string `json:"handler"`
	Service  string `json:"service"`
	Mode     string `json:"mode"`
	Data     string `json:"data"`
	Consumed *bool  `json:"consumed,omitempty"`
}

// Userelection is the struct for a user in an election
type Userelection struct {
	UserID     types.HexBytes `json:"userId" bson:"userId"`
	ElectionID types.HexBytes `json:"electionId" bson:"electionId"`
	Consumed   *bool          `json:"consumed" bson:"consumed"`
}

type UserelectionComplete struct {
	UserID     types.HexBytes `json:"userId" bson:"userId"`
	ElectionID types.HexBytes `json:"electionId" bson:"electionId"`
	User       User           `json:"user" bson:"user"`
	Consumed   *bool          `json:"consumed" bson:"consumed"`
}

// UserelectionStore is the interface to manage users
type UserelectionStore interface {
	CreateUserelection(electionID types.HexBytes, handler HandlerConfig, userData string) (*UserelectionComplete, error)
	Userelection(electionID types.HexBytes, userID types.HexBytes) (*UserelectionComplete, error)
	UpdateUserelection(electionID types.HexBytes, userID types.HexBytes, userR UserelectionRequest) (*UserelectionComplete, error)
	DeleteUserelection(electionID types.HexBytes, userID types.HexBytes) error
	ListUserelection(electionID types.HexBytes) (*[]UserelectionComplete, error)
	SearchUserelection(electionID types.HexBytes, userR UserelectionRequest) (*[]UserelectionComplete, error)
	GetUserElections(userID types.HexBytes) (*UserComplete, error)
}

// userelectionStore is the implementation of UserelectionStore
type userelectionStore struct {
	db *MongoStorage
}

// NewUserelectionStore returns a new UserelectionStore
func NewUserelectionStore(db *MongoStorage) UserelectionStore {
	return &userelectionStore{db: db}
}

// CreateUserelection creates a new user or returns an existing one
func (store *userelectionStore) CreateUserelection(electionID types.HexBytes,
	handler HandlerConfig, userData string,
) (*UserelectionComplete, error) {
	// Get the user
	userStore := NewUserStore(store.db)
	user, err := userStore.CreateOrGetUser(handler, userData)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var found Userelection
	result := store.db.userelections.FindOne(ctx, bson.M{
		"userId":     user.ID,
		"electionId": electionID,
	})
	if error := result.Decode(&found); error == nil {
		log.Warnw("Userelection already exists", "Userelection found", found)
		return nil, ErrUserelectionDuplicated
	}

	notConsumed := false
	userElection := Userelection{
		UserID:     user.ID,
		ElectionID: electionID,
		Consumed:   &notConsumed,
	}

	if _, err := store.db.userelections.InsertOne(ctx, userElection); err != nil {
		return nil, err
	}

	return store.Userelection(userElection.ElectionID, userElection.UserID)
}

// Userelection returns the user for the given electionID and userID
func (store *userelectionStore) Userelection(electionID types.HexBytes, userID types.HexBytes) (*UserelectionComplete, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var userelection UserelectionComplete
	result := store.db.userelections.FindOne(ctx, bson.M{"userId": userID, "electionId": electionID})
	if err := result.Decode(&userelection); err != nil {
		log.Warnw("Error finding the userelection", "err", err)
		return nil, ErrUserelectionUnknown
	}

	var user User
	result = store.db.users.FindOne(ctx, bson.M{"_id": userelection.UserID})
	if err := result.Err(); err != nil {
		log.Warnw("Error finding the user", "err", err)
	}
	if err := result.Decode(&user); err != nil {
		log.Warnw("Error finding the user", "err", err)
	}
	userelection.User = user

	return &userelection, nil
}

// UpdateUserelection updates the user for the given electionID and userID
func (store *userelectionStore) UpdateUserelection(electionID types.HexBytes,
	userID types.HexBytes, userR UserelectionRequest,
) (*UserelectionComplete, error) {
	userelection, err := store.Userelection(electionID, userID)
	if err != nil {
		return nil, err
	}

	userelection.Consumed = userR.Consumed

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.ReplaceOptions{}
	if _, err = store.db.userelections.ReplaceOne(ctx, bson.M{"userId": userelection.UserID, "electionId": userelection.ElectionID},
		userelection, &opts); err != nil {
		return nil, err
	}

	return store.Userelection(electionID, userID)
}

// DeleteUserelection deletes the user for the given electionID and userID
func (store *userelectionStore) DeleteUserelection(electionID types.HexBytes, userID types.HexBytes) error {
	store.db.keysLock.Lock()
	defer store.db.keysLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := store.db.userelections.DeleteOne(ctx, bson.M{"userId": userID, "electionId": electionID})
	return err
}

// ListUserelection returns the list of users for the given electionID
func (store *userelectionStore) ListUserelection(electionID types.HexBytes) (*[]UserelectionComplete, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Filter by electionID if provided
	var cur *mongo.Cursor
	var err error
	if len(electionID) > 0 {
		cur, err = store.db.userelections.Find(ctx, bson.M{"electionId": electionID}, &opts)
	} else {
		cur, err = store.db.userelections.Find(ctx, bson.M{}, &opts)
	}

	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var userelections []UserelectionComplete

	for cur.Next(ctx) {
		userElection := UserelectionComplete{}
		err := cur.Decode(&userElection)
		if err != nil {
			log.Warnw("Error finding the userelection", "err", err)
		}

		var user User
		result := store.db.users.FindOne(ctx, bson.M{"_id": userElection.UserID})
		if err := result.Err(); err != nil {
			log.Warnw("Error finding the user", "err", err)
		}
		if err := result.Decode(&user); err != nil {
			log.Warnw("Error finding the user", "err", err)
		}

		userElection.User = user
		userelections = append(userelections, userElection)
	}

	return &userelections, nil
}

// SearchUserelection returns the list of users for the given electionID
func (store *userelectionStore) SearchUserelection(electionID types.HexBytes,
	userR UserelectionRequest,
) (*[]UserelectionComplete, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	userStore := NewUserStore(store.db)
	ur := UserRequest{
		UserID:  userR.UserID,
		Handler: userR.Handler,
		Service: userR.Service,
		Mode:    userR.Mode,
		Data:    userR.Data,
	}
	users, err := userStore.SearchUser(ur)
	if err != nil {
		return nil, err
	}
	// Create a slice to store the user IDs
	var userIDs []types.HexBytes

	// Iterate over the users and extract their IDs
	for _, user := range *users {
		userIDs = append(userIDs, user.ID)
	}

	// Find in mongo filtering by the params of UserelectionRequest if present and not empty
	filter := bson.M{}
	if len(electionID) > 0 {
		filter["electionId"] = electionID
	}
	if len(userIDs) > 0 {
		filter["userId"] = bson.M{"$in": userIDs}
	}
	if userR.Consumed != nil {
		filter["consumed"] = &userR.Consumed
	}

	var cur *mongo.Cursor
	cur, err = store.db.userelections.Find(ctx, filter, &opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var userelections []UserelectionComplete

	for cur.Next(ctx) {
		userElection := UserelectionComplete{}
		err := cur.Decode(&userElection)
		if err != nil {
			log.Warnw("Error finding the user", "err", err)
		}

		var user User
		result := store.db.users.FindOne(ctx, bson.M{"_id": userElection.UserID})
		if err := result.Err(); err != nil {
			log.Warnw("Error finding the user", "err", err)
		}
		if err := result.Decode(&user); err != nil {
			log.Warnw("Error finding the user", "err", err)
		}

		userElection.User = user

		userelections = append(userelections, userElection)
	}

	return &userelections, nil
}

// GetUserElections returns the list of elections the given userID
func (store *userelectionStore) GetUserElections(userID types.HexBytes) (*UserComplete, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	user := UserComplete{}
	result := store.db.users.FindOne(ctx, bson.M{"_id": userID})
	if err := result.Err(); err != nil {
		log.Warnw("Error finding the user", "err", err)
	}
	if err := result.Decode(&user); err != nil {
		log.Warnw("Error finding the user", "err", err)
	}

	var cur *mongo.Cursor
	cur, err := store.db.userelections.Find(ctx, bson.M{"userId": userID}, &opts)
	if err != nil {
		return nil, err
	}

	for cur.Next(ctx) {
		userElection := Userelection{}
		err := cur.Decode(&userElection)
		if err != nil {
			log.Warnw("Error finding the election", "err", err)
		}

		user.Elections = append(user.Elections, userElection)
	}

	return &user, nil
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}
