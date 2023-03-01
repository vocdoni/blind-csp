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
	ErrUserUnknown = fmt.Errorf("user is unknown")
	// ErrUserDuplicated is returned when the user is duplicated
	ErrUserDuplicated = fmt.Errorf("user is duplicated")
)

// UserRequest is the request interface for the provided data
type UserRequest struct {
	UserID   string `json:"userId"`
	Handler  string `json:"handler"`
	Service  string `json:"service"`
	Mode     string `json:"mode"`
	Data     string `json:"data"`
	Consumed *bool  `json:"consumed,omitempty"`
}

// User is the struct for a user in an election
type User struct {
	ID         types.HexBytes `json:"userId" bson:"_id"`
	ElectionID types.HexBytes `json:"electionId" bson:"electionId"`
	Handler    string         `json:"handler" bson:"handler"`
	Service    string         `json:"service" bson:"service"`
	Mode       string         `json:"mode" bson:"mode"`
	Data       string         `json:"data" bson:"data"`
	Consumed   *bool          `json:"consumed" bson:"consumed"`
}

// UserStore is the interface to manage users
type UserStore interface {
	CreateUser(electionID types.HexBytes, handler HandlerConfig, userData string) (*User, error)
	User(electionID types.HexBytes, userID types.HexBytes) (*User, error)
	UpdateUser(electionID types.HexBytes, userID types.HexBytes, userR UserRequest) (*User, error)
	DeleteUser(electionID types.HexBytes, userID types.HexBytes) error
	ListUser(electionID types.HexBytes) (*[]User, error)
	SearchUser(electionID types.HexBytes, userR UserRequest) (*[]User, error)
}

// userStore is the implementation of UserStore
type userStore struct {
	db *MongoStorage
}

// NewUserStore returns a new UserStore
func NewUserStore(db *MongoStorage) UserStore {
	return &userStore{db: db}
}

func (store *userStore) CreateUser(electionID types.HexBytes, handler HandlerConfig, userData string) (*User, error) {
	userElectionIDSize := 32
	userID := randomBytes(userElectionIDSize)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var found User
	result := store.db.users.FindOne(ctx, bson.M{
		"electionId": electionID,
		"handler":    handler.Handler,
		"service":    handler.Service,
		"mode":       handler.Mode,
		"data":       userData,
	})
	if error := result.Decode(&found); error == nil {
		log.Warnw("User already exists", "User found", found)
		return nil, ErrUserDuplicated
	}

	notConsumed := false
	userElection := User{
		ID:         userID,
		ElectionID: electionID,
		Handler:    handler.Handler,
		Service:    handler.Service,
		Mode:       handler.Mode,
		Data:       userData,
		Consumed:   &notConsumed,
	}

	if _, err := store.db.users.InsertOne(ctx, userElection); err != nil {
		return nil, err
	}

	return &userElection, nil
}

// User returns the user for the given electionID and userID
func (store *userStore) User(electionID types.HexBytes, userID types.HexBytes) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	result := store.db.users.FindOne(ctx, bson.M{"_id": userID, "electionId": electionID})
	if err := result.Decode(&user); err != nil {
		log.Warnw("Error finding the user", "err", err)
		return nil, ErrUserUnknown
	}
	return &user, nil
}

// UpdateUser updates the user for the given electionID and userID
func (store *userStore) UpdateUser(electionID types.HexBytes, userID types.HexBytes, userR UserRequest) (*User, error) {
	user, err := store.User(electionID, userID)
	if err != nil {
		return nil, err
	}

	user.Consumed = userR.Consumed

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	opts := options.ReplaceOptions{}
	if _, err = store.db.users.ReplaceOne(ctx, bson.M{"_id": user.ID}, user, &opts); err != nil {
		return nil, err
	}

	user, err = store.User(electionID, userID)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// DeleteUser deletes the user for the given electionID and userID
func (store *userStore) DeleteUser(electionID types.HexBytes, userID types.HexBytes) error {
	store.db.keysLock.Lock()
	defer store.db.keysLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := store.db.users.DeleteOne(ctx, bson.M{"_id": userID, "electionId": electionID})
	return err
}

// ListUser returns the list of users for the given electionID
func (store *userStore) ListUser(electionID types.HexBytes) (*[]User, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Filter by electionID if provided
	var cur *mongo.Cursor
	var err error
	if len(electionID) > 0 {
		cur, err = store.db.users.Find(ctx, bson.M{"electionId": electionID}, &opts)
	} else {
		cur, err = store.db.users.Find(ctx, bson.M{}, &opts)
	}

	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var users []User

	for cur.Next(ctx) {
		userElection := User{}
		err := cur.Decode(&userElection)
		if err != nil {
			log.Warnw("Error finding the user", "err", err)
		}
		users = append(users, userElection)
	}

	return &users, nil
}

// SearchUser returns the list of users for the given electionID
func (store *userStore) SearchUser(electionID types.HexBytes, userR UserRequest) (*[]User, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Filter by electionID if provided
	var cur *mongo.Cursor
	var err error

	var userID types.HexBytes
	if err := userID.FromString(userR.UserID); err != nil {
		return nil, err
	}

	// Find in mongo filtering by the params of UserRequest if present and not empty
	filter := bson.M{}
	if len(electionID) > 0 {
		filter["electionId"] = electionID
	}
	if len(userID) > 0 {
		filter["_id"] = userID
	}
	if userR.Handler != "" {
		filter["handler"] = userR.Handler
	}
	if userR.Service != "" {
		filter["service"] = userR.Service
	}
	if userR.Mode != "" {
		filter["mode"] = userR.Mode
	}
	if userR.Data != "" {
		filter["data"] = userR.Data
	}
	if userR.Consumed != nil {
		filter["consumed"] = &userR.Consumed
	}

	cur, err = store.db.users.Find(ctx, filter, &opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var users []User

	for cur.Next(ctx) {
		userElection := User{}
		err := cur.Decode(&userElection)
		if err != nil {
			log.Warnw("Error finding the user", "err", err)
		}
		users = append(users, userElection)
	}

	return &users, nil
}

func randomBytes(n int) []byte {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		panic(err)
	}
	return bytes
}
