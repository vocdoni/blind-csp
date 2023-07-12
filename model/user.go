package model

import (
	"context"
	"fmt"
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

// Userelection is the struct for a user in an election
type User struct {
	ID      types.HexBytes `json:"userId" bson:"_id"`
	Handler string         `json:"handler" bson:"handler"`
	Service string         `json:"service" bson:"service"`
	Mode    string         `json:"mode" bson:"mode"`
	Data    string         `json:"data" bson:"data"`
}

type UserComplete struct {
	ID        types.HexBytes `json:"userId" bson:"_id"`
	Handler   string         `json:"handler" bson:"handler"`
	Service   string         `json:"service" bson:"service"`
	Mode      string         `json:"mode" bson:"mode"`
	Data      string         `json:"data" bson:"data"`
	Elections []Userelection `json:"elections" bson:"elections"`
}

// UserRequest is the request interface for the provided data
type UserRequest struct {
	UserID  string `json:"userId"`
	Handler string `json:"handler"`
	Service string `json:"service"`
	Mode    string `json:"mode"`
	Data    string `json:"data"`
}

type UserStore interface {
	CreateOrGetUser(handler HandlerConfig, userData string) (*User, error)
	User(userID types.HexBytes) (*User, error)
	SearchUser(userR UserRequest) (*[]User, error)
}

type userStore struct {
	db *MongoStorage
}

// NewUserStore returns a new UserStore
func NewUserStore(db *MongoStorage) UserStore {
	return &userStore{db: db}
}

// CreateOrGetUser creates a new user or returns an existing one
func (store *userStore) CreateOrGetUser(handler HandlerConfig, userData string) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var found User
	result := store.db.users.FindOne(ctx, bson.M{
		"handler": handler.Handler,
		"service": handler.Service,
		"mode":    handler.Mode,
		"data":    userData,
	})
	if error := result.Decode(&found); error == nil {
		return &found, nil
	}

	userElectionIDSize := 32
	user := User{
		ID:      randomBytes(userElectionIDSize),
		Handler: handler.Handler,
		Service: handler.Service,
		Mode:    handler.Mode,
		Data:    userData,
	}

	if _, err := store.db.users.InsertOne(ctx, user); err != nil {
		return nil, err
	}

	return &user, nil
}

// User returns a user by ID
func (store *userStore) User(userID types.HexBytes) (*User, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var user User
	result := store.db.users.FindOne(ctx, bson.M{"_id": userID})
	if err := result.Decode(&user); err != nil {
		log.Warnw("Error finding the user", "err", err)
		return nil, ErrUserelectionUnknown
	}
	return &user, nil
}

func (store *userStore) SearchUser(userR UserRequest) (*[]User, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var userID types.HexBytes
	if err := userID.FromString(userR.UserID); err != nil {
		return nil, err
	}

	var cur *mongo.Cursor
	filter := bson.M{}
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

	cur, err := store.db.users.Find(ctx, filter, &opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var users []User

	for cur.Next(ctx) {
		user := User{}
		err := cur.Decode(&user)
		if err != nil {
			log.Warnw("Error finding the user", "err", err)
		}
		users = append(users, user)
	}

	return &users, nil
}
