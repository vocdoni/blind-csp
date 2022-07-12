package smshandler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.vocdoni.io/dvote/log"
)

// TODO: check if authToken is unknown or invalid and userID is valid,
// the attempt should not be invalidated.
/// Only if authtoken is known the attempt should be counted!

// MongoStorage uses an external MongoDB service for stoting the user data of the smshandler.
type MongoStorage struct {
	users          *mongo.Collection
	tokenIndex     *mongo.Collection
	keysLock       sync.RWMutex
	maxSmsAttempts int
	coolDownTime   time.Duration
}

func (ms *MongoStorage) Init(dataDir string, maxAttempts int, coolDownTime time.Duration) error {
	var err error
	url := os.Getenv("CSP_MONGODB_URL")
	if url == "" {
		return fmt.Errorf("CSP_MONGODB_URL env var is not defined")
	}
	database := os.Getenv("CSP_DATABASE")
	if database == "" {
		return fmt.Errorf("CSP_DATABASE for mongodb is not defined")
	}
	log.Infof("connecting to mongodb %s@%s", url, database)
	opts := options.Client()
	opts.ApplyURI(url)
	opts.SetMaxConnecting(20)
	timeout := time.Second * 10
	opts.ConnectTimeout = &timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	client, err := mongo.Connect(ctx, options.Client().ApplyURI(url))
	defer cancel()
	if err != nil {
		return err
	}
	// Shutdown database connection when SIGTERM received
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Warnf("received SIGTERM, disconnecting mongo database")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := client.Disconnect(ctx)
		if err != nil {
			log.Warn(err)
		}
		cancel()
	}()

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return fmt.Errorf("cannot connect to mongodb: %w", err)
	}
	ms.users = client.Database(database).Collection("users")
	ms.tokenIndex = client.Database(database).Collection("tokenindex")
	ms.maxSmsAttempts = maxAttempts
	ms.coolDownTime = coolDownTime

	// Create text index on `extra` for finding user data
	ctx, cancel3 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel3()
	index := mongo.IndexModel{
		Keys: bson.D{
			{Key: "extradata", Value: "text"},
		},
	}
	_, err = ms.users.Indexes().CreateOne(ctx, index)
	if err != nil {
		return err
	}

	// If reset flag is enabled, drop database documents
	// TODO: make the reset function part of the storage interface
	if reset := os.Getenv("CSP_RESET_DB"); reset != "" {
		log.Infof("reseting database")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = ms.users.Drop(ctx); err != nil {
			return err
		}
	}
	return nil
}

func (ms *MongoStorage) MaxAttempts() int {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	return ms.maxSmsAttempts
}

func (ms *MongoStorage) Users() (*Users, error) {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	opts := options.FindOptions{}
	opts.SetProjection(bson.M{"_id": true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := ms.users.Find(ctx, bson.M{}, &opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var users Users
	for cur.Next(ctx) {
		user := UserData{}
		err := cur.Decode(&user)
		if err != nil {
			log.Warn(err)
		}
		users.Users = append(users.Users, user.UserID)
	}
	return &users, nil
}

func (ms *MongoStorage) AddUser(userID types.HexBytes, processIDs []types.HexBytes,
	phone, extra string) error {
	phoneNum, err := phonenumbers.Parse(phone, DefaultPhoneCountry)
	if err != nil {
		return err
	}
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()

	maxAttempts := ms.maxSmsAttempts * len(processIDs)
	// nolint[:ineffassign]
	if maxAttempts == 0 {
		maxAttempts = ms.maxSmsAttempts
	}
	user := UserData{
		UserID:    userID,
		ExtraData: extra,
		Phone:     phoneNum,
	}
	user.Elections = make(map[string]UserElection, len(processIDs))
	for _, e := range HexBytesToElection(processIDs, ms.maxSmsAttempts) {
		user.Elections[e.ElectionID.String()] = e
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = ms.users.InsertOne(ctx, user)
	return err
}

func (ms *MongoStorage) User(userID types.HexBytes) (*UserData, error) {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	user, err := ms.getUserData(userID)
	if err != nil {
		return nil, err
	}
	return user, nil
}

func (ms *MongoStorage) getUserData(userID types.HexBytes) (*UserData, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := ms.users.FindOne(ctx, bson.M{"_id": userID})
	var user UserData
	if err := result.Decode(&user); err != nil {
		log.Warn(err)
		return nil, ErrUserUnknown
	}
	return &user, nil
}

func (ms *MongoStorage) updateUser(user *UserData) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ms.users.ReplaceOne(ctx, bson.M{"_id": user.UserID}, user)
	if err != nil {
		return fmt.Errorf("cannot update object: %w", err)
	}
	return nil
}

func (ms *MongoStorage) UpdateUser(udata *UserData) error {
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()
	return ms.updateUser(udata)
}

func (ms *MongoStorage) BelongsToElection(userID types.HexBytes,
	electionID types.HexBytes) (bool, error) {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	user, err := ms.getUserData(userID)
	if err != nil {
		return false, err
	}
	_, ok := user.Elections[electionID.String()]
	return ok, nil
}

func (ms *MongoStorage) SetAttempts(userID, electionID types.HexBytes, delta int) error {
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()

	user, err := ms.getUserData(userID)
	if err != nil {
		return err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return ErrUserNotBelongsToElection
	}
	election.RemainingAttempts += delta
	user.Elections[electionID.String()] = election
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = ms.users.ReplaceOne(ctx, bson.M{"_id": userID}, user)
	if err != nil {
		return fmt.Errorf("cannot update object: %w", err)
	}
	return nil
}

func (ms *MongoStorage) NewAttempt(userID, electionID types.HexBytes,
	challenge int, token *uuid.UUID) (*phonenumbers.PhoneNumber, error) {
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()

	user, err := ms.getUserData(userID)
	if err != nil {
		return nil, err
	}

	election, ok := user.Elections[electionID.String()]
	if !ok {
		return nil, ErrUserNotBelongsToElection
	}

	// Check if the CSP signature is already consumed for the user/election
	if election.Consumed {
		return nil, ErrUserAlreadyVerified
	}
	// Check cool down time
	if election.LastAttempt != nil {
		if time.Now().Before(election.LastAttempt.Add(ms.coolDownTime)) {
			return nil, ErrAttemptCoolDownTime
		}
	}
	// Check remaining attempts
	if election.RemainingAttempts < 1 {
		return nil, ErrTooManyAttempts
	}
	// Save new data
	election.AuthToken = token
	election.Challenge = challenge
	t := time.Now()
	election.LastAttempt = &t
	user.Elections[electionID.String()] = election
	if err := ms.updateUser(user); err != nil {
		return nil, err
	}

	// Save the token as index for finding the userID
	atindex := AuthTokenIndex{
		AuthToken: token,
		UserID:    user.UserID,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = ms.tokenIndex.InsertOne(ctx, atindex)

	return user.Phone, err
}

func (ms *MongoStorage) Exists(userID types.HexBytes) bool {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	_, err := ms.getUserData(userID)
	return err == nil
}

func (ms *MongoStorage) Verified(userID, electionID types.HexBytes) (bool, error) {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	user, err := ms.getUserData(userID)
	if err != nil {
		return false, err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return false, ErrUserNotBelongsToElection
	}
	return election.Consumed, nil
}

func (ms *MongoStorage) VerifyChallenge(electionID types.HexBytes,
	token *uuid.UUID, solution int) error {
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()

	// fetch the user ID by token
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result := ms.tokenIndex.FindOne(ctx, bson.M{"_id": token})
	var atIndex AuthTokenIndex
	if err := result.Decode(&atIndex); err != nil {
		log.Warnf("cannot fetch auth token: %v", err)
		return ErrInvalidAuthToken
	}

	// with the user ID fetch the user data
	user, err := ms.getUserData(atIndex.UserID)
	if err != nil {
		return err
	}

	// find the election and check the solution
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return ErrUserNotBelongsToElection
	}
	if election.Consumed {
		return ErrUserAlreadyVerified
	}
	if election.AuthToken == nil {
		return fmt.Errorf("no auth token available for this election")
	}
	if election.AuthToken.String() != token.String() {
		return ErrInvalidAuthToken
	}

	// clean token data (we only allow 1 chance)
	election.AuthToken = nil
	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := ms.tokenIndex.DeleteOne(ctx, bson.M{"_id": token}); err != nil {
		return err
	}

	// set consumed to true or false depending on the challenge solution
	election.Consumed = election.Challenge == solution

	// save the user data
	user.Elections[electionID.String()] = election
	if err := ms.updateUser(user); err != nil {
		return err
	}

	// return error if the solution does not match the challenge
	if election.Challenge != solution {
		return ErrChallengeCodeFailure
	}

	return nil
}

func (ms *MongoStorage) DelUser(userID types.HexBytes) error {
	ms.keysLock.Lock()
	defer ms.keysLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := ms.users.DeleteOne(ctx, bson.M{"_id": userID})
	return err
}

func (ms *MongoStorage) Search(term string) (*Users, error) {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()
	opts := options.FindOptions{}
	opts.SetProjection(bson.M{"_id": true})
	filter := bson.M{"$text": bson.M{"$search": term}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := ms.users.Find(ctx, filter, &opts)
	if err != nil {
		return nil, err
	}
	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	var users Users
	for cur.Next(ctx) {
		user := UserData{}
		err := cur.Decode(&user)
		if err != nil {
			log.Warn(err)
		}
		users.Users = append(users.Users, user.UserID)
	}
	return &users, nil
}

func (ms *MongoStorage) String() string {
	ms.keysLock.RLock()
	defer ms.keysLock.RUnlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := ms.users.Find(ctx, bson.D{{}})
	if err != nil {
		log.Warn(err)
		return "{}"
	}

	ctx2, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var output strings.Builder
	var user UserData
	output.WriteString("\n")
	for cur.Next(ctx2) {
		err := cur.Decode(&user)
		if err != nil {
			log.Warn(err)
		}
		data, err := json.MarshalIndent(user, "", " ")
		if err != nil {
			log.Warn(err)
		}
		output.Write(data)
	}
	return output.String()
}
