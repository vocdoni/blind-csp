package model

import (
	"context"
	"fmt"
	"time"

	"github.com/vocdoni/blind-csp/types"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.vocdoni.io/dvote/log"
	"go.vocdoni.io/dvote/vochain/processid"
	"go.vocdoni.io/proto/build/go/models"
)

// ErrElectionUnknown is returned when the election is not found
var ErrElectionUnknown = fmt.Errorf("election is unknown")

// ErrElectionUnknown is returned when the election is invalid
var ErrElectionInvalid = fmt.Errorf("election invalid")

// HandlerConfig is the configuration of a handler
type HandlerConfig struct {
	Handler string   `json:"handler" bson:"handler"`
	Service string   `json:"service" bson:"service"`
	Mode    string   `json:"mode" bson:"mode"`
	Data    []string `json:"data" bson:"data"`
}

// Election is the configuration of an election
type Election struct {
	ID       types.HexBytes  `json:"electionId" bson:"_id"`
	Handlers []HandlerConfig `json:"handlers" bson:"handlers"` // List of handlers that will use this census
}

// ElectionStore is the interface to manage elections
type ElectionStore interface {
	CreateElection(election *Election) (*Election, error)
	Election(id types.HexBytes) (*Election, error)
	DeleteElection(id types.HexBytes) error
	ListElection() (*[]types.HexBytes, error)
}

// electionStore is the implementation of ElectionStore
type electionStore struct {
	db *MongoStorage
}

// NewElectionStore returns a new ElectionStore
func NewElectionStore(db *MongoStorage) ElectionStore {
	return &electionStore{db: db}
}

// CreateElection creates a new election including the census data
func (store *electionStore) CreateElection(election *Election) (*Election, error) {
	// Verify if the election census belongs to the CSP
	p := processid.ProcessID{}
	err := p.Unmarshal(election.ID)
	if err != nil || p.CensusOrigin() != models.CensusOrigin_OFF_CHAIN_CA {
		log.Warnw("Error! Election census is not from the CSP", "electionId", election.ID, "censusOrigin", p.CensusOrigin())
		return nil, ErrElectionInvalid
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if _, err := store.db.elections.InsertOne(ctx, election); err != nil {
		return nil, err
	}

	// Foreach handler in census data, create a User
	userStore := NewUserStore(store.db) // This is a bit ugly, but it's the only way to avoid services
	for _, handler := range election.Handlers {
		for _, userData := range handler.Data {
			if _, err := userStore.CreateUser(election.ID, handler, userData); err != nil {
				return nil, err
			}
		}
	}

	created, err := store.Election(election.ID)
	if err != nil {
		return nil, err
	}

	return created, nil
}

// Election returns an election
func (store *electionStore) Election(electionID types.HexBytes) (*Election, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var election Election
	result := store.db.elections.FindOne(ctx, bson.M{"_id": electionID})
	if err := result.Decode(&election); err != nil {
		log.Warnw("Error finding the Election", "err", err)
		return nil, ErrElectionUnknown
	}
	return &election, nil
}

// DeleteElection deletes an election
func (store *electionStore) DeleteElection(electionID types.HexBytes) error {
	store.db.keysLock.Lock()
	defer store.db.keysLock.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := store.db.elections.DeleteOne(ctx, bson.M{"_id": electionID})
	return err
}

// ListElection returns a list of elections
func (store *electionStore) ListElection() (*[]types.HexBytes, error) {
	store.db.keysLock.RLock()
	defer store.db.keysLock.RUnlock()
	opts := options.FindOptions{}
	opts.SetProjection(bson.M{"_id": true})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cur, err := store.db.elections.Find(ctx, bson.M{}, &opts)
	if err != nil {
		return nil, err
	}

	ctx, cancel2 := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel2()
	var elections []types.HexBytes

	for cur.Next(ctx) {
		election := Election{}
		err := cur.Decode(&election)
		if err != nil {
			log.Warnw("Error decoding the Election data", "err", err)
		}
		elections = append(elections, election.ID)
	}

	return &elections, nil
}
