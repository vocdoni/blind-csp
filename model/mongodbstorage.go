package model

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
	"go.vocdoni.io/dvote/log"
)

type MongoStorage struct {
	keysLock      sync.RWMutex
	elections     *mongo.Collection
	users         *mongo.Collection
	userelections *mongo.Collection
}

func (ms *MongoStorage) Init() error {
	var err error
	url := os.Getenv("CSP_MONGODB_URL")
	if url == "" {
		return fmt.Errorf("CSP_MONGODB_URL env var is not defined")
	}
	database := os.Getenv("CSP_DATABASE")
	if database == "" {
		return fmt.Errorf("CSP_DATABASE for mongodb is not defined")
	}
	log.Infow("connecting to mongodb", "url", url, "database", database)
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
		log.Warnw("received SIGTERM, disconnecting mongo database")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		err := client.Disconnect(ctx)
		if err != nil {
			log.Warnw("Disconnect error", "err", err)
		}
		cancel()
	}()

	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	err = client.Ping(ctx, readpref.Primary())
	if err != nil {
		return fmt.Errorf("cannot connect to mongodb: %w", err)
	}
	ms.elections = client.Database(database).Collection("elections")
	ms.users = client.Database(database).Collection("users")
	ms.userelections = client.Database(database).Collection("userelections")

	// Create an index on the 'ElectionId/data' field (used when searching for a user)
	indexModel := mongo.IndexModel{
		Keys: bson.D{
			{Key: "electionId", Value: 1},
			{Key: "data", Value: 1},
		},
	}

	if _, err := ms.userelections.Indexes().CreateOne(context.Background(), indexModel); err != nil {
		log.Fatal(err)
	}

	// If reset flag is enabled, drop database documents
	// TODO: make the reset function part of the storage interface
	if reset := os.Getenv("CSP_RESET_DB"); reset != "" {
		log.Infow("reseting database")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := ms.elections.Drop(ctx); err != nil {
			return err
		}
		if err := ms.users.Drop(ctx); err != nil {
			return err
		}
		if err := ms.userelections.Drop(ctx); err != nil {
			return err
		}
	}
	return nil
}
