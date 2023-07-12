package model_test

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/test"
)

var (
	electionStore     model.ElectionStore
	userelectionStore model.UserelectionStore
	userStore         model.UserStore
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, err := test.StartMongoContainer(ctx)
	if err != nil {
		panic(err)
	}
	defer func() { _ = container.Terminate(ctx) }()

	mongoURI, err := container.Endpoint(ctx, "mongodb")
	if err != nil {
		panic(err)
	}

	_ = os.Setenv("CSP_MONGODB_URL", mongoURI)
	_ = os.Setenv("CSP_DATABASE", test.RandomDatabaseName())
	_ = os.Setenv("CSP_RESET_DB", "true")

	// Storage
	db := &model.MongoStorage{}
	if err := db.Init(); err != nil {
		panic(err)
	}

	electionStore = model.NewElectionStore(db)
	userelectionStore = model.NewUserelectionStore(db)
	userStore = model.NewUserStore(db)

	exitCode := m.Run()

	os.Exit(exitCode)
}

func generateID(length int) string {
	// Initialize random number generator
	rand.New(rand.NewSource(time.Now().UnixNano()))

	// Define character set for ID
	const charset = "0123456789"

	// Generate ID
	id := make([]byte, length)
	for i := range id {
		id[i] = charset[rand.Intn(len(charset))]
	}

	return string(id)
}
