package model_test

import (
	"context"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/strikesecurity/strikememongo"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/vocdoni/blind-csp/model"
)

// mongodbContainer represents the mongodb container type used in the module
type mongodbContainer struct {
	testcontainers.Container
}

var (
	electionStore model.ElectionStore
	userStore     model.UserStore
)

func TestMain(m *testing.M) {
	ctx := context.Background()
	container, _ := startMongoContainer(ctx)
	mongoURI, _ := container.Endpoint(ctx, "mongodb")

	_ = os.Setenv("CSP_MONGODB_URL", mongoURI)
	_ = os.Setenv("CSP_DATABASE", strikememongo.RandomDatabase())
	_ = os.Setenv("CSP_RESET_DB", "true")

	// Storage
	db := &model.MongoStorage{}
	if err := db.Init(); err != nil {
		panic(err)
	}

	electionStore = model.NewElectionStore(db)
	userStore = model.NewUserStore(db)

	exitCode := m.Run()

	_ = container.Terminate(ctx)

	os.Exit(exitCode)
}

// startMongoContainer creates an instance of the mongodb container type
func startMongoContainer(ctx context.Context) (*mongodbContainer, error) {
	req := testcontainers.ContainerRequest{
		Image:        "mongo:6",
		ExposedPorts: []string{"27017/tcp"},
		WaitingFor: wait.ForAll(
			wait.ForLog("Waiting for connections"),
			wait.ForListeningPort("27017/tcp"),
		),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	return &mongodbContainer{Container: container}, nil
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
