package admin

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/model"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/apirest"
	"go.vocdoni.io/dvote/log"
)

const bearerTokenReqAmount = 100000000

// Admin is the main struct for the admin API, containing all the controllers, router and storage
type Admin struct {
	router             *httprouter.HTTProuter
	api                *apirest.API
	storage            *model.MongoStorage
	electionController *ElectionController
	userController     *UserController
}

// NewAdmin creates a new Admin instance by initializing the storage and controllers
func NewAdmin() (*Admin, error) {
	mongoStorage := model.MongoStorage{}

	return &Admin{
		storage:            &mongoStorage,
		electionController: NewElectionController(model.NewElectionStore(&mongoStorage)),
		userController:     NewUserController(model.NewUserStore(&mongoStorage)),
	}, mongoStorage.Init()
}

// ServeAPI registers the admin API handlers to the router
func (admin *Admin) ServeAPI(r *httprouter.HTTProuter, baseRoute string) error {
	if !strings.HasPrefix(baseRoute, "/") {
		return fmt.Errorf("invalid base route %q, it must start with /", baseRoute)
	}

	// Remove trailing slash
	if len(baseRoute) > 1 {
		baseRoute = strings.TrimSuffix(baseRoute, "/")
	}
	if r == nil {
		return fmt.Errorf("router is nil")
	}

	var authToken []string
	if len(authToken) == 0 {
		authToken = strings.Split(os.Getenv("ADMINAPI_AUTHTOKEN"), ",")
	}

	// Initialize API
	admin.router = r
	var err error
	admin.api, err = apirest.NewAPI(admin.router, baseRoute)
	if err != nil {
		return err
	}

	// Set bearer authentication
	if len(authToken) == 0 || authToken[0] == "" {
		authToken = []string{uuid.New().String()}
	}

	for _, at := range authToken {
		admin.api.AddAuthToken(at, bearerTokenReqAmount)
	}
	log.Infow("using bearer authentication token", "token", authToken)

	return admin.registerHandlers()
}

// registerHandlers registers all the admin API handlers
func (admin *Admin) registerHandlers() error {
	if err := admin.api.RegisterMethod(
		"/elections",
		"GET",
		apirest.MethodAccessTypePublic,
		admin.electionController.List,
	); err != nil {
		return err
	}

	// Create census and link it to a new election
	if err := admin.api.RegisterMethod(
		"/elections",
		"POST",
		apirest.MethodAccessTypePublic,
		admin.electionController.Create,
	); err != nil {
		return err
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/auth",
		"POST",
		apirest.MethodAccessTypePublic,
		admin.electionController.AdminToken,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}",
		"GET",
		apirest.MethodAccessTypePublic,
		admin.electionController.Election,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}",
		"DELETE",
		apirest.MethodAccessTypePublic,
		admin.electionController.Delete,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users",
		"GET",
		apirest.MethodAccessTypePublic,
		admin.userController.List,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users",
		"POST",
		apirest.MethodAccessTypePublic,
		admin.userController.Create,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users/{userId}",
		"GET",
		apirest.MethodAccessTypePublic,
		admin.userController.User,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users/{userId}",
		"PUT",
		apirest.MethodAccessTypePublic,
		admin.userController.Update,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users/{userId}",
		"DELETE",
		apirest.MethodAccessTypePublic,
		admin.userController.Delete,
	); err != nil {
		log.Fatal(err)
	}

	if err := admin.api.RegisterMethod(
		"/elections/{electionId}/users/search",
		"POST",
		apirest.MethodAccessTypePublic,
		admin.userController.Search,
	); err != nil {
		log.Fatal(err)
	}

	return nil
}
