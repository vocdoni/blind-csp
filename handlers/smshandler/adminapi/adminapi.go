package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.vocdoni.io/dvote/httprouter/bearerstdapi"
	"go.vocdoni.io/dvote/log"

	"github.com/google/uuid"
	flag "github.com/spf13/pflag"
	"github.com/vocdoni/blind-csp/handlers/smshandler"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
)

const respOK = `{"ok":"true"}`

var storage smshandler.Storage

func main() {
	var tlsDomain, logLevel, authToken string
	var port int
	flag.StringVar(&tlsDomain, "tlsDomain", "", "domain name for TLS certificate")
	flag.IntVar(&port, "port", 5001, "port for the API")
	// nolint[:lll]
	flag.StringVar(&authToken, "authToken", "", "bearer token for authentication (empty autogenerates)")
	flag.StringVar(&logLevel, "logLevel", "info",
		"log level {debug,info,warn,error}")
	// nolint[:lll]
	fmt.Printf("ENV vars: ADMINAPI_TLSDOMAIN ADMINAPI_LOGLEVEL ADMINAPI_AUTHTOKEN ADMINAPI_PORT CSP_MONGODB_URL CSP_DATABASE\n")
	flag.Parse()

	// Set the ENV vars
	if tlsDomain == "" {
		tlsDomain = os.Getenv("ADMINAPI_TLSDOMAIN")
	}
	if logLevel == "info" && os.Getenv("ADMINAPI_LOGLEVEL") != "" {
		logLevel = os.Getenv("ADMINAPI_LOGLEVEL")
	}
	if authToken == "" {
		authToken = os.Getenv("ADMINAPI_AUTHTOKEN")
	}
	var err error
	if port == 5001 && os.Getenv("ADMINAPI_PORT") != "" {
		port, err = strconv.Atoi(os.Getenv("ADMINAPI_PORT"))
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Init(logLevel, "stdout")
	// Create the HTTP router
	router := httprouter.HTTProuter{}
	router.TLSdomain = tlsDomain
	router.TLSdirCert = "tls"

	// Start the router
	if err := router.Init("0.0.0.0", port); err != nil {
		log.Fatal(err)
	}

	// Create the Bearer API attached to the router
	api, err := bearerstdapi.NewBearerStandardAPI(&router, "/smsapi")
	if err != nil {
		log.Fatal(err)
	}

	// Set bearer authentication
	if authToken == "" {
		authToken = uuid.New().String()
	}
	api.AddAuthToken(authToken, 1000000)
	log.Infof("using bearer authentication token %s", authToken)

	storage = &smshandler.MongoStorage{}
	if err := storage.Init("", 5, time.Second); err != nil {
		log.Fatal(err)
	}

	// Register methods
	if err := api.RegisterMethod(
		"/ping",
		"GET",
		bearerstdapi.MethodAccessTypePublic,
		ping,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/dump",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		dump,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/users",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		users,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/user/{userid}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		user,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/addAttempt/{userid}/{electionid}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		addAttempt,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/setConsumed/{userid}/{electionid}/{consumed}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		setConsumed,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/cloneUser/{olduserid}/{newuserid}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		cloneUser,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/delUser/{userid}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		delUser,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/newUser/{userid}",
		"POST",
		bearerstdapi.MethodAccessTypePrivate,
		newUser,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/addElection/{userid}/{electionid}",
		"GET",
		bearerstdapi.MethodAccessTypePrivate,
		addElection,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/search",
		"POST",
		bearerstdapi.MethodAccessTypePrivate,
		search,
	); err != nil {
		log.Fatal(err)
	}

	if err := api.RegisterMethod(
		"/import",
		"POST",
		bearerstdapi.MethodAccessTypePrivate,
		importDump,
	); err != nil {
		log.Fatal(err)
	}

	// Wait for SIGTERM
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Warnf("received SIGTERM, exiting at %s", time.Now().Format(time.RFC850))
	os.Exit(0)
}

// ping is a simple health check handler.
func ping(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	return ctx.Send([]byte("."), bearerstdapi.HTTPstatusCodeOK)
}

func dump(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	return ctx.Send([]byte(storage.String()), bearerstdapi.HTTPstatusCodeOK)
}

func importDump(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	if err := storage.Import(msg.Data); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func users(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	users, err := storage.Users()
	if err != nil {
		return err
	}
	resp, err := json.MarshalIndent(users, "", " ")
	if err != nil {
		return err
	}
	return ctx.Send(resp, bearerstdapi.HTTPstatusCodeOK)
}

func user(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	user, err := storage.User(userID)
	if err != nil {
		return err
	}
	resp, err := json.MarshalIndent(user, "", " ")
	if err != nil {
		return err
	}
	return ctx.Send(resp, bearerstdapi.HTTPstatusCodeOK)
}

type newUserData struct {
	Phone string `json:"phone"`
	Extra string `json:"extra"`
}

func newUser(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	if storage.Exists(userID) {
		return fmt.Errorf("user already exists")
	}
	newUser := newUserData{}
	if err := json.Unmarshal(msg.Data, &newUser); err != nil {
		return err
	}
	if err := storage.AddUser(userID, nil, newUser.Phone, newUser.Extra); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func addElection(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID, electionID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	if err := electionID.FromString(ctx.URLParam("electionid")); err != nil {
		return err
	}
	user, err := storage.User(userID)
	if err != nil {
		return err
	}
	election := smshandler.UserElection{
		ElectionID:        electionID,
		RemainingAttempts: storage.MaxAttempts(),
	}
	user.Elections[electionID.String()] = election
	if err := storage.UpdateUser(user); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func addAttempt(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID, election types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	if err := election.FromString(ctx.URLParam("electionid")); err != nil {
		return err
	}
	if err := storage.SetAttempts(userID, election, 1); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func setConsumed(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID, electionID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	if err := electionID.FromString(ctx.URLParam("electionid")); err != nil {
		return err
	}
	consumed := ctx.URLParam("consumed") == "true" || ctx.URLParam("consumed") == "1"
	user, err := storage.User(userID)
	if err != nil {
		return err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return fmt.Errorf("user does not belong to election")
	}
	election.Consumed = consumed
	user.Elections[electionID.String()] = election // Redundant?
	if err := storage.UpdateUser(user); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func delUser(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userid")); err != nil {
		return err
	}
	if err := storage.DelUser(userID); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

func cloneUser(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	var oldUserID, newUserID types.HexBytes
	if err := oldUserID.FromString(ctx.URLParam("olduserid")); err != nil {
		return err
	}
	if err := newUserID.FromString(ctx.URLParam("newuserid")); err != nil {
		return err
	}
	user, err := storage.User(oldUserID)
	if err != nil {
		return err
	}
	elections := []types.HexBytes{}
	for _, e := range user.Elections {
		elections = append(elections, e.ElectionID)
	}
	phone := ""
	if user.Phone != nil {
		phone = fmt.Sprintf("+%d%d", user.Phone.GetCountryCode(), user.Phone.GetNationalNumber())
	}
	if err := storage.AddUser(newUserID, elections, phone, user.ExtraData); err != nil {
		return err
	}
	return ctx.Send([]byte(respOK), bearerstdapi.HTTPstatusCodeOK)
}

type searchUserData struct {
	Term string `json:"term"`
}

func search(msg *bearerstdapi.BearerStandardAPIdata, ctx *httprouter.HTTPContext) error {
	searchTerm := searchUserData{}
	if err := json.Unmarshal(msg.Data, &searchTerm); err != nil {
		return err
	}
	if len(searchTerm.Term) < 1 {
		return fmt.Errorf("search term cannot be empty")
	}
	output, err := storage.Search(searchTerm.Term)
	if err != nil {
		return err
	}
	data, err := json.Marshal(output)
	if err != nil {
		return err
	}
	return ctx.Send(data, bearerstdapi.HTTPstatusCodeOK)
}
