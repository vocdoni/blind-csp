package smshandler

import (
	"encoding/csv"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/log"
)

// DefaultMaxSMSattempts defines the default maximum number of SMS allowed attempts.
const DefaultMaxSMSattempts = 5

// SmsHandler is a handler that requires a simple math operation to be resolved.
type SmsHandler struct {
	stg               Storage
	mathRandom        *rand.Rand
	SendChallengeFunc func(phone *phonenumbers.PhoneNumber, challenge int) error
}

// GetName returns the name of the handler
func (sh *SmsHandler) Name() string {
	return "smsHandler"
}

// Init initializes the handler.
// Takes one argument for persistent data directory.
func (sh *SmsHandler) Init(opts ...string) error {
	if len(opts) == 0 {
		return fmt.Errorf("no data dir provided")
	}
	var err error
	// set default max attempts
	maxAttempts := DefaultMaxSMSattempts
	if len(opts) > 1 {
		maxAttempts, err = strconv.Atoi(opts[1])
		if err != nil {
			return err
		}
	}
	// if MongoDB env var is defined, use MongoDB as storage backend
	if os.Getenv("CSP_MONGODB_URL") != "" {
		sh.stg = &MongoStorage{}
	} else {
		sh.stg = &JSONstorage{}
	}
	// set math random source
	sh.mathRandom = rand.New(rand.NewSource(time.Now().UnixNano()))
	if err := sh.stg.Init(filepath.Join(opts[0], "storage"), maxAttempts); err != nil {
		return err
	}
	// set challenge function (if not defined, use Twilio)
	if sh.SendChallengeFunc == nil {
		switch os.Getenv("SMS_PROVIDER") {
		case "messagebird":
			sh.SendChallengeFunc = NewMessageBirdSMS().SendChallenge
		default:
			sh.SendChallengeFunc = NewTwilioSMS().SendChallenge
		}
	}

	// check for files to import to the storage database
	importFile := os.Getenv("CSP_IMPORT_FILE")
	if importFile != "" {
		sh.importCSVfile(importFile)
	}
	return nil
}

// CSV file must follow the format:
// userId, phone, extraInfo, electionID1, electionID2, ..., electionIDn
func (sh *SmsHandler) importCSVfile(filepath string) {
	log.Infof("importing CSV file %s", filepath)
	f, err := os.Open(filepath)
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	// read csv values using csv.Reader
	csvReader := csv.NewReader(f)
	data, err := csvReader.ReadAll()
	if err != nil {
		log.Fatal(err)
	}
	for i, line := range data {
		if len(line) < 4 {
			log.Warnf("wrong CSV entry (missing fields): %s", line)
			continue
		}
		userID := types.HexBytes{}
		if err := userID.FromString(line[0]); err != nil {
			log.Warnf("wrong data field at line %d", i)
			continue
		}

		electionIDs := []types.HexBytes{}
		for _, eid := range line[3:] {
			eidh := types.HexBytes{}
			if err := eidh.FromString(eid); err != nil {
				log.Warnf("wrong electionID at line %d", i)
				continue
			}
			electionIDs = append(electionIDs, eidh)
		}

		if err := sh.stg.AddUser(userID, electionIDs, line[1], line[2]); err != nil {
			log.Warnf("cannot add user from line %d", i)
		}
	}
	log.Debug(sh.stg.String())
}

// Info returns the handler options and information.
func (sh *SmsHandler) Info() *types.Message {
	return &types.Message{
		Title:    "SMS code handler",
		AuthType: "auth",
		SignType: []string{types.SignatureTypeBlind},
		AuthSteps: []*types.AuthField{
			{Title: "UserId", Type: "text"},
			{Title: "Code", Type: "int4"},
		},
	}
}

// Indexer takes a unique user identifier and returns the list of processIDs where
// the user is elegible for participation. This is a helper function that might not
// be implemented (depends on the handler use case).
func (sh *SmsHandler) Indexer(userID types.HexBytes) []types.Election {
	user, err := sh.stg.User(userID)
	if err != nil {
		log.Warnf("cannot get indexer elections: %v", err)
		return nil
	}
	indexerElections := []types.Election{}
	for _, e := range user.Elections {
		ie := types.Election{
			RemainingAttempts: e.RemainingAttempts,
			Consumed:          e.Consumed,
			ElectionID:        e.ElectionID,
		}
		indexerElections = append(indexerElections, ie)
	}
	return indexerElections
}

// Auth is the handler method for managing the simple math authentication challenge.
func (sh *SmsHandler) Auth(r *http.Request, c *types.Message,
	electionID types.HexBytes, signType string, step int) types.AuthResponse {
	if signType != types.SignatureTypeBlind {
		return types.AuthResponse{Response: []string{"incorrect signature type, only blind supported"}}
	}
	switch step {
	case 0:
		// If first step, build new challenge
		if len(c.AuthData) != 1 {
			return types.AuthResponse{Response: []string{"incorrect auth data fields"}}
		}
		var userID types.HexBytes
		if err := userID.FromString(c.AuthData[0]); err != nil {
			return types.AuthResponse{Response: []string{"incorrect format for userId"}}
		}

		// Generate challenge and authentication token
		challenge := sh.mathRandom.Intn(900000) + 100000
		atoken := uuid.New()

		// Get the phone number. This methods checks for electionID and user verification status.
		phone, err := sh.stg.NewAttempt(userID, electionID, challenge, &atoken)
		if err != nil {
			log.Warn(err)
			return types.AuthResponse{Response: []string{err.Error()}}
		}

		// Send the challenge
		if err := sh.SendChallengeFunc(phone, challenge); err != nil {
			log.Warn(err)
			if err := sh.stg.IncreaseAttempt(userID, electionID); err != nil {
				log.Warn(err)
			}
			return types.AuthResponse{Response: []string{"error sending SMS"}}
		}
		log.Infof("user %s challenged with %d", userID.String(), challenge)
		phoneStr := strconv.FormatUint(phone.GetNationalNumber(), 10)
		if len(phoneStr) < 3 {
			return types.AuthResponse{Response: []string{"error parsing the phone number"}}
		}
		return types.AuthResponse{
			Success:   true,
			AuthToken: &atoken,
			Response:  []string{phoneStr[len(phoneStr)-2:]},
		}
	case 1:
		if c.AuthToken == nil || len(c.AuthData) != 1 {
			return types.AuthResponse{Response: []string{"auth token not provided or missing auth data"}}
		}
		solution, err := strconv.Atoi(c.AuthData[0])
		if err != nil {
			log.Warnf("cannot atoi solution string %d", solution)
			return types.AuthResponse{Response: []string{"wrong format in challenge solution"}}
		}
		// Verify the challenge solution
		if err := sh.stg.VerifyChallenge(electionID, c.AuthToken, solution); err != nil {
			log.Warn(err)
			return types.AuthResponse{Response: []string{"challenge not completed"}}
		}

		log.Infof("new user registered, challenge resolved %s", c.AuthData[0])
		return types.AuthResponse{
			Response: []string{"challenge resolved"},
			Success:  true,
		}
	}

	return types.AuthResponse{Response: []string{"invalid auth step"}}
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (sh *SmsHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (sh *SmsHandler) CertificateCheck(subject []byte) bool {
	return true
}

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (sh *SmsHandler) Certificates() [][]byte {
	return nil
}
