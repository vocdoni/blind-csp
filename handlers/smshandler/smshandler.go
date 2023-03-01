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

const (
	// DefaultMaxSMSattempts defines the default maximum number of SMS allowed attempts.
	DefaultMaxSMSattempts = 5
	// DefaultSMScoolDownTime defines the default cool down time window for sending challenges.
	DefaultSMScoolDownTime = 2 * time.Minute
	// DefaultPhoneCountry defines the default country code for phone numbers.
	DefaultPhoneCountry = "ES"
	// DefaultSMSthrottleTime is the default throttle time for the SMS provider API.
	DefaultSMSthrottleTime = time.Millisecond * 500
	// DefaultSMSqueueMaxRetries is how many times to retry delivering an SMS in case upstream provider returns an error
	DefaultSMSqueueMaxRetries = 10
)

// SmsHandler is a handler that requires a simple math operation to be resolved.
type SmsHandler struct {
	stg           Storage
	smsQueue      *smsQueue
	mathRandom    *rand.Rand
	SendChallenge []SendChallengeFunc
}

// SendChallengeFunc is the function that sends the SMS challenge to a phone number.
type SendChallengeFunc func(phone *phonenumbers.PhoneNumber, challenge int) error

// Name returns the name for the handler.
func (sh *SmsHandler) Name() string {
	return "smsHandler"
}

// Init initializes the handler.
// First argument is the maximum SMS challenge attempts per user and election.
// Second is the data directory (mandatory).
// Third is the SMS cooldown time in milliseconds (optional).
// Fourth is the SMS throttle time in milliseconds (optional).
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
	// set default sms cooldown time
	smsCoolDownTime := DefaultSMScoolDownTime
	if len(opts) > 2 {
		ms, err := strconv.Atoi(opts[2])
		if err != nil {
			return err
		}
		smsCoolDownTime = time.Millisecond * time.Duration(ms)
	}
	// set default sms throttle time
	smsThrottle := DefaultSMSthrottleTime
	if len(opts) > 3 {
		ms, err := strconv.Atoi(opts[3])
		if err != nil {
			return err
		}
		smsThrottle = time.Millisecond * time.Duration(ms)
	}
	if smsCoolDownTime < smsThrottle {
		return fmt.Errorf("sms cooldown time cannot be smaller than sms throttle")
	}

	// if MongoDB env var is defined, use MongoDB as storage backend
	if os.Getenv("CSP_MONGODB_URL") != "" {
		sh.stg = &MongoStorage{}
	} else {
		sh.stg = &JSONstorage{}
	}

	// set math random source
	sh.mathRandom = rand.New(rand.NewSource(time.Now().UnixNano()))
	if err := sh.stg.Init(
		filepath.Join(opts[0], "storage"),
		maxAttempts,
		smsCoolDownTime,
	); err != nil {
		return err
	}

	// set challenge function (if not defined, use Twilio)
	if sh.SendChallenge == nil {
		switch os.Getenv("SMS_PROVIDER") {
		case "messagebird":
			sh.SendChallenge = []SendChallengeFunc{NewMessageBirdSMS().SendChallenge}
		case "messagebird,twilio":
			sh.SendChallenge = []SendChallengeFunc{
				NewMessageBirdSMS().SendChallenge,
				NewTwilioSMS().SendChallenge,
			}
		case "twilio,messagebird":
			sh.SendChallenge = []SendChallengeFunc{
				NewTwilioSMS().SendChallenge,
				NewMessageBirdSMS().SendChallenge,
			}
		default:
			sh.SendChallenge = []SendChallengeFunc{NewTwilioSMS().SendChallenge}
		}
	}

	// check for files to import to the storage database
	importFile := os.Getenv("CSP_IMPORT_FILE")
	if importFile != "" {
		sh.importCSVfile(importFile)
	}

	// create SMS queue
	sh.smsQueue = newSmsQueue(
		smsCoolDownTime,
		smsThrottle,
		sh.SendChallenge,
	)
	go sh.smsQueue.run()
	go sh.smsQueueController()
	return nil
}

func (sh *SmsHandler) smsQueueController() {
	for {
		r := <-sh.smsQueue.response
		if r.success {
			if err := sh.stg.SetAttempts(r.userID, r.electionID, -1); err != nil {
				log.Warnf("challenge cannot be sent: %v", err)
			} else {
				log.Infof("%s: challenge successfully sent to user %s", r, r.userID)
			}
		} else {
			log.Warnf("%s: challenge sending failed", r)
		}
	}
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
	// Get the last two digits of the phone and return them as extraData
	phoneStr := ""
	if user.Phone != nil {
		phoneStr = strconv.FormatUint(user.Phone.GetNationalNumber(), 10)
		if len(phoneStr) < 3 {
			phoneStr = ""
		} else {
			phoneStr = phoneStr[len(phoneStr)-2:]
		}
	}
	indexerElections := []types.Election{}
	for _, e := range user.Elections {
		ie := types.Election{
			RemainingAttempts: e.RemainingAttempts,
			Consumed:          e.Consumed,
			ElectionID:        e.ElectionID,
			ExtraData:         []string{phoneStr},
		}
		indexerElections = append(indexerElections, ie)
	}
	return indexerElections
}

// Auth is the handler method for managing the simple math authentication challenge.
func (sh *SmsHandler) Auth(r *http.Request, c *types.Message,
	electionID types.HexBytes, signType string, step int,
) types.AuthResponse {
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
			log.Warnf("new attempt for user %s failed: %v", userID, err)
			return types.AuthResponse{Response: []string{err.Error()}}
		}
		if phone == nil {
			log.Warnf("phone is nil for user %s", userID)
			return types.AuthResponse{Response: []string{"no phone for this user data"}}
		}
		// Enqueue to send the SMS challenge
		if err := sh.smsQueue.add(userID, electionID, phone, challenge); err != nil {
			log.Errorf("cannot enqueue challenge: %v", err)
			return types.AuthResponse{Response: []string{"problem with SMS challenge system"}}
		}
		log.Infof("user %s challenged with %d at phone %d", userID.String(), challenge, phone.GetNationalNumber())

		// Build success reply
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
			log.Warnf("verify challenge %d failed: %v", solution, err)
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
