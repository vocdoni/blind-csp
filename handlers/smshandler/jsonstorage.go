package smshandler

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

const (
	userPrefix           = "u_"
	authTokenIndexPrefix = "a_"
)

// JSONstorage uses a local KV database (Pebble) for storing the smshandler user data.
// JSON is used for data serialization.
type JSONstorage struct {
	kv             db.Database
	keysLock       sync.RWMutex
	maxSmsAttempts int
	coolDownTime   time.Duration
}

func (js *JSONstorage) Init(dataDir string, maxAttempts int, coolDownTime time.Duration) error {
	var err error
	js.kv, err = metadb.New(db.TypePebble, filepath.Clean(dataDir))
	if err != nil {
		return err
	}
	js.maxSmsAttempts = maxAttempts
	js.coolDownTime = coolDownTime
	return nil
}

func (js *JSONstorage) Users() (*Users, error) {
	var us Users
	if err := js.kv.Iterate(nil, func(key, value []byte) bool {
		us.Users = append(us.Users, key2userID(key))
		return true
	}); err != nil {
		return nil, err
	}
	return &us, nil
}

func userIDkey(u types.HexBytes) []byte {
	return append([]byte(userPrefix), u...)
}

func key2userID(key []byte) (u types.HexBytes) {
	_ = u.FromString(fmt.Sprintf("%x", key[len(userPrefix):]))
	return u
}

func (js *JSONstorage) AddUser(userID types.HexBytes, processIDs []types.HexBytes,
	phone, extra string) error {
	phoneNum, err := phonenumbers.Parse(phone, DefaultPhoneCountry)
	if err != nil {
		return err
	}
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	maxAttempts := js.maxSmsAttempts * len(processIDs)
	if maxAttempts == 0 {
		// nolint[:gosimple]
		maxAttempts = js.maxSmsAttempts
	}
	user := UserData{
		ExtraData: extra,
		Phone:     phoneNum,
	}
	user.Elections = make(map[string]UserElection, len(processIDs))
	for _, e := range HexBytesToElection(processIDs, js.maxSmsAttempts) {
		user.Elections[e.ElectionID.String()] = e
	}

	userData, err := json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userIDkey(userID), userData); err != nil {
		return err
	}
	return tx.Commit()
}

func (js *JSONstorage) MaxAttempts() int {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	return js.maxSmsAttempts
}

func (js *JSONstorage) User(userID types.HexBytes) (*UserData, error) {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.ReadTx()
	defer tx.Discard()
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return nil, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return nil, err
	}
	return &user, nil
}

func (js *JSONstorage) UpdateUser(udata *UserData) error {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	if udata.UserID == nil {
		return ErrUserUnknown
	}
	userData, err := json.Marshal(udata)
	if err != nil {
		return err
	}
	if err := tx.Set(userIDkey(udata.UserID), userData); err != nil {
		return err
	}
	return tx.Commit()
}

func (js *JSONstorage) BelongsToElection(userID types.HexBytes,
	electionID types.HexBytes) (bool, error) {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.ReadTx()
	defer tx.Discard()
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return false, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return false, err
	}
	_, ok := user.Elections[electionID.String()]
	return ok, nil
}

func (js *JSONstorage) SetAttempts(userID, electionID types.HexBytes, delta int) error {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return ErrUserNotBelongsToElection
	}
	election.RemainingAttempts += delta
	user.Elections[electionID.String()] = election
	userData, err = json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userIDkey(userID), userData); err != nil {
		return err
	}
	return tx.Commit()
}

func (js *JSONstorage) NewAttempt(userID, electionID types.HexBytes,
	challenge int, token *uuid.UUID) (*phonenumbers.PhoneNumber, error) {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return nil, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return nil, err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return nil, ErrUserNotBelongsToElection
	}
	if election.Consumed {
		return nil, ErrUserAlreadyVerified
	}
	if election.LastAttempt != nil {
		if time.Now().Before(election.LastAttempt.Add(js.coolDownTime)) {
			return nil, ErrAttemptCoolDownTime
		}
	}
	if election.RemainingAttempts < 1 {
		return nil, ErrTooManyAttempts
	}
	election.AuthToken = token
	election.Challenge = challenge
	t := time.Now()
	election.LastAttempt = &t
	user.Elections[electionID.String()] = election
	userData, err = json.Marshal(user)
	if err != nil {
		return nil, err
	}
	// Save the user data
	if err := tx.Set(userIDkey(userID), userData); err != nil {
		return nil, err
	}
	// Save the token as index for finding the userID
	if err := tx.Set([]byte(authTokenIndexPrefix+token.String()), userID); err != nil {
		return nil, err
	}

	return user.Phone, tx.Commit()
}

func (js *JSONstorage) Exists(userID types.HexBytes) bool {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.ReadTx()
	defer tx.Discard()
	_, err := tx.Get(userIDkey(userID))
	return err == nil
}

func (js *JSONstorage) Verified(userID, electionID types.HexBytes) (bool, error) {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.ReadTx()
	defer tx.Discard()
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return false, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return false, err
	}
	election, ok := user.Elections[electionID.String()]
	if !ok {
		return false, ErrUserNotBelongsToElection
	}
	return election.Consumed, nil
}

func (js *JSONstorage) VerifyChallenge(electionID types.HexBytes,
	token *uuid.UUID, solution int) error {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()

	// fetch the user ID by token
	userID, err := tx.Get([]byte(authTokenIndexPrefix + token.String()))
	if err != nil {
		return ErrInvalidAuthToken
	}

	// with the user ID fetch the user data
	userData, err := tx.Get(userIDkey(userID))
	if err != nil {
		return err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
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
	if err := tx.Delete([]byte(authTokenIndexPrefix + token.String())); err != nil {
		return err
	}

	// set consumed to true or false depending on the challenge solution
	election.Consumed = election.Challenge == solution

	// save the user data
	user.Elections[electionID.String()] = election
	userData, err = json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userIDkey(userID), userData); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// return error if the solution does not match the challenge
	if election.Challenge != solution {
		return ErrChallengeCodeFailure
	}
	return nil
}

func (js *JSONstorage) DelUser(userID types.HexBytes) error {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	if err := tx.Delete(userIDkey(userID)); err != nil {
		return err
	}
	return tx.Commit()
}

func (js *JSONstorage) Search(term string) (*Users, error) {
	var users Users
	if err := js.kv.Iterate(nil, func(key, value []byte) bool {
		if !strings.Contains(string(value), term) {
			return true
		}
		users.Users = append(users.Users, key2userID(key))
		return true
	}); err != nil {
		return nil, err
	}

	return &users, nil
}

func (js *JSONstorage) String() string {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	output := make(map[string]UserData)
	if err := js.kv.Iterate(nil, func(key, value []byte) bool {
		var data UserData

		err := json.Unmarshal(value, &data)
		if err != nil {
			log.Warn(err)
		}
		// nolint[:ineffassign]
		output[key2userID(key).String()] = data
		return true
	}); err != nil {
		log.Warn(err)
		return ""
	}
	outputData, err := json.MarshalIndent(output, "", " ")
	if err != nil {
		log.Warn(err)
		return ""
	}
	return string(outputData)
}

// TODO
func (js *JSONstorage) Import(data []byte) error {
	return nil
}
