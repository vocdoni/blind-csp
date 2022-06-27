package smshandler

import (
	"encoding/json"
	"path/filepath"
	"sync"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
	"go.vocdoni.io/dvote/log"
)

const authTokenIndexPrefix = "at_"

// JSONstorage uses a local KV database (Pebble) for storing the smshandler user data.
// JSON is used for data serialization.
type JSONstorage struct {
	kv             db.Database
	keysLock       sync.RWMutex
	maxSmsAttempts int
}

func (js *JSONstorage) Init(dataDir string, maxAttempts int) error {
	var err error
	js.kv, err = metadb.New(db.TypePebble, filepath.Clean(dataDir))
	if err != nil {
		return err
	}
	js.maxSmsAttempts = maxAttempts
	return nil
}

// TODO
func (js *JSONstorage) Users() (*Users, error) {
	return nil, nil
}

func (js *JSONstorage) AddUser(userID types.HexBytes, processIDs []types.HexBytes,
	phone, extra string) error {
	phoneNum, err := phonenumbers.Parse(phone, "ES")
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
		Elections: []UserElection(HexBytesToElection(processIDs, js.maxSmsAttempts)),
		ExtraData: extra,
		Phone:     phoneNum,
	}
	userData, err := json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userID, userData); err != nil {
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
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userID)
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
	if err := tx.Set(udata.UserID, userData); err != nil {
		return err
	}
	return tx.Commit()
}

func (js *JSONstorage) BelongsToElection(userID types.HexBytes,
	electionID types.HexBytes) (bool, error) {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userID)
	if err != nil {
		return false, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return false, err
	}
	ei := user.FindElection(electionID)
	return ei >= 0, nil
}

func (js *JSONstorage) IncreaseAttempt(userID, electionID types.HexBytes) error {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userID)
	if err != nil {
		return err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return err
	}
	ei := user.FindElection(electionID)
	if ei == -1 {
		return ErrUserNotBelongsToElection
	}
	user.Elections[ei].RemainingAttempts++
	userData, err = json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userID, userData); err != nil {
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
	userData, err := tx.Get(userID)
	if err != nil {
		return nil, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return nil, err
	}
	ei := user.FindElection(electionID)
	if ei == -1 {
		return nil, ErrUserNotBelongsToElection
	}
	if user.Elections[ei].Consumed {
		return nil, ErrUserAlreadyVerified
	}
	if user.Elections[ei].RemainingAttempts < 1 {
		return nil, ErrTooManyAttempts
	}
	user.Elections[ei].RemainingAttempts--
	user.Elections[ei].AuthToken = token
	user.Elections[ei].Challenge = challenge
	userData, err = json.Marshal(user)
	if err != nil {
		return nil, err
	}
	// Save the user data
	if err := tx.Set(userID, userData); err != nil {
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
	tx := js.kv.WriteTx()
	defer tx.Discard()
	_, err := tx.Get(userID)
	return err == nil
}

func (js *JSONstorage) Verified(userID, electionID types.HexBytes) (bool, error) {
	js.keysLock.RLock()
	defer js.keysLock.RUnlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	userData, err := tx.Get(userID)
	if err != nil {
		return false, err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return false, err
	}
	ei := user.FindElection(electionID)
	if ei == -1 {
		return false, ErrUserNotBelongsToElection
	}
	return user.Elections[ei].Consumed, nil
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
	userData, err := tx.Get(userID)
	if err != nil {
		return err
	}
	var user UserData
	if err := json.Unmarshal(userData, &user); err != nil {
		return err
	}

	// find the election and check the solution
	ei := user.FindElection(electionID)
	if ei == -1 {
		return ErrUserNotBelongsToElection
	}
	if user.Elections[ei].Consumed {
		return ErrUserAlreadyVerified
	}
	if user.Elections[ei].AuthToken.String() != token.String() {
		return ErrInvalidAuthToken
	}

	// clean token data (we only allow 1 chance)
	user.Elections[ei].AuthToken = nil
	if err := tx.Delete([]byte(authTokenIndexPrefix + token.String())); err != nil {
		return err
	}

	// set consumed to true or false depending on the challenge solution
	user.Elections[ei].Consumed = user.Elections[ei].Challenge == solution

	// save the user data
	userData, err = json.Marshal(user)
	if err != nil {
		return err
	}
	if err := tx.Set(userID, userData); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}

	// return error if the solution does not match the challenge
	if user.Elections[ei].Challenge != solution {
		return ErrChallengeCodeFailure
	}
	return nil
}

func (js *JSONstorage) DelUser(userID types.HexBytes) error {
	js.keysLock.Lock()
	defer js.keysLock.Unlock()
	tx := js.kv.WriteTx()
	defer tx.Discard()
	if err := tx.Delete(userID); err != nil {
		return err
	}
	return tx.Commit()
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
		var user types.HexBytes
		user = key
		output[user.String()] = data
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
