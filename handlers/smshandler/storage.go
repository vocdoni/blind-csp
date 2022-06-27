package smshandler

import (
	"bytes"
	"fmt"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
)

var (
	// ErrTooManyAttempts is returned when no more SMS attempts available for a user.
	ErrTooManyAttempts = fmt.Errorf("too many SMS tries")
	// ErrUserUnknown is returned if the userID is not found in the database.
	ErrUserUnknown = fmt.Errorf("user is unknown")
	// ErrUserAlreadyVerified is returned if the user is already verified when trying to verify it.
	ErrUserAlreadyVerified = fmt.Errorf("user is already verified")
	// ErrUserNotBelongsToElection is returned if the user does not has participation rights.
	ErrUserNotBelongsToElection = fmt.Errorf("user does not belong to election")
	// ErrInvalidAuthToken is returned if the authtoken does not match with the election.
	ErrInvalidAuthToken = fmt.Errorf("invalid authentication token")
	// ErrChallengeCodeFailure is returned when the challenge code does not match.
	ErrChallengeCodeFailure = fmt.Errorf("challenge code do not match")
)

// Users is the list of smshandler users.
type Users struct {
	Users []types.HexBytes `json:"users"`
}

// UserData represents a user of the SMS handler.
type UserData struct {
	UserID    types.HexBytes            `json:"userID,omitempty" bson:"_id"`
	Elections []UserElection            `json:"elections,omitempty" bson:"elections,omitempty"`
	ExtraData string                    `json:"extraData,omitempty" bson:"extradata,omitempty"`
	Phone     *phonenumbers.PhoneNumber `json:"phone,omitempty" bson:"phone,omitempty"`
}

// UserElection represents an election and its details owned by a user (UserData)
type UserElection struct {
	ElectionID        types.HexBytes `json:"electionId" bson:"_id"`
	RemainingAttempts int            `json:"remainingAttempts" bson:"remainingattempts"`
	Consumed          bool           `json:"consumed" bson:"consumed"`
	AuthToken         *uuid.UUID     `json:"authToken,omitempty" bson:"authtoken,omitempty"`
	Challenge         int            `json:"challenge,omitempty" bson:"challenge,omitempty"`
}

// AuthTokenIndex is used by the storage to index a token with its userID (from UserData).
type AuthTokenIndex struct {
	AuthToken *uuid.UUID     `json:"authToken" bson:"_id"`
	UserID    types.HexBytes `json:"userID" bson:"userid"`
}

// HexBytesToElection transforms a slice of HexBytes to []Election.
// All entries are set with RemainingAttempts = attempts.
func HexBytesToElection(electionIDs []types.HexBytes, attempts int) []UserElection {
	elections := []UserElection{}

	for _, e := range electionIDs {
		ue := UserElection{}
		ue.ElectionID = e
		ue.RemainingAttempts = attempts
		elections = append(elections, ue)
	}
	return elections
}

// FindElection returns the election index.
// -1 is returned if the election ID is not found.
func (ud *UserData) FindElection(electionID types.HexBytes) int {
	for i, e := range ud.Elections {
		if bytes.Equal(electionID, e.ElectionID) {
			return i
		}
	}
	return -1
}

// Storage interface implements the storage layer for the smshandler
type Storage interface {
	// initializes the storage, maxAttempts is used to set the default maximum SMS attempts.
	Init(dataDir string, maxAttempts int) (err error)
	// adds a new user to the storage
	AddUser(userID types.HexBytes, processIDs []types.HexBytes, phone, extra string) (err error)
	// returns the list of users
	Users() (users *Users, err error)
	// returns the full information of a user, including the election list.
	User(userID types.HexBytes) (user *UserData, err error)
	// updates a user
	UpdateUser(udata *UserData) (err error)
	// returns true if the user belongs to the electionID
	BelongsToElection(userID, electionID types.HexBytes) (belongs bool, err error)
	// increment by one the attempt counter
	IncreaseAttempt(userID, electionID types.HexBytes) (err error)
	// returns the default max attempts
	MaxAttempts() (attempts int)
	// returns the phone and decrease attempt counter
	NewAttempt(userID, electionID types.HexBytes, challenge int,
		token *uuid.UUID) (phone *phonenumbers.PhoneNumber, err error)
	// returns true if the user exists in the database
	Exists(userID types.HexBytes) (exists bool)
	// returns true if the user is verified
	Verified(userID, electionID types.HexBytes) (verified bool, error error)
	// returns nil if the challenge is solved correctly. Sets verified to true and removes the
	// temporary auth token from the storage
	VerifyChallenge(electionID types.HexBytes, token *uuid.UUID, solution int) (err error)
	// removes an user from the storage
	DelUser(userID types.HexBytes) (err error)
	// returns the string representation of the storage
	String() string
}
