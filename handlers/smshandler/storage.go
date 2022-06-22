package smshandler

import (
	"bytes"
	"fmt"

	"github.com/google/uuid"
	"github.com/nyaruka/phonenumbers"
	"github.com/vocdoni/blind-csp/types"
)

// ErrTooManyAttempts is returned when no more SMS attempts available for a user.
var ErrTooManyAttempts = fmt.Errorf("too many SMS tries")

// ErrUserAlreadyVerified is returned if the user is already verified when trying to verify it.
var ErrUserAlreadyVerified = fmt.Errorf("user is already verified")

// ErrUserNotBelongsToElection is returned if the user does not has participation rights for an election.
var ErrUserNotBelongsToElection = fmt.Errorf("user does not belong to election")

// ErrInvalidAuthToken is returned if the authtoken does not match with the election.
var ErrInvalidAuthToken = fmt.Errorf("invalid authentication token")

// ErrChallengeCodeFailure is returned when the challenge code does not match.
var ErrChallengeCodeFailure = fmt.Errorf("challenge code do not match")

// Users is the list of smshandler users.
type Users struct {
	Users map[string]UserData `json:"users"`
}

// UserData represents a user of the SMS handler.
type UserData struct {
	Elections []UserElection            `json:"elections,omitempty"`
	ExtraData string                    `json:"extraData,omitempty"`
	Phone     *phonenumbers.PhoneNumber `json:"phone,omitempty"`
}

type UserElection struct {
	ElectionID        types.HexBytes `json:"electionId"`
	RemainingAttempts int            `json:"remainingAttempts"`
	Consumed          bool           `json:"consumed"`
	AuthToken         *uuid.UUID     `json:"authToken,omitempty"`
	Challenge         int            `json:"challenge,omitempty"`
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
	// returns the list of elections for a user
	GetElections(userID types.HexBytes) (elections []UserElection, err error)
	// returns true if the user belongs to the electionID
	BelongsToElection(userID, electionID types.HexBytes) (belongs bool, err error)
	// increment by one the attempt counter
	IncreaseAttempt(userID, electionID types.HexBytes) (err error)
	// returns the phone and decrease attempt counter
	NewAttempt(userID, electionID types.HexBytes, challenge int,
		token *uuid.UUID) (phone *phonenumbers.PhoneNumber, err error)
	// returns true if the user exists in the database
	Exists(userID types.HexBytes) (exists bool)
	// returns true if the user is verified
	IsVerified(userID, electionID types.HexBytes) (verified bool, error error)
	// returns nil if the challenge is solved correctly. Sets verified to true and removes the
	// temporary auth token from the storage
	VerifyChallenge(electionID types.HexBytes, token *uuid.UUID, solution int) (err error)
	// removes an user from the storage
	DelUser(userID types.HexBytes) (err error)
	// returns the string representation of the storage
	String() string
}