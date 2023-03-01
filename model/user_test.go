package model_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
)

func createUser(electionID types.HexBytes) (*model.User, model.HandlerConfig, error) {
	handler := model.HandlerConfig{
		Handler: "oauth",
		Service: "github",
		Mode:    "usernames",
	}

	created, err := userStore.CreateUser(
		electionID,
		handler,
		"user"+generateID(3)+"@gmail.com",
	)

	return created, handler, err
}

func TestCreateUser(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, handler, err := createUser(electionID)

	qt.Assert(t, created, qt.Not(qt.IsNil))
	qt.Assert(t, created.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, created.Service, qt.Equals, handler.Service)
	qt.Assert(t, created.Mode, qt.Equals, handler.Mode)
	qt.Assert(t, err, qt.IsNil)
}

func TestGetUser(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, handler, err := createUser(electionID)
	qt.Assert(t, err, qt.IsNil)

	user, err := userStore.User(electionID, created.ID)
	qt.Assert(t, user, qt.Not(qt.IsNil))
	qt.Assert(t, user.ElectionID.String(), qt.Equals, electionID.String())
	qt.Assert(t, user.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, user.Service, qt.Equals, handler.Service)
	qt.Assert(t, user.Mode, qt.Equals, handler.Mode)
	notConsumed := false
	qt.Assert(t, user.Consumed, qt.DeepEquals, &notConsumed)
	qt.Assert(t, err, qt.IsNil)
}

func TestUpdateUser(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, _, err := createUser(electionID)
	qt.Assert(t, err, qt.IsNil)

	consumed := true
	ur := model.UserRequest{
		Consumed: &consumed,
	}
	updated, err := userStore.UpdateUser(electionID, created.ID, ur)
	qt.Assert(t, *updated.Consumed, qt.IsTrue)
	qt.Assert(t, err, qt.IsNil)

	user, err := userStore.User(electionID, created.ID)
	qt.Assert(t, *user.Consumed, qt.IsTrue)
	qt.Assert(t, err, qt.IsNil)
}

func TestDeleteUser(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, _, err := createUser(electionID)
	qt.Assert(t, err, qt.IsNil)

	err = userStore.DeleteUser(electionID, created.ID)
	qt.Assert(t, err, qt.IsNil)

	_, err = userStore.User(electionID, created.ID)
	qt.Assert(t, err, qt.ErrorMatches, model.ErrUserUnknown.Error())
}

func TestListUsers(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	_, _, _ = createUser(electionID)
	_, _, _ = createUser(electionID)

	users, err := userStore.ListUser(electionID)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 2)
}

func TestSearchUsers(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	_, _, _ = createUser(electionID)

	notConsumed := false
	ur := model.UserRequest{
		Consumed: &notConsumed,
	}
	users, err := userStore.SearchUser(electionID, ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 1)

	consumed := true
	ur = model.UserRequest{
		Consumed: &consumed,
	}
	users, err = userStore.SearchUser(electionID, ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 0)
}
