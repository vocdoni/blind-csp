package model_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
)

func createUserelection(electionID types.HexBytes) (*model.UserelectionComplete, model.HandlerConfig, error) {
	handler := model.HandlerConfig{
		Handler: "oauth",
		Service: "github",
		Mode:    "usernames",
	}

	created, err := userelectionStore.CreateUserelection(
		electionID,
		handler,
		"user"+generateID(3)+"@gmail.com",
	)

	return created, handler, err
}

func TestCreateUserelection(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, handler, err := createUserelection(electionID)
	qt.Assert(t, created, qt.Not(qt.IsNil))
	qt.Assert(t, err, qt.IsNil)

	user, err := userStore.User(created.UserID)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, user.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, user.Service, qt.Equals, handler.Service)
	qt.Assert(t, user.Mode, qt.Equals, handler.Mode)
}

func TestGetUserelection(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, handler, err := createUserelection(electionID)
	qt.Assert(t, err, qt.IsNil)

	userelection, err := userelectionStore.Userelection(electionID, created.UserID)
	qt.Assert(t, userelection, qt.Not(qt.IsNil))
	qt.Assert(t, userelection.ElectionID.String(), qt.Equals, electionID.String())
	notConsumed := false
	qt.Assert(t, userelection.Consumed, qt.DeepEquals, &notConsumed)
	qt.Assert(t, err, qt.IsNil)

	user, err := userStore.User(created.UserID)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, user.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, user.Service, qt.Equals, handler.Service)
	qt.Assert(t, user.Mode, qt.Equals, handler.Mode)
}

func TestUpdateUserelection(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, _, err := createUserelection(electionID)
	qt.Assert(t, err, qt.IsNil)

	consumed := true
	ur := model.UserelectionRequest{
		Consumed: &consumed,
	}
	updated, err := userelectionStore.UpdateUserelection(electionID, created.UserID, ur)
	qt.Assert(t, *updated.Consumed, qt.IsTrue)
	qt.Assert(t, err, qt.IsNil)

	user, err := userelectionStore.Userelection(electionID, created.UserID)
	qt.Assert(t, *user.Consumed, qt.IsTrue)
	qt.Assert(t, err, qt.IsNil)
}

func TestDeleteUserelection(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	created, _, err := createUserelection(electionID)
	qt.Assert(t, err, qt.IsNil)

	err = userelectionStore.DeleteUserelection(electionID, created.UserID)
	qt.Assert(t, err, qt.IsNil)

	_, err = userelectionStore.Userelection(electionID, created.UserID)
	qt.Assert(t, err, qt.ErrorMatches, model.ErrUserelectionUnknown.Error())
}

func TestListUserelections(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	_, _, _ = createUserelection(electionID)
	_, _, _ = createUserelection(electionID)

	users, err := userelectionStore.ListUserelection(electionID)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 2)
}

func TestSearchUserelections(t *testing.T) {
	var electionID types.HexBytes
	_ = electionID.FromString(generateID(5))
	_, _, _ = createUserelection(electionID)

	notConsumed := false
	ur := model.UserelectionRequest{
		Handler:  "oauth",
		Service:  "github",
		Consumed: &notConsumed,
	}
	users, err := userelectionStore.SearchUserelection(electionID, ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 1)

	_, _, _ = createUserelection(electionID)
	_, _, _ = createUserelection(electionID)
	users, err = userelectionStore.SearchUserelection(electionID, ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 3)

	consumed := true
	ur = model.UserelectionRequest{
		Consumed: &consumed,
	}
	users, err = userelectionStore.SearchUserelection(electionID, ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, len(*users), qt.Equals, 0)
}
