package model_test

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/blind-csp/model"
)

func createUser() (*model.User, model.HandlerConfig, error) {
	handler := model.HandlerConfig{
		Handler: "oauth",
		Service: "github",
		Mode:    "usernames",
	}

	created, err := userStore.CreateOrGetUser(
		handler,
		"user"+generateID(3)+"@gmail.com",
	)

	return created, handler, err
}

func TestCreateOrGetUser(t *testing.T) {
	created, handler, err := createUser()

	qt.Assert(t, created, qt.Not(qt.IsNil))
	qt.Assert(t, created.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, created.Service, qt.Equals, handler.Service)
	qt.Assert(t, created.Mode, qt.Equals, handler.Mode)
	qt.Assert(t, err, qt.IsNil)
}

func TestGetUser(t *testing.T) {
	created, handler, err := createUser()
	qt.Assert(t, err, qt.IsNil)

	user, err := userStore.User(created.ID)
	qt.Assert(t, user, qt.Not(qt.IsNil))
	qt.Assert(t, user.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, user.Service, qt.Equals, handler.Service)
	qt.Assert(t, user.Mode, qt.Equals, handler.Mode)
	qt.Assert(t, err, qt.IsNil)
}

func TestSeachUser(t *testing.T) {
	created, handler, err := createUser()
	qt.Assert(t, err, qt.IsNil)

	ur := model.UserRequest{
		UserID:  created.ID.String(),
		Handler: handler.Handler,
		Service: handler.Service,
		Mode:    handler.Mode,
		Data:    created.Data,
	}

	users, err := userStore.SearchUser(ur)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, users, qt.Not(qt.IsNil))
	qt.Assert(t, len(*users), qt.Equals, 1)

	user := (*users)[0]
	qt.Assert(t, user.Handler, qt.Equals, handler.Handler)
	qt.Assert(t, user.Service, qt.Equals, handler.Service)
	qt.Assert(t, user.Mode, qt.Equals, handler.Mode)
	qt.Assert(t, user.Data, qt.Equals, created.Data)
}
