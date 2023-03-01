package admin

import (
	"encoding/json"

	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/apirest"
)

// UserController is the interface for the user controller
type UserController struct {
	store model.UserStore
}

// NewUserController creates a new user controller
func NewUserController(store model.UserStore) *UserController {
	return &UserController{store: store}
}

// Create creates a new user in an election
func (c *UserController) Create(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	userData := model.UserRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	handler := model.HandlerConfig{
		Handler: userData.Handler,
		Service: userData.Service,
		Mode:    userData.Mode,
	}

	user, err := c.store.CreateUser(electionID, handler, userData.Data)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// Update updates a user in an election
func (c *UserController) Update(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userId")); err != nil {
		return err
	}

	userData := model.UserRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	user, err := c.store.UpdateUser(electionID, userID, userData)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// User returns a user in an election
func (c *UserController) User(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userId")); err != nil {
		return err
	}

	user, err := c.store.User(electionID, userID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// Delete deletes a user from an election
func (c *UserController) Delete(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	var userID types.HexBytes
	if err := userID.FromString(ctx.URLParam("userId")); err != nil {
		return err
	}

	if err := c.store.DeleteUser(electionID, userID); err != nil {
		return err
	}
	return ctx.Send(new(ApiResponse).Set(nil).MustMarshall(), apirest.HTTPstatusOK)
}

// List returns a list of users for an election
func (c *UserController) List(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	users, err := c.store.ListUser(electionID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(users).MustMarshall(), apirest.HTTPstatusOK)
}

// Search returns a list of users for a criteria
func (c *UserController) Search(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	valid, err := ValidateAdminToken(electionID, msg.AuthToken)
	if !valid || err != nil {
		return ctx.Send(
			new(ApiResponse).SetError(CodeErrInvalidAuth, ReasonErrInvalidAuth).MustMarshall(),
			apirest.HTTPstatusBadRequest,
		)
	}

	userData := model.UserRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	users, err := c.store.SearchUser(electionID, userData)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(users).MustMarshall(), apirest.HTTPstatusOK)
}
