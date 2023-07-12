package admin

import (
	"encoding/json"

	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/apirest"
)

// userElectionController is the interface for the user controller
type UserelectionController struct {
	store model.UserelectionStore
}

// NewUserelectionController creates a new user controller
func NewUserelectionController(store model.UserelectionStore) *UserelectionController {
	return &UserelectionController{store: store}
}

// Create creates a new user in an election
func (c *UserelectionController) Create(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	userData := model.UserelectionRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	handler := model.HandlerConfig{
		Handler: userData.Handler,
		Service: userData.Service,
		Mode:    userData.Mode,
	}

	user, err := c.store.CreateUserelection(electionID, handler, userData.Data)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// Update updates a user in an election
func (c *UserelectionController) Update(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	userData := model.UserelectionRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	user, err := c.store.UpdateUserelection(electionID, userID, userData)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// Userelection returns a user in an election
func (c *UserelectionController) Userelection(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	user, err := c.store.Userelection(electionID, userID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}

// Delete deletes a user from an election
func (c *UserelectionController) Delete(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	if err := c.store.DeleteUserelection(electionID, userID); err != nil {
		return err
	}
	return ctx.Send(new(ApiResponse).Set(nil).MustMarshall(), apirest.HTTPstatusOK)
}

// List returns a list of users for an election
func (c *UserelectionController) List(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	users, err := c.store.ListUserelection(electionID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(users).MustMarshall(), apirest.HTTPstatusOK)
}

// Search returns a list of users for a criteria
func (c *UserelectionController) Search(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	userData := model.UserelectionRequest{}
	if err := json.Unmarshal(msg.Data, &userData); err != nil {
		return err
	}

	users, err := c.store.SearchUserelection(electionID, userData)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(users).MustMarshall(), apirest.HTTPstatusOK)
}

// GetUserElections returns a list of elections for a user
func (c *UserelectionController) GetUserElections(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var userID types.HexBytes
	userID, err := hexStringToBytes(ctx.URLParam("userId"))
	if err != nil {
		return err
	}

	user, err := c.store.GetUserElections(userID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(user).MustMarshall(), apirest.HTTPstatusOK)
}
