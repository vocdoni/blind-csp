package admin

import (
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/httprouter/apirest"
)

// ElectionWithTokenResponse is the response to the election creation or admin token request.
// Containing the admin token needed for permissioned actions.
type ElectionWithTokenResponse struct {
	AdminToken string         `json:"adminToken"`
	Election   model.Election `json:"election"`
}

// ElectionController is the interface for the election controller
type ElectionController struct {
	store model.ElectionStore
}

// NewElectionController creates a new election controller
func NewElectionController(store model.ElectionStore) *ElectionController {
	return &ElectionController{store: store}
}

// Create creates a new election with it's users
func (c *ElectionController) Create(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	newElection := model.Election{}
	if err := json.Unmarshal(msg.Data, &newElection); err != nil {
		return err
	}

	election, err := c.store.CreateElection(&newElection)
	if err != nil {
		return err
	}

	electionBearerToken, err := GenerateAdminToken(election.ID)
	if err != nil {
		return err
	}

	response := ElectionWithTokenResponse{
		AdminToken: electionBearerToken,
		Election:   *election,
	}

	return ctx.Send(new(ApiResponse).Set(response).MustMarshall(), apirest.HTTPstatusOK)
}

// Election returns the election data
func (c *ElectionController) Election(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	election, err := c.store.Election(electionID)
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(election).MustMarshall(), apirest.HTTPstatusOK)
}

// Delete deletes an election
func (c *ElectionController) Delete(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
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

	if err := c.store.DeleteElection(electionID); err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(nil).MustMarshall(), apirest.HTTPstatusOK)
}

// List returns the list of elections
func (c *ElectionController) List(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	elections, err := c.store.ListElection()
	if err != nil {
		return err
	}

	return ctx.Send(new(ApiResponse).Set(elections).MustMarshall(), apirest.HTTPstatusOK)
}

// AdminTokenRequest is the request to get the admin token,
// containing the signature and the data (thas has been signed)
type AdminTokenRequest struct {
	Signature string `json:"signature"`
	Data      string `json:"data"`
}

// AdminToken returns the admin token for an election
func (c *ElectionController) AdminToken(msg *apirest.APIdata, ctx *httprouter.HTTPContext) error {
	var electionID types.HexBytes
	electionID, err := hexStringToBytes(ctx.URLParam("electionId"))
	if err != nil {
		return err
	}

	adminTokenRequest := AdminTokenRequest{}
	if err := json.Unmarshal(msg.Data, &adminTokenRequest); err != nil {
		return err
	}

	signature, err := hexStringToBytes(adminTokenRequest.Signature)
	if err != nil {
		return ctx.Send(new(ApiResponse).SetError(CodeErrInvalidAuth, "Invalid signature").MustMarshall(), apirest.HTTPstatusOK)
	}

	// Verify the signature
	verified, err := VerifySignatureForElection(electionID, signature, types.HexBytes(adminTokenRequest.Data))
	if !verified || err != nil {
		return ctx.Send(new(ApiResponse).SetError(CodeErrInvalidAuth, "Invalid signer").MustMarshall(), apirest.HTTPstatusOK)
	}

	// Get the election
	election, err := c.store.Election(electionID)
	if err != nil {
		return err
	}

	// Get the admin token
	electionBearerToken, err := GenerateAdminToken(electionID)
	if err != nil {
		return err
	}

	response := ElectionWithTokenResponse{
		AdminToken: electionBearerToken,
		Election:   *election,
	}

	return ctx.Send(new(ApiResponse).Set(response).MustMarshall(), apirest.HTTPstatusOK)
}

// Helper function to decode a hex string to byte slice
func hexStringToBytes(hexString string) ([]byte, error) {
	hexString = strings.TrimPrefix(hexString, "0x")

	if len(hexString)%2 != 0 {
		hexString = "0" + hexString
	}
	return hex.DecodeString(hexString)
}
