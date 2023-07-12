package oauthhandler

import (
	"encoding/json"
	"net/http"

	"github.com/google/uuid"
	"github.com/vocdoni/blind-csp/admin"
	"github.com/vocdoni/blind-csp/model"
	"github.com/vocdoni/blind-csp/types"
	"go.vocdoni.io/dvote/httprouter"
	"go.vocdoni.io/dvote/log"
)

// OauthHandler is a handler that requires a verifiable oAuth token to be resolved.
type OauthHandler struct{}

// Init does nothing
func (oh *OauthHandler) Init(r *httprouter.HTTProuter, baseURL string, opts ...string) error {
	admin, err := admin.NewAdmin()
	if err != nil {
		log.Fatal(err)
	}

	if err := admin.ServeAPI(r, baseURL+"/admin"); err != nil {
		log.Fatal(err)
	}

	return nil
}

// GetName returns the name of the handler
func (oh *OauthHandler) Name() string {
	return "oAuth"
}

// Info returns the handler options and required auth steps.
func (oh *OauthHandler) Info() *types.Message {
	return &types.Message{
		Title:    "oAuth handler",
		AuthType: "auth",
		SignType: types.AllSignatures,
		AuthSteps: []*types.AuthField{
			{Title: "GetAuthUrl", Type: "text"},
			{Title: "VerifyElection", Type: "text"},
		},
	}
}

// Indexer takes a unique user identifier and returns the list of processIDs where
// the user is elegible for participation. This is a helper function that might not
// be implemented (depends on the handler use case).
func (oh *OauthHandler) Indexer(userID types.HexBytes) []types.Election {
	// Init the Storage and get the user
	storage := &model.MongoStorage{}
	if err := storage.Init(); err != nil {
		log.Fatal(err)
	}

	userelectionStore := model.NewUserelectionStore(storage)
	user, err := userelectionStore.GetUserElections(userID)
	if err != nil {
		log.Warnf("cannot get indexer elections: %v", err)
		return nil
	}

	indexerElections := []types.Election{}
	for _, e := range user.Elections {
		remainingAttempts := 1
		if *e.Consumed {
			remainingAttempts = 0
		}

		ie := types.Election{
			RemainingAttempts: remainingAttempts,
			Consumed:          *e.Consumed,
			ElectionID:        e.ElectionID,
			ExtraData:         []string{user.Service, user.Handler, user.Mode, user.Data},
		}
		indexerElections = append(indexerElections, ie)
	}

	return indexerElections
}

// Auth is the handler for the dummy handler
func (oh *OauthHandler) Auth(r *http.Request,
	c *types.Message, pid types.HexBytes, signType string, step int,
) types.AuthResponse {
	if signType != types.SignatureTypeBlind {
		return types.AuthResponse{Response: []string{"incorrect signature type, only blind supported"}}
	}

	providers, err := Init(pid.String())
	if err != nil {
		return types.AuthResponse{Response: []string{"failed to initialize providers"}}
	}

	switch step {
	case 0:
		if len(c.AuthData) != 2 {
			return types.AuthResponse{Response: []string{"missing auth data"}}
		}
		service := c.AuthData[0]
		redirectURL := c.AuthData[1]
		atoken := uuid.New()

		provider, ok := providers[service]
		if !ok {
			return types.AuthResponse{Response: []string{"Provider not found."}}
		}

		// Get the Service Auth URL from the electionID and requested service
		authURL := provider.GetAuthURL(redirectURL)

		return types.AuthResponse{
			Success:   true,
			AuthToken: &atoken,
			Response:  []string{authURL},
		}
	case 1:
		// Convert the provided "code" to an oAuth Token
		if len(c.AuthData) != 3 {
			return types.AuthResponse{Response: []string{"auth token not provided or missing auth data"}}
		}
		service := c.AuthData[0]
		oAuthCode := c.AuthData[1]
		redirectURL := c.AuthData[2]
		provider, ok := providers[service]
		if !ok {
			log.Warnw("Provider not found.", "service", service)
			return types.AuthResponse{Response: []string{"Provider not found."}}
		}

		oAuthToken, err := provider.GetOAuthToken(oAuthCode, redirectURL)
		if err != nil {
			log.Warnw("error obtaining the oAuthToken", "err", err)
			return types.AuthResponse{Response: []string{"error obtaining the oAuthToken"}}
		}

		// Get the profile
		profileRaw, err := provider.GetOAuthProfile(oAuthToken)
		if err != nil {
			log.Warnw("error obtaining the profile", "err", err)
			return types.AuthResponse{Response: []string{"error obtaining the profile"}}
		}

		var profile map[string]interface{}
		if err := json.Unmarshal(profileRaw, &profile); err != nil {
			log.Warnw("error marshalling the profile", "err", err)
			return types.AuthResponse{Response: []string{"error obtaining the profile"}}
		}

		// Init the Storage and get the user
		storage := &model.MongoStorage{}
		if err := storage.Init(); err != nil {
			log.Fatal(err)
		}

		consumed := false
		request := model.UserelectionRequest{
			Handler:  "oauth",
			Service:  service,
			Consumed: &consumed,
		}

		userelectionStore := model.NewUserelectionStore(storage) // This is a bit ugly, but it's the only way to avoid services
		for _, mode := range []string{"usernames"} {
			request.Mode = mode

			if mode == "usernames" {
				request.Data = profile[provider.UsernameField].(string)
			}

			usersPtr, err := userelectionStore.SearchUserelection(pid, request)
			if err != nil {
				log.Fatal(err)
			}

			// Check the length of the users array
			users := *usersPtr
			consumedT := true
			if len(users) == 1 {
				if _, err := userelectionStore.UpdateUserelection(pid,
					users[0].UserID, model.UserelectionRequest{Consumed: &consumedT}); err != nil {
					return types.AuthResponse{Response: []string{"error updating the voter"}}
				}

				return types.AuthResponse{
					Success:  true,
					Response: []string{"Challenge completed!", string(profileRaw)},
				}
			}
		}

		return types.AuthResponse{
			Success:  false,
			Response: []string{"No match found for the provided service"},
		}
	}

	return types.AuthResponse{Response: []string{"invalid auth step"}}
}

// RequireCertificate must return true if the auth handler requires some kind of client
// TLS certificate. If true then CertificateCheck() and HardcodedCertificate() methods
// must be correctly implemented. Else both function can just return true and nil.
func (oh *OauthHandler) RequireCertificate() bool {
	return false
}

// CertificateCheck is used by the Auth handler to ensure a specific certificate is
// added to the CA cert pool on the HTTP/TLS layer (optional).
func (oh *OauthHandler) CertificateCheck(subject []byte) bool {
	return true
}

// Certificates returns a hardcoded CA certificated that will be added to the
// CA cert pool by the handler (optional).
func (oh *OauthHandler) Certificates() [][]byte {
	return nil
}
