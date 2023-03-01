package oauthhandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/joho/godotenv"
	"go.vocdoni.io/dvote/log"
	"gopkg.in/yaml.v3"
)

// Config represents the configuration file.
type Config struct {
	Providers map[string]ProviderConfig `yaml:"providers"`
}

// ProviderConfig represents the configuration for an OAuth provider.
type ProviderConfig struct {
	Name          string `yaml:"name"`
	AuthURL       string `yaml:"auth_url"`
	TokenURL      string `yaml:"token_url"`
	ProfileURL    string `yaml:"profile_url"`
	ClientID      string `yaml:"client_id"`
	ClientSecret  string `yaml:"client_secret"`
	Scope         string `yaml:"scope"`
	UsernameField string `yaml:"username_field"`
}

// Provider is the OAuth provider.
type Provider struct {
	Name          string
	AuthURL       string
	TokenURL      string
	ProfileURL    string
	ClientID      string
	ClientSecret  string
	Scope         string
	UsernameField string
}

// OAuthToken is the OAuth token.
type OAuthToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

// NewProvider creates a new OAuth provider.
func NewProvider(name, authURL, tokenURL, profileURL, clientID, clientSecret, scope string, usernameField string) *Provider {
	return &Provider{
		Name:          name,
		AuthURL:       authURL,
		TokenURL:      tokenURL,
		ProfileURL:    profileURL,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		Scope:         scope,
		UsernameField: usernameField,
	}
}

func Init(pid string) (map[string]*Provider, error) {
	// Load the .env file
	err := godotenv.Load()
	if err != nil {
		log.Errorw(err, "Error loading .env file")
	}

	// Read the configuration file.
	filename := filepath.Join("handlers", "oauthhandler", "config.yml")
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %v", err)
	}

	// Parse the configuration file.
	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to parse configuration file: %v", err)
	}

	// Initialize the providers.
	providers := make(map[string]*Provider, len(cfg.Providers))
	for name, conf := range cfg.Providers {
		provider := NewProvider(
			conf.Name,
			conf.AuthURL,
			conf.TokenURL,
			conf.ProfileURL,
			os.Getenv(conf.ClientID),
			os.Getenv(conf.ClientSecret),
			conf.Scope,
			conf.UsernameField,
		)
		providers[name] = provider
	}

	return providers, nil
}

// GetAuthURL returns the OAuth authorize URL for the provider.
func (p *Provider) GetAuthURL(redirectURL string) string {
	u, _ := url.Parse(p.AuthURL)
	q := u.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", redirectURL)
	q.Set("scope", p.Scope)
	u.RawQuery = q.Encode()
	return u.String()
}

// GetOAuthToken obtains the OAuth token for the provider using the authorization code.
func (p *Provider) GetOAuthToken(code string, redirectURL string) (*OAuthToken, error) {
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", redirectURL)
	data.Set("code", code)

	req, err := http.NewRequest("POST", p.TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warnw("error closing HTTP body: %v\n", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get OAuth token: %s", body)
	}

	var token OAuthToken
	if err := json.Unmarshal(body, &token); err != nil {
		log.Warnf("failed to unmarshal OAuth token: %s", body)
		return nil, err
	}

	return &token, nil
}

// GetOAuthProfile obtains the OAuth profile for the provider using the OAuth token.
func (p *Provider) GetOAuthProfile(token *OAuthToken) ([]byte, error) {
	req, err := http.NewRequest("GET", p.ProfileURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.AccessToken))
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Warnw("error closing HTTP body", "err", err)
		}
	}()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get OAuth profile: %s", body)
	}

	return body, nil
}
