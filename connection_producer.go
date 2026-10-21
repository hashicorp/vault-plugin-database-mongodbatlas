// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package mongodbatlas

import (
	"context"
	"errors"
	"net/http"
	"sync"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/hashicorp/vault/sdk/helper/useragent"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/mitchellh/mapstructure"
	"github.com/mongodb-forks/digest"
	"go.mongodb.org/atlas/mongodbatlas"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	// TODO: The Vault version used in the user agent string is hard coded until
	//  it's possible for database plugins to use the system view to obtain correct
	//  Vault version information via the plugin environment.
	userAgentVaultVersion = "1.13.0"
	userAgentPluginName   = "database-mongodbatlas"

	// atlasTokenURL is the OAuth 2.0 token endpoint for Atlas service accounts.
	atlasTokenURL = "https://cloud.mongodb.com/api/oauth/token"
)

type mongoDBAtlasConnectionProducer struct {
	PublicKey  string `json:"public_key" structs:"public_key" mapstructure:"public_key"`
	PrivateKey string `json:"private_key" structs:"private_key" mapstructure:"private_key"`
	ProjectID  string `json:"project_id" structs:"project_id" mapstructure:"project_id"`

	// ClientID and ClientSecret are the credentials of an Atlas service account.
	// They are an alternative to PublicKey and PrivateKey.
	ClientID     string `json:"client_id" structs:"client_id" mapstructure:"client_id"`
	ClientSecret string `json:"client_secret" structs:"client_secret" mapstructure:"client_secret"`

	Initialized bool
	RawConfig   map[string]interface{}
	Type        string
	client      *mongodbatlas.Client
	sync.Mutex
}

func (c *mongoDBAtlasConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.PrivateKey:   "[private_key]",
		c.ClientSecret: "[client_secret]",
	}
}

// Close terminates the database connection.
func (c *mongoDBAtlasConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	c.client = nil

	return nil
}

func (c *mongoDBAtlasConnectionProducer) Connection(_ context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.client != nil {
		return c.client, nil
	}

	cl, err := c.httpClient()
	if err != nil {
		return nil, err
	}

	client, err := mongodbatlas.New(cl)
	if err != nil {
		return nil, err
	}

	// TODO: Obtain the plugin environment from the system view.
	env := &logical.PluginEnvironment{
		VaultVersion: userAgentVaultVersion,
	}
	client.UserAgent = useragent.PluginString(env, userAgentPluginName)

	c.client = client

	return c.client, nil
}

// httpClient returns an HTTP client that authenticates to the Atlas Admin API
// with either the service account or the programmatic API key.
func (c *mongoDBAtlasConnectionProducer) httpClient() (*http.Client, error) {
	if c.ClientID != "" {
		return serviceAccountClient(c.ClientID, c.ClientSecret, atlasTokenURL), nil
	}

	transport := digest.NewTransport(c.PublicKey, c.PrivateKey)
	return transport.Client()
}

// serviceAccountClient returns an HTTP client that uses the OAuth 2.0 client
// credentials flow. It fetches a token on first use and a new one when the
// current token expires.
func serviceAccountClient(clientID, clientSecret, tokenURL string) *http.Client {
	config := clientcredentials.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		AuthStyle:    oauth2.AuthStyleInHeader,
	}

	// The client is cached and outlives any single request, so it must not
	// use a request context.
	return config.Client(context.Background())
}

func (m *mongoDBAtlasConnectionProducer) Initialize(ctx context.Context, req dbplugin.InitializeRequest) error {
	m.Lock()
	defer m.Unlock()

	m.RawConfig = req.Config

	err := mapstructure.WeakDecode(req.Config, m)
	if err != nil {
		return err
	}

	if err := m.validateAuth(); err != nil {
		return err
	}

	// Set initialized to true at this point since all fields are set,
	// and the connection can be established at a later time.
	m.Initialized = true

	return nil
}

// validateAuth checks that exactly one complete set of credentials is set:
// a programmatic API key or a service account.
func (m *mongoDBAtlasConnectionProducer) validateAuth() error {
	hasAPIKey := len(m.PublicKey) > 0 || len(m.PrivateKey) > 0
	hasServiceAccount := len(m.ClientID) > 0 || len(m.ClientSecret) > 0

	switch {
	case hasAPIKey && hasServiceAccount:
		return errors.New("set either public_key and private_key, or client_id and client_secret, not both; " +
			"to switch an existing config, set the unused fields to an empty string")
	case hasServiceAccount:
		if len(m.ClientID) == 0 {
			return errors.New("client_id is not set")
		}
		if len(m.ClientSecret) == 0 {
			return errors.New("client_secret is not set")
		}
	case hasAPIKey:
		if len(m.PublicKey) == 0 {
			return errors.New("public Key is not set")
		}
		if len(m.PrivateKey) == 0 {
			return errors.New("private Key is not set")
		}
	default:
		return errors.New("either public_key and private_key, or client_id and client_secret must be set")
	}

	return nil
}
