// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package mongodbatlas

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/mongodb-forks/digest"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestConnectionProducer_ValidateAuth(t *testing.T) {
	tests := map[string]struct {
		config  map[string]interface{}
		wantErr string
	}{
		"api key": {
			config: map[string]interface{}{"public_key": "pub", "private_key": "priv"},
		},
		"service account": {
			config: map[string]interface{}{"client_id": "id", "client_secret": "secret"},
		},
		"switch to service account with blanked api key": {
			config: map[string]interface{}{"public_key": "", "private_key": "", "client_id": "id", "client_secret": "secret"},
		},
		"nothing set": {
			config:  map[string]interface{}{},
			wantErr: "either public_key and private_key, or client_id and client_secret must be set",
		},
		"both set": {
			config:  map[string]interface{}{"public_key": "pub", "private_key": "priv", "client_id": "id", "client_secret": "secret"},
			wantErr: "set either public_key and private_key, or client_id and client_secret, not both",
		},
		"api key and half a service account": {
			config:  map[string]interface{}{"public_key": "pub", "private_key": "priv", "client_id": "id"},
			wantErr: "not both",
		},
		"public key only": {
			config:  map[string]interface{}{"public_key": "pub"},
			wantErr: "private Key is not set",
		},
		"private key only": {
			config:  map[string]interface{}{"private_key": "priv"},
			wantErr: "public Key is not set",
		},
		"client id only": {
			config:  map[string]interface{}{"client_id": "id"},
			wantErr: "client_secret is not set",
		},
		"client secret only": {
			config:  map[string]interface{}{"client_secret": "secret"},
			wantErr: "client_id is not set",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			db := new()
			defer dbtesting.AssertClose(t, db)

			_, err := db.Initialize(t.Context(), dbplugin.InitializeRequest{Config: test.config})
			if test.wantErr == "" {
				require.NoError(t, err)
				require.True(t, db.Initialized)
				return
			}
			require.ErrorContains(t, err, test.wantErr)
			require.False(t, db.Initialized)
		})
	}
}

func TestIntegrationDatabaseUser_Initialize_ServiceAccount(t *testing.T) {
	connectionDetails := map[string]interface{}{
		"client_id":     "mdb_sa_id_test",
		"client_secret": "mdb_sa_sk_test",
	}
	db := new()
	defer dbtesting.AssertClose(t, db)

	req := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	expectedConfig := map[string]interface{}{
		"client_id":     "mdb_sa_id_test",
		"client_secret": "mdb_sa_sk_test",
		dbplugin.SupportedCredentialTypesKey: []interface{}{
			dbplugin.CredentialTypePassword.String(),
			dbplugin.CredentialTypeClientCertificate.String(),
		},
	}

	resp := dbtesting.AssertInitialize(t, db, req)

	if !reflect.DeepEqual(resp.Config, expectedConfig) {
		t.Fatalf("Actual config: %#v\nExpected config: %#v", resp.Config, expectedConfig)
	}
}

func TestConnectionProducer_SecretValues(t *testing.T) {
	c := &mongoDBAtlasConnectionProducer{
		ClientID:     "id",
		ClientSecret: "secret",
	}

	values := c.secretValues()
	require.Equal(t, "[client_secret]", values["secret"])
	require.NotContains(t, values, "id")
}

func TestServiceAccountClient(t *testing.T) {
	var tokenRequests atomic.Int32
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenRequests.Add(1)

		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != "id" || clientSecret != "secret" {
			http.Error(w, "bad client credentials", http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil || r.PostForm.Get("grant_type") != "client_credentials" {
			http.Error(w, "bad grant type", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`)
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer apiServer.Close()

	client := serviceAccountClient("id", "secret", tokenServer.URL, tokenRequestTimeout)

	for range 2 {
		resp, err := client.Get(apiServer.URL)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// The token is reused until it expires.
	require.EqualValues(t, 1, tokenRequests.Load())
}

func TestTokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"Invalid client credentials"}`)
	}))
	defer tokenServer.Close()

	client := serviceAccountClient("id", "wrong-secret", tokenServer.URL, tokenRequestTimeout)

	_, err := client.Get("http://127.0.0.1:0")
	require.Error(t, err)

	// The HTTP client wraps the token error in *url.Error, which the error
	// sanitizer would replace with "unable to parse connection url".
	var urlErr *url.Error
	require.ErrorAs(t, err, &urlErr)

	err = tokenError(err)
	require.False(t, errors.As(err, &urlErr), "tokenError must not wrap *url.Error")
	require.ErrorContains(t, err, "failed to get an Atlas service account access token")
	require.ErrorContains(t, err, "invalid_client")
	require.NotContains(t, err.Error(), "wrong-secret")

	// Other errors pass through unchanged.
	other := errors.New("other")
	require.Same(t, other, tokenError(other))
	require.NoError(t, tokenError(nil))
}

// newTokenServer returns a token server that issues tokens which expire after
// expiresIn seconds, and an API server that accepts them.
func newTokenServer(t *testing.T, expiresIn int) (tokenURL, apiURL string, tokenRequests *atomic.Int32) {
	t.Helper()
	tokenRequests = &atomic.Int32{}
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := tokenRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"access_token":"token-%d","token_type":"Bearer","expires_in":%d}`, n, expiresIn)
	}))
	t.Cleanup(tokenServer.Close)

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		want := fmt.Sprintf("Bearer token-%d", tokenRequests.Load())
		if r.Header.Get("Authorization") != want {
			http.Error(w, "unexpected bearer token", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(apiServer.Close)

	return tokenServer.URL, apiServer.URL, tokenRequests
}

func TestServiceAccountClient_RefreshesExpiredToken(t *testing.T) {
	// oauth2 treats a token as expired 10 seconds early, so a token that
	// lasts 1 second is refreshed on every request.
	tokenURL, apiURL, tokenRequests := newTokenServer(t, 1)
	client := serviceAccountClient("id", "secret", tokenURL, tokenRequestTimeout)

	for range 2 {
		resp, err := client.Get(apiURL)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	require.EqualValues(t, 2, tokenRequests.Load())
}

func TestServiceAccountClient_TokenRequestTimeout(t *testing.T) {
	release := make(chan struct{})
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer tokenServer.Close()
	defer close(release)

	client := serviceAccountClient("id", "secret", tokenServer.URL, 100*time.Millisecond)

	done := make(chan error, 1)
	go func() {
		_, err := client.Get("http://127.0.0.1:0")
		done <- err
	}()

	select {
	case err := <-done:
		require.Error(t, err)
		err = tokenError(err)
		var urlErr *url.Error
		require.False(t, errors.As(err, &urlErr), "tokenError must not wrap *url.Error")
		require.ErrorContains(t, err, "failed to get an Atlas service account access token")
		require.ErrorContains(t, err, "Client.Timeout exceeded")
	case <-time.After(5 * time.Second):
		t.Fatal("token request did not time out")
	}
}

func TestTokenError_NetworkError(t *testing.T) {
	// A closed server refuses connections.
	tokenServer := httptest.NewServer(http.NotFoundHandler())
	tokenServer.Close()

	client := serviceAccountClient("id", "secret", tokenServer.URL, tokenRequestTimeout)
	_, err := client.Get("http://127.0.0.1:0")
	require.Error(t, err)

	err = tokenError(err)
	var urlErr *url.Error
	require.False(t, errors.As(err, &urlErr), "tokenError must not wrap *url.Error")
	require.ErrorContains(t, err, "failed to get an Atlas service account access token")
	require.ErrorContains(t, err, "connection refused")
}

func TestConnectionProducer_HTTPClient(t *testing.T) {
	t.Run("service account", func(t *testing.T) {
		tokenURL, _, tokenRequests := newTokenServer(t, 3600)
		c := &mongoDBAtlasConnectionProducer{ClientID: "id", ClientSecret: "secret", tokenURL: tokenURL}

		client, err := c.httpClient()
		require.NoError(t, err)
		require.IsType(t, &oauth2.Transport{}, client.Transport)
		require.Zero(t, client.Timeout, "API requests are bounded by their request context, not the token timeout")

		_, err = client.Transport.(*oauth2.Transport).Source.Token()
		require.NoError(t, err)
		require.EqualValues(t, 1, tokenRequests.Load(), "token must come from the configured token URL")
	})

	t.Run("api key", func(t *testing.T) {
		c := &mongoDBAtlasConnectionProducer{PublicKey: "pub", PrivateKey: "priv"}

		client, err := c.httpClient()
		require.NoError(t, err)
		require.IsType(t, &digest.Transport{}, client.Transport)
	})
}

// TestNewUser_ServiceAccountTokenError checks that a token error reaches the
// caller through the error sanitizer that New() installs, instead of being
// replaced with "unable to parse connection url".
func TestNewUser_ServiceAccountTokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":"invalid_client","error_description":"Invalid client credentials"}`)
	}))
	defer tokenServer.Close()

	inner := new()
	inner.tokenURL = tokenServer.URL
	db := dbplugin.NewDatabaseErrorSanitizerMiddleware(inner, inner.secretValues)
	defer dbtesting.AssertClose(t, db)

	dbtesting.AssertInitialize(t, db, dbplugin.InitializeRequest{
		Config: map[string]interface{}{
			"client_id":     "id",
			"client_secret": "wrong-secret",
			"project_id":    "project",
		},
	})

	_, err := db.NewUser(context.Background(), dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{DisplayName: "test", RoleName: "test"},
		Statements:     dbplugin.Statements{Commands: []string{testMongoDBAtlasRole}},
		Password:       "password",
		Expiration:     time.Now().Add(time.Minute),
	})
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to get an Atlas service account access token")
	require.ErrorContains(t, err, "invalid_client")
	require.NotContains(t, err.Error(), "unable to parse connection url")
	require.NotContains(t, err.Error(), "wrong-secret")
}
