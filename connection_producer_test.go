// Copyright IBM Corp. 2019, 2025
// SPDX-License-Identifier: MPL-2.0

package mongodbatlas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/stretchr/testify/require"
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

	client := serviceAccountClient("id", "secret", tokenServer.URL)

	for range 2 {
		resp, err := client.Get(apiServer.URL)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// The token is reused until it expires.
	require.EqualValues(t, 1, tokenRequests.Load())
}
