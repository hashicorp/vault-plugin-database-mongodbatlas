package mongodbatlas

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo/readpref"

	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	dbtesting "github.com/hashicorp/vault/sdk/database/dbplugin/v5/testing"
	"github.com/mongodb-forks/digest"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/atlas/mongodbatlas"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const (
	testMongoDBAtlasRole = `{"roles": [{"databaseName":"admin","roleName":"readWriteAnyDatabase"}], "scopes": [{"name": "vault-test-free-cluster", "type": "CLUSTER"}]}`

	envVarAtlasPublicKey   = "ATLAS_PUBLIC_KEY"
	envVarAtlasPrivateKey  = "ATLAS_PRIVATE_KEY"
	envVarAtlasProjectID   = "ATLAS_PROJECT_ID"
	envVarAtlasConnURL     = "ATLAS_CONN_URL"
	envVarAtlasAllowListIP = "ATLAS_ALLOWLIST_IP"

	envVarRunAccTests = "VAULT_ACC"
)

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

func TestMain(m *testing.M) {
	flag.Parse()

	controller, err := newTestController()
	if err != nil {
		log.Fatal(err)
	}

	if err := controller.Setup(); err != nil {
		log.Fatal(err)
	}

	// Run the actual tests
	code := m.Run()

	if err := controller.Teardown(); err != nil {
		log.Fatal(err)
	}

	os.Exit(code)
}

// testController takes care of performing one-time setup and teardown tasks per
// test run, such as adding the IP of the machine to Atlas' allowlist. This is
// only applicable when running acceptance tests.
type testController struct {
	client    *mongodbatlas.Client
	ip        string
	projectID string
}

func newTestController() (testController, error) {
	if !runAcceptanceTests {
		return testController{}, nil
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)

	// This is the public IP of your machine so that it gets allow listed
	// for the project during the test run
	ip := os.Getenv(envVarAtlasAllowListIP)

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		return testController{}, err
	}

	controller := testController{
		client:    client,
		ip:        ip,
		projectID: projectID,
	}

	return controller, nil
}

func (c testController) Setup() error {
	if !runAcceptanceTests {
		return nil
	}

	allowList := []*mongodbatlas.ProjectIPAccessList{
		{
			IPAddress: c.ip,
		},
	}
	_, _, err := c.client.ProjectIPAccessList.Create(context.Background(), c.projectID, allowList)
	return err
}

func (c testController) Teardown() error {
	if !runAcceptanceTests {
		return nil
	}

	_, err := c.client.ProjectIPAccessList.Delete(context.Background(), c.projectID, c.ip)
	return err
}

func TestIntegrationDatabaseUser_Initialize(t *testing.T) {
	connectionDetails := map[string]interface{}{
		"public_key":  "aspergesme",
		"private_key": "domine",
	}
	db := new()
	defer dbtesting.AssertClose(t, db)

	req := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	expectedConfig := map[string]interface{}{
		"public_key":  "aspergesme",
		"private_key": "domine",
	}

	resp := dbtesting.AssertInitialize(t, db, req)

	if !reflect.DeepEqual(resp.Config, expectedConfig) {
		t.Fatalf("Actual config: %#v\nExpected config: %#v", resp.Config, expectedConfig)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}
}

func TestAcceptanceDatabaseUser_CreateUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "testcreate",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL, testMongoDBAtlasRole)
}

func TestAcceptanceDatabaseUser_CreateUserDefaultTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	roleName := "test"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "testcreate",
			RoleName:    roleName,
		},
		Statements: dbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL, testMongoDBAtlasRole)
	if len(createResp.Username) != 20 {
		t.Fatalf("Username did not match template, username: %s, defaultUserNameTemplate: %s", createResp.Username, defaultUserNameTemplate)
	}

	expectedUsernameRegex := `^v-test-[a-zA-Z0-9]{13}$`
	require.Regexp(t, expectedUsernameRegex, createResp.Username)
}

func TestAcceptanceDatabaseUser_CreateUserWithTemplate(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":        publicKey,
		"private_key":       privateKey,
		"project_id":        projectID,
		"username_template": "begin_{{.RoleName}}_end",
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	roleName := "test"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "testcreate",
			RoleName:    roleName,
		},
		Statements: dbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL, testMongoDBAtlasRole)

	expectedUsername := "begin_" + roleName + "_end"
	if createResp.Username != expectedUsername {
		t.Fatalf("Username did not match template, username: %s, expectedUsername: %s", createResp.Username, expectedUsername)
	}
}

func TestAcceptanceDatabaseUser_CreateUserWithSpecialChar(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test.special",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL, testMongoDBAtlasRole)
}

func TestAcceptanceDatabaseUser_DeleteUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "testdelete",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer func() {
		// Delete user directly if the test failed for any reason after this.
		if t.Failed() {
			deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)
		}
	}()

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL, testMongoDBAtlasRole)

	// Test default revocation statement
	delReq := dbplugin.DeleteUserRequest{
		Username: createResp.Username,
	}

	dbtesting.AssertDeleteUser(t, db, delReq)

	assertCredsDoNotExist(t, projectID, publicKey, privateKey, createResp.Username)
}

func TestAcceptanceDatabaseUser_UpdateUser_Password(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv(envVarAtlasPublicKey)
	privateKey := os.Getenv(envVarAtlasPrivateKey)
	projectID := os.Getenv(envVarAtlasProjectID)
	connURL := os.Getenv(envVarAtlasConnURL)

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := dbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	// create the database user in advance, and test the connection
	dbUser := "testmongouser"
	startingPassword := "myreallysecurepassword"

	createAtlasDBUser(t, projectID, publicKey, privateKey, dbUser, startingPassword)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, dbUser)

	assertCredsExists(t, projectID, publicKey, privateKey, dbUser, startingPassword, connURL, "")

	newPassword := "some-other-password"

	updateReq := dbplugin.UpdateUserRequest{
		Username: dbUser,
		Password: &dbplugin.ChangePassword{
			NewPassword: newPassword,
		},
	}

	dbtesting.AssertUpdateUser(t, db, updateReq)

	assertCredsExists(t, projectID, publicKey, privateKey, dbUser, newPassword, connURL, "")
}

func assertCredsExists(t testing.TB, projectID, publicKey, privateKey, username, password, connURL, expectedRolesAndScopesJSON string) {
	t.Helper()

	t.Logf("Asserting username: %s", username)

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to get an API client: %s", err)
	}

	dbUser, _, err := client.DatabaseUsers.Get(context.Background(), "admin", projectID, username)
	if err != nil {
		t.Fatalf("Failed to retrieve user from from MongoDB Atlas: %s", err)
	}
	if expectedRolesAndScopesJSON != "" {
		var expectedRolesAndScopes mongoDBAtlasStatement
		err = json.Unmarshal([]byte(expectedRolesAndScopesJSON), &expectedRolesAndScopes)
		if err != nil {
			t.Fatalf("Failed to unmarshal database user: %s", err)
		}
		if len(dbUser.Roles) != len(expectedRolesAndScopes.Roles) || len(dbUser.Scopes) != len(expectedRolesAndScopes.Scopes) {
			t.Fatalf("Mismatch in roles or scopes, expected %+v but got %+v", expectedRolesAndScopes, dbUser)
		}
		for i := range dbUser.Roles {
			if dbUser.Roles[i] != expectedRolesAndScopes.Roles[i] {
				t.Fatalf("Mismatch in roles, expected %+v but got %+v", expectedRolesAndScopes.Roles[i], dbUser.Roles[i])
			}
		}
		for i := range dbUser.Scopes {
			if dbUser.Scopes[i] != expectedRolesAndScopes.Scopes[i] {
				t.Fatalf("Mismatch in scopes, expected %+v but got %+v", expectedRolesAndScopes.Scopes[i], dbUser.Scopes[i])
			}
		}
	}

	// Connect to the cluster to verify user password
	mongoURI := fmt.Sprintf("mongodb+srv://%s", connURL)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	credential := options.Credential{
		Username: username,
		Password: url.QueryEscape(password),
	}
	clientOpts := options.Client().ApplyURI(mongoURI).SetAuth(credential)

	mClient, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		t.Fatalf("Failed to connect to mongo: %s", err)
	}
	defer mClient.Disconnect(context.Background())

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			t.Fatalf("Timed out waiting for user %s to ping database", username)
		case <-ticker.C:
			err = mClient.Ping(ctx, readpref.Primary())
			if err == nil {
				return
			}
		}
	}
}

func assertCredsDoNotExist(t testing.TB, projectID, publicKey, privateKey, username string) {
	t.Helper()

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Error creating client: %s", err)
	}

	dbUser, _, err := client.DatabaseUsers.Get(context.Background(), "admin", projectID, username)
	if err == nil && dbUser != nil {
		t.Fatal("Expected user to not exist")
	}
}

func createAtlasDBUser(t testing.TB, projectID, publicKey, privateKey, username, startingPassword string) {
	t.Helper()

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Error creating client: %s", err)
	}

	databaseUserRequest := &mongodbatlas.DatabaseUser{
		Username:     username,
		Password:     startingPassword,
		DatabaseName: "admin",
		Roles: []mongodbatlas.Role{
			{
				DatabaseName: "admin",
				RoleName:     "readWriteAnyDatabase",
			},
		},
	}

	_, _, err = client.DatabaseUsers.Create(context.Background(), projectID, databaseUserRequest)
	if err != nil {
		t.Fatalf("Error creating user %s", err)
	}

}

func deleteAtlasDBUser(t testing.TB, projectID, publicKey, privateKey, username string) {
	t.Helper()

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Error creating client: %s", err)
	}

	_, err = client.DatabaseUsers.Delete(context.Background(), "admin", projectID, username)
	if err != nil {
		t.Fatalf("Error deleting database user: %s", err)
	}
}

func getClient(publicKey, privateKey string) (*mongodbatlas.Client, error) {
	transport := digest.NewTransport(publicKey, privateKey)
	cl, err := transport.Client()
	if err != nil {
		return nil, err
	}

	return mongodbatlas.New(cl)

}
