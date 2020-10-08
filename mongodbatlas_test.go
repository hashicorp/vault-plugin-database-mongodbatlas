package mongodbatlas

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/mongo/readpref"

	"github.com/Sectorbob/mlab-ns2/gae/ns/digest"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
	dbtesting "github.com/hashicorp/vault/sdk/database/newdbplugin/testing"
	"github.com/mongodb/go-client-mongodb-atlas/mongodbatlas"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const envVarRunAccTests = "VAULT_ACC"

const testMongoDBAtlasRole = `{"roles": [{"databaseName":"admin","roleName":"readWriteAnyDatabase"}]}`

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

type testController struct {
	client    *mongodbatlas.Client
	ip        string
	projectID string
}

func newTestController() (testController, error) {
	if !runAcceptanceTests {
		return testController{}, nil
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")

	// This is the public IP of your machine so that it gets whitelisted
	// for the project during the test run
	ip := os.Getenv("ATLAS_PUBLIC_IP")

	// Remove access to the cluster
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

	allowList := []*mongodbatlas.ProjectIPWhitelist{
		{
			IPAddress: c.ip,
		},
	}
	_, _, err := c.client.ProjectIPWhitelist.Create(context.Background(), c.projectID, allowList)
	return err
}

func (c testController) Teardown() error {
	if !runAcceptanceTests {
		return nil
	}

	_, err := c.client.ProjectIPWhitelist.Delete(context.Background(), c.projectID, c.ip)
	return err
}

func TestIntegrationDatabaseUser_Initialize(t *testing.T) {
	connectionDetails := map[string]interface{}{
		"public_key":  "aspergesme",
		"private_key": "domine",
	}
	db := new()
	defer dbtesting.AssertClose(t, db)

	req := newdbplugin.InitializeRequest{
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

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")
	connURL := os.Getenv("ATLAS_CONN_URL")

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := newdbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "testcreate",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL)

}

func TestAcceptanceDatabaseUser_CreateUserWithSpecialChar(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")
	connURL := os.Getenv("ATLAS_CONN_URL")

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := newdbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "test.special",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	createResp := dbtesting.AssertNewUser(t, db, createReq)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, createResp.Username)

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL)
}

func TestAcceptanceDatabaseUser_DeleteUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")
	connURL := os.Getenv("ATLAS_CONN_URL")

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := newdbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	password := "myreallysecurepassword"
	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "testdelete",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
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

	assertCredsExists(t, projectID, publicKey, privateKey, createResp.Username, password, connURL)

	// Test default revocation statement
	delReq := newdbplugin.DeleteUserRequest{
		Username: createResp.Username,
	}

	dbtesting.AssertDeleteUser(t, db, delReq)

	assertCredsDoNotExist(t, projectID, publicKey, privateKey, createResp.Username)
}

func TestAcceptanceDatabaseUser_UpdateUser_Password(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")
	connURL := os.Getenv("ATLAS_CONN_URL")

	connectionDetails := map[string]interface{}{
		"public_key":  publicKey,
		"private_key": privateKey,
		"project_id":  projectID,
	}

	db := new()
	defer dbtesting.AssertClose(t, db)

	initReq := newdbplugin.InitializeRequest{
		Config: connectionDetails,
	}

	dbtesting.AssertInitialize(t, db, initReq)

	// create the database user in advance, and test the connection
	dbUser := "testmongouser"
	startingPassword := "3>^chcBo7a7t-ZI"

	createAtlasDBUser(t, projectID, publicKey, privateKey, dbUser, startingPassword)
	defer deleteAtlasDBUser(t, projectID, publicKey, privateKey, dbUser)

	assertCredsExists(t, projectID, publicKey, privateKey, dbUser, startingPassword, connURL)

	newPassword := "some-other-password"

	updateReq := newdbplugin.UpdateUserRequest{
		Username: dbUser,
		Password: &newdbplugin.ChangePassword{
			NewPassword: newPassword,
		},
	}

	dbtesting.AssertUpdateUser(t, db, updateReq)

	assertCredsExists(t, projectID, publicKey, privateKey, dbUser, newPassword, connURL)
}

func assertCredsExists(t testing.TB, projectID, publicKey, privateKey, username, password, connURL string) {
	t.Helper()

	t.Logf("Asserting username: %s", username)

	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to get an API client: %s", err)
	}

	_, _, err = client.DatabaseUsers.Get(context.Background(), projectID, username)
	if err != nil {
		t.Fatalf("Failed to retrieve user from from MongoDB Atlas: %s", err)
	}

	// Connect to the cluster to verify user password
	mongoURI := fmt.Sprintf("mongodb+srv://%s", connURL)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	credential := options.Credential{
		Username: username,
		Password: password,
	}
	clientOpts := options.Client().ApplyURI(mongoURI).SetAuth(credential)

	mClient, err := mongo.Connect(context.Background(), clientOpts)
	if err != nil {
		t.Fatalf("Failed to connect to mongo: %s", err)
	}
	defer mClient.Disconnect(context.Background())

	ticker := time.NewTicker(3 * time.Second)
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

	dbUser, _, err := client.DatabaseUsers.Get(context.Background(), projectID, username)
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

	_, err = client.DatabaseUsers.Delete(context.Background(), projectID, username)
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
