package mongodbatlas

import (
	"context"
	"os"
	"reflect"
	"testing"

	"github.com/Sectorbob/mlab-ns2/gae/ns/digest"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
	dbtesting "github.com/hashicorp/vault/sdk/database/newdbplugin/testing"
	"github.com/mongodb/go-client-mongodb-atlas/mongodbatlas"
)

const envVarRunAccTests = "VAULT_ACC"

const testMongoDBAtlasRole = `{"roles": [{"databaseName":"admin","roleName":"atlasAdmin"}]}`

var runAcceptanceTests = os.Getenv(envVarRunAccTests) == "1"

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

	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
	}

	createResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := testCredsExists(projectID, publicKey, privateKey, createResp.Username); err != nil {
		t.Fatalf("Credentials were not created: %s", err)
	}

	if err := deleteCredentials(projectID, publicKey, privateKey, createResp.Username); err != nil {
		t.Fatalf("Credentials could not be deleted: %s", err)
	}

}

func TestAcceptanceDatabaseUser_CreateUserWithSpecialChar(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")

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

	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "test.test",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
	}

	createResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := testCredsExists(projectID, publicKey, privateKey, createResp.Username); err != nil {
		t.Fatalf("Credentials were not created: %s", err)
	}

	if err := deleteCredentials(projectID, publicKey, privateKey, createResp.Username); err != nil {
		t.Fatalf("Credentials could not be deleted: %s", err)
	}

}

func TestAcceptanceDatabaseUser_DeleteUser(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")

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

	createReq := newdbplugin.NewUserRequest{
		UsernameConfig: newdbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: newdbplugin.Statements{
			Commands: []string{testMongoDBAtlasRole},
		},
	}

	createResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := testCredsExists(projectID, publicKey, privateKey, createResp.Username); err != nil {
		t.Fatalf("Credentials were not created: %s", err)
	}

	// Test default revocation statement
	delReq := newdbplugin.DeleteUserRequest{
		Username: createResp.Username,
	}

	dbtesting.AssertDeleteUser(t, db, delReq)

	// TODO: Assert not exist
}

func TestAcceptanceDatabaseUser_UpdateUser_Password(t *testing.T) {
	if !runAcceptanceTests {
		t.SkipNow()
	}

	publicKey := os.Getenv("ATLAS_PUBLIC_KEY")
	privateKey := os.Getenv("ATLAS_PRIVATE_KEY")
	projectID := os.Getenv("ATLAS_PROJECT_ID")

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

	testCreateAtlasDBUser(t, projectID, publicKey, privateKey, dbUser, startingPassword)
	if err := testCredsExists(projectID, publicKey, privateKey, dbUser); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	newPassword, err := db.GenerateCredentials(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	updateReq := newdbplugin.UpdateUserRequest{
		Username: dbUser,
		Password: &newdbplugin.ChangePassword{
			NewPassword: newPassword,
		},
	}

	dbtesting.AssertUpdateUser(t, db, updateReq)

	if err := testCredsExists(projectID, publicKey, privateKey, dbUser); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	if err := deleteCredentials(projectID, publicKey, privateKey, dbUser); err != nil {
		t.Fatalf("Credentials could not be deleted: %s", err)
	}
}

func testCreateAtlasDBUser(t testing.TB, projectID, publicKey, privateKey, username, startingPassword string) {
	client, err := getClient(publicKey, privateKey)
	if err != nil {
		t.Fatalf("Error creating client %s", err)
	}

	databaseUserRequest := &mongodbatlas.DatabaseUser{
		Username:     username,
		Password:     startingPassword,
		DatabaseName: "admin",
		Roles: []mongodbatlas.Role{
			{
				DatabaseName: "admin",
				RoleName:     "atlasAdmin",
			},
		},
	}

	_, _, err = client.DatabaseUsers.Create(context.Background(), projectID, databaseUserRequest)
	if err != nil {
		t.Fatalf("Error Creating User %s", err)
	}

}

func testCredsExists(projectID, publicKey, privateKey, username string) (err error) {
	client, err := getClient(publicKey, privateKey)
	if err != nil {
		return
	}

	_, _, err = client.DatabaseUsers.Get(context.Background(), projectID, username)

	return
}

func deleteCredentials(projectID, publicKey, privateKey, username string) error {
	client, err := getClient(publicKey, privateKey)
	if err != nil {
		return err
	}
	_, err = client.DatabaseUsers.Delete(context.Background(), projectID, username)

	return err
}

func getClient(publicKey, privateKey string) (*mongodbatlas.Client, error) {
	transport := digest.NewTransport(publicKey, privateKey)
	cl, err := transport.Client()
	if err != nil {
		return nil, err
	}

	return mongodbatlas.New(cl)

}
