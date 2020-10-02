package mongodbatlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/mitchellh/mapstructure"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/dbplugin"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
	"github.com/mongodb/go-client-mongodb-atlas/mongodbatlas"
)

const mongoDBAtlasTypeName = "mongodbatlas"

// Verify interface is implemented
var _ newdbplugin.Database = &MongoDBAtlas{}

type MongoDBAtlas struct {
	*mongoDBAtlasConnectionProducer
	credsutil.CredentialsProducer
}

func New() (interface{}, error) {
	db := new()
	dbType := newdbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new() *MongoDBAtlas {
	connProducer := &mongoDBAtlasConnectionProducer{
		Type: mongoDBAtlasTypeName,
	}

	credsProducer := &credsutil.SQLCredentialsProducer{
		DisplayNameLen: credsutil.NoneLength,
		RoleNameLen:    15,
		UsernameLen:    20,
		Separator:      "-",
	}

	return &MongoDBAtlas{
		mongoDBAtlasConnectionProducer: connProducer,
		CredentialsProducer:            credsProducer,
	}
}

// Run instantiates a MongoDBAtlas object, and runs the RPC server for the plugin
func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}

	dbplugin.Serve(dbType.(dbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

	return nil
}

func (m *MongoDBAtlas) Initialize(ctx context.Context, req newdbplugin.InitializeRequest) (newdbplugin.InitializeResponse, error) {
	m.Lock()
	defer m.Unlock()

	m.RawConfig = req.Config

	err := mapstructure.WeakDecode(req.Config, m.mongoDBAtlasConnectionProducer)
	if err != nil {
		return newdbplugin.InitializeResponse{}, err
	}

	if len(m.PublicKey) == 0 {
		return newdbplugin.InitializeResponse{}, errors.New("public Key is not set")
	}

	if len(m.PrivateKey) == 0 {
		return newdbplugin.InitializeResponse{}, errors.New("private Key is not set")
	}

	// Set initialized to true at this point since all fields are set,
	// and the connection can be established at a later time.
	m.Initialized = true

	resp := newdbplugin.InitializeResponse{
		Config: req.Config,
	}

	return resp, nil
}

func (m *MongoDBAtlas) NewUser(ctx context.Context, req newdbplugin.NewUserRequest) (newdbplugin.NewUserResponse, error) {
	// Grab the lock
	m.Lock()
	defer m.Unlock()

	if len(req.Statements.Commands) == 0 {
		return newdbplugin.NewUserResponse{}, dbutil.ErrEmptyCreationStatement
	}

	client, err := m.getConnection(ctx)
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	username, err := m.GenerateUsername(dbplugin.UsernameConfig{
		DisplayName: req.UsernameConfig.DisplayName,
		RoleName:    req.UsernameConfig.RoleName,
	})
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	password, err := m.GeneratePassword()
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	// Unmarshal statements.CreationStatements into mongodbRoles
	var databaseUser mongoDBAtlasStatement
	err = json.Unmarshal([]byte(req.Statements.Commands[0]), &databaseUser)
	if err != nil {
		return newdbplugin.NewUserResponse{}, fmt.Errorf("Error unmarshalling statement %s", err)
	}

	// Default to "admin" if no db provided
	if databaseUser.DatabaseName == "" {
		databaseUser.DatabaseName = "admin"
	}

	if len(databaseUser.Roles) == 0 {
		return newdbplugin.NewUserResponse{}, fmt.Errorf("roles array is required in creation statement")
	}

	databaseUserRequest := &mongodbatlas.DatabaseUser{
		Username:     username,
		Password:     password,
		DatabaseName: databaseUser.DatabaseName,
		Roles:        databaseUser.Roles,
	}

	_, _, err = client.DatabaseUsers.Create(ctx, m.ProjectID, databaseUserRequest)
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	resp := newdbplugin.NewUserResponse{
		Username: username,
	}

	return resp, nil
}

func (m *MongoDBAtlas) UpdateUser(ctx context.Context, req newdbplugin.UpdateUserRequest) (newdbplugin.UpdateUserResponse, error) {
	if req.Password == nil {
		return newdbplugin.UpdateUserResponse{}, nil
	}

	m.Lock()
	defer m.Unlock()

	client, err := m.getConnection(ctx)
	if err != nil {
		return newdbplugin.UpdateUserResponse{}, err
	}

	databaseUserRequest := &mongodbatlas.DatabaseUser{
		Password: req.Password.NewPassword,
	}

	_, _, err = client.DatabaseUsers.Update(context.Background(), m.ProjectID, req.Username, databaseUserRequest)
	if err != nil {
		return newdbplugin.UpdateUserResponse{}, err
	}

	return newdbplugin.UpdateUserResponse{}, nil

}

func (m *MongoDBAtlas) DeleteUser(ctx context.Context, req newdbplugin.DeleteUserRequest) (newdbplugin.DeleteUserResponse, error) {
	m.Lock()
	defer m.Unlock()

	client, err := m.getConnection(ctx)
	if err != nil {
		return newdbplugin.DeleteUserResponse{}, err
	}

	_, err = client.DatabaseUsers.Delete(ctx, m.ProjectID, req.Username)
	return newdbplugin.DeleteUserResponse{}, err
}

func (m *MongoDBAtlas) getConnection(ctx context.Context) (*mongodbatlas.Client, error) {
	client, err := m.Connection(ctx)
	if err != nil {
		return nil, err
	}

	return client.(*mongodbatlas.Client), nil
}

// RotateRootCredentials is not currently supported on MongoDB
func (m *MongoDBAtlas) RotateRootCredentials(ctx context.Context, statements []string) (map[string]interface{}, error) {
	return nil, errors.New("root credential rotation is not currently implemented in this database secrets engine")
}

// Type returns the TypeName for this backend
func (m *MongoDBAtlas) Type() (string, error) {
	return mongoDBAtlasTypeName, nil
}

type mongoDBAtlasStatement struct {
	DatabaseName string              `json:"database_name"`
	Roles        []mongodbatlas.Role `json:"roles,omitempty"`
}
