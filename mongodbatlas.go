package mongodbatlas

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"
	"github.com/hashicorp/vault/sdk/database/newdbplugin"
	"github.com/mitchellh/mapstructure"
	"github.com/mongodb/go-client-mongodb-atlas/mongodbatlas"
)

const mongoDBAtlasTypeName = "mongodbatlas"

// Verify interface is implemented
var _ newdbplugin.Database = &MongoDBAtlas{}

type MongoDBAtlas struct {
	*mongoDBAtlasConnectionProducer
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

	return &MongoDBAtlas{
		mongoDBAtlasConnectionProducer: connProducer,
	}
}

// Run instantiates a MongoDBAtlas object, and runs the RPC server for the plugin
func Run(apiTLSConfig *api.TLSConfig) error {
	dbType, err := New()
	if err != nil {
		return err
	}

	newdbplugin.Serve(dbType.(newdbplugin.Database), api.VaultPluginTLSProvider(apiTLSConfig))

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

	username, err := credsutil.GenerateUsername(
		credsutil.DisplayName("", credsutil.NoneLength),
		credsutil.RoleName(req.UsernameConfig.RoleName, 15),
		credsutil.MaxLength(20),
		credsutil.Separator("-"),
	)
	if err != nil {
		return newdbplugin.NewUserResponse{}, err
	}

	// Unmarshal creation statements into mongodb roles
	var databaseUser mongoDBAtlasStatement
	err = json.Unmarshal([]byte(req.Statements.Commands[0]), &databaseUser)
	if err != nil {
		return newdbplugin.NewUserResponse{}, fmt.Errorf("error unmarshalling statement %s", err)
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
		Password:     req.Password,
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
	if req.Password != nil {
		err := m.changePassword(ctx, req.Username, req.Password.NewPassword)
		return newdbplugin.UpdateUserResponse{}, err
	}

	// This also results in an no-op if the expiration is updated due to renewal.
	return newdbplugin.UpdateUserResponse{}, nil
}

func (m *MongoDBAtlas) changePassword(ctx context.Context, username, password string) error {
	m.Lock()
	defer m.Unlock()

	client, err := m.getConnection(ctx)
	if err != nil {
		return err
	}

	databaseUserRequest := &mongodbatlas.DatabaseUser{
		Password: password,
	}

	_, _, err = client.DatabaseUsers.Update(context.Background(), m.ProjectID, username, databaseUserRequest)
	if err != nil {
		return err
	}

	return nil
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
