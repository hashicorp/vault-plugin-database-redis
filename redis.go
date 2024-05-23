// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/errwrap"
	hclog "github.com/hashicorp/go-hclog"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/mediocregopher/radix/v4"
	"github.com/mediocregopher/radix/v4/resp/resp3"
)

const (
	redisTypeName        = "redis"
	defaultRedisUserRule = `["~*", "+@read"]`
	defaultTimeout       = 20000 * time.Millisecond
	maxKeyLength         = 64
)

var _ dbplugin.Database = &RedisDB{}

// Type that combines the custom plugins Redis database connection configuration options and the Vault CredentialsProducer
// used for generating user information for the Redis database.
type RedisDB struct {
	*redisDBConnectionProducer
	credsutil.CredentialsProducer
}

// New implements builtinplugins.BuiltinFactory
func New() (interface{}, error) {
	db := new()
	// Wrap the plugin with middleware to sanitize errors
	dbType := dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.secretValues)
	return dbType, nil
}

func new() *RedisDB {
	connProducer := &redisDBConnectionProducer{}
	connProducer.Type = redisTypeName

	db := &RedisDB{
		redisDBConnectionProducer: connProducer,
	}

	return db
}

func (c *RedisDB) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	err := c.redisDBConnectionProducer.Initialize(ctx, req.Config, req.VerifyConnection)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}
	resp := dbplugin.InitializeResponse{
		Config: req.Config,
	}
	return resp, nil
}

func (c *RedisDB) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	// Grab the lock
	c.Lock()
	defer c.Unlock()

	username, err := credsutil.GenerateUsername(
		credsutil.DisplayName(req.UsernameConfig.DisplayName, maxKeyLength),
		credsutil.RoleName(req.UsernameConfig.RoleName, maxKeyLength))
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to generate username: %w", err)
	}
	username = strings.ToUpper(username)

	db, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to get connection: %w", err)
	}

	err = newUser(ctx, db, username, c.getPersistenceMode(), req)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	resp := dbplugin.NewUserResponse{
		Username: username,
	}

	return resp, nil
}

func (c *RedisDB) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	if req.Password != nil {
		err := c.changeUserPassword(ctx, req.Username, req.Password.NewPassword)
		return dbplugin.UpdateUserResponse{}, err
	}
	return dbplugin.UpdateUserResponse{}, nil
}

func (c *RedisDB) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to make connection: %w", err)
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	var response string
	var replicaSets map[string]radix.ReplicaSet
	var connType string

	switch db.(type) {

	case *radix.Sentinel:
		replicaSets, err = db.(*radix.Sentinel).Clients()
		connType = "Sentinel"

	case radix.MultiClient:
		replicaSets, err = db.Clients()
		connType = "MultiClient"

	case *radix.Cluster:
		replicaSets, err = db.(*radix.Cluster).Clients()
		connType = "Cluster"
	}
	if err != nil {
		return dbplugin.DeleteUserResponse{}, errwrap.Wrapf(fmt.Sprintf("retrieving %s clients failed error: {{err}}", connType), err)
	}
	for node, rs := range replicaSets {
		for _, v := range getClientsFromRS(rs) {
			v.Do(ctx, radix.Cmd(&response, "ACL", "DELUSER", req.Username))
			if err != nil {
				return dbplugin.DeleteUserResponse{}, errwrap.Wrapf(fmt.Sprintf("response from %s node %s for DeleteUser: %s, error: {{err}}", connType, node, response), err)
			}
			err = persistChange(ctx, v, c.Persistence)
			if err != nil {
				return dbplugin.DeleteUserResponse{}, errwrap.Wrapf(fmt.Sprintf("error persisting DeleteUser on node %s: {{err}}", node), err)
			}

		}
	}
	return dbplugin.DeleteUserResponse{}, nil
}

func newUser(ctx context.Context, db radix.MultiClient, username, mode string, req dbplugin.NewUserRequest) error {
	statements := removeEmpty(req.Statements.Commands)

	if len(statements) == 0 {
		statements = append(statements, defaultRedisUserRule)
	}

	// setup REDIS command
	aclargs := []string{"SETUSER", username, "ON", ">" + req.Password}

	var args []string
	err := json.Unmarshal([]byte(statements[0]), &args)
	if err != nil {
		return errwrap.Wrapf("error unmarshalling REDIS rules in the creation statement JSON: {{err}}", err)
	}
	// append the additional rules/permissions
	aclargs = append(aclargs, args...)

	var response string
	var replicaSets map[string]radix.ReplicaSet
	var connType string

	switch db.(type) {

	case *radix.Sentinel:
		replicaSets, err = db.(*radix.Sentinel).Clients()
		connType = "Sentinel"

	case radix.MultiClient:
		replicaSets, err = db.Clients()
		connType = "MultiClient"

	case *radix.Cluster:
		replicaSets, err = db.(*radix.Cluster).Clients()
		connType = "Cluster"
	}
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("retrieving %s clients failed error: {{err}}", connType), err)
	}
	for node, rs := range replicaSets {
		for _, v := range getClientsFromRS(rs) {

			err = v.Do(ctx, radix.Cmd(&response, "ACL", aclargs...))
			if err != nil {
				return errwrap.Wrapf(fmt.Sprintf("Response in %s newUser: %s for node %s, error: {{err}}", connType, node, response), err)
			}
			err = persistChange(ctx, v, mode)
			if err != nil {
				return errwrap.Wrapf(fmt.Sprintf("persist error for node %s: {{err}}", node), err)
			}
		}
	}

	return nil
}

func (c *RedisDB) changeUserPassword(ctx context.Context, username, password string) error {
	c.Lock()
	defer c.Unlock()

	db, err := c.getConnection(ctx)
	if err != nil {
		return err
	}

	// Close the database connection to ensure no new connections come in
	defer func() {
		if err := c.close(); err != nil {
			logger := hclog.New(&hclog.LoggerOptions{})
			logger.Error("defer close failed", "error", err)
		}
	}()

	var response resp3.ArrayHeader
	mn := radix.Maybe{Rcv: &response}
	var redisErr resp3.SimpleError

	// check the user exists before attempting a password change
	var replicaSets map[string]radix.ReplicaSet
	var connType string

	switch db.(type) {

	case *radix.Sentinel:
		replicaSets, err = db.(*radix.Sentinel).Clients()
		connType = "Sentinel"

	case radix.MultiClient:
		replicaSets, err = db.Clients()
		connType = "MultiClient"

	case *radix.Cluster:
		replicaSets, err = db.(*radix.Cluster).Clients()
		connType = "Cluster"
	}
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("retrieving %s clients failed error: {{err}}", connType), err)
	}
	for node, rs := range replicaSets {
		for _, v := range getClientsFromRS(rs) {

			err = v.Do(ctx, radix.Cmd(&mn, "ACL", "GETUSER", username))
			if errors.As(err, &redisErr) {
				fmt.Printf("redis error returned: %s", redisErr.Error())
			}

			if err != nil {
				return fmt.Errorf("reset of passwords for user %s failed in changeUserPassword on cluster member %s: %w", username, node, err)
			}

			if mn.Null {
				return fmt.Errorf("changeUserPassword for user %s failed on cluster member %s, user not found!", node, username)
			}
		}
	}
	// go ahead an change the password
	var sresponse string

	switch db.(type) {

	case *radix.Sentinel:
		replicaSets, err = db.(*radix.Sentinel).Clients()
		connType = "Sentinel"

	case radix.MultiClient:
		replicaSets, err = db.Clients()
		connType = "MultiClient"

	case *radix.Cluster:
		replicaSets, err = db.(*radix.Cluster).Clients()
		connType = "Cluster"
	}
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("retrieving %s clients failed error: {{err}}", connType), err)
	}
	for node, rs := range replicaSets {
		for _, v := range getClientsFromRS(rs) {
			err = v.Do(ctx, radix.Cmd(&sresponse, "ACL", "SETUSER", username, "RESETPASS", ">"+password))
			if err != nil {
				return errwrap.Wrapf(fmt.Sprintf("cluster reset of password for user %s on node %s failed, REDIS response %s, error, {{err}}", username, node, sresponse), err)
			}
			err = persistChange(ctx, v, c.Persistence)
			if err != nil {
				return errwrap.Wrapf(fmt.Sprintf("error persisting password change on node %s: {{err}}", node), err)
			}
		}
	}

	return nil
}

func removeEmpty(strs []string) []string {
	var newStrs []string
	for _, str := range strs {
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		newStrs = append(newStrs, str)
	}

	return newStrs
}

func computeTimeout(ctx context.Context) (timeout time.Duration) {
	deadline, ok := ctx.Deadline()
	if ok {
		return time.Until(deadline)
	}
	return defaultTimeout
}

func (c *RedisDB) getConnection(ctx context.Context) (radix.MultiClient, error) {
	db, err := c.Connection(ctx)
	if err != nil {
		return nil, err
	}
	return db.(radix.MultiClient), nil
}

func (c *RedisDB) getPersistenceMode() string {
	return c.Persistence
}

func (c *RedisDB) Type() (string, error) {
	return redisTypeName, nil
}

func (c *RedisDB) Close() error {
	return nil
}

func persistChange(ctx context.Context, client radix.Client, pmode string) error {
	var response string
	var err error
	switch pmode {
	case "REWRITE":
		err = client.Do(ctx, radix.Cmd(&response, "CONFIG", "REWRITE"))
	case "ACLFILE":
		err = client.Do(ctx, radix.Cmd(&response, "ACL", "SAVE"))
	}
	if err != nil {
		return errwrap.Wrapf(fmt.Sprintf("error from persistChange() response: %s, error: {{err}}", response), err)
	}

	return nil
}

func getClientsFromRS(rs radix.ReplicaSet) []radix.Client {
	c := []radix.Client{}
	if rs.Primary != nil {
		c = append(c, rs.Primary)
	}
	for s := range rs.Secondaries {
		c = append(c, rs.Secondaries[s])
	}
	return c
}
