// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/mediocregopher/radix/v4"
	"github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
)

const (
	defaultUsername  = "default"
	defaultPassword  = "default-pa55w0rd"
	adminUsername    = "Administrator"
	adminPassword    = "password"
	sentinelUsername = defaultUsername
	sentinelPassword = defaultPassword
	aclCat           = "+@admin"
	testRedisRole    = `["%s"]`
	testRedisGroup   = `["+@all"]`
	testRedisRole3   = `["%s", "%s", "%s"]`
)

var (
	redisTls                   = false
	redis_host                 = ""
	redis_port                 = 0
	redis_secondaries          = ""
	redis_cluster_hosts        = ""
	redis_sentinel_hosts       = ""
	redis_sentinel_master_name = ""
	persistence_mode           = ""
)

func prepareRedisTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("TEST_REDIS_TLS") != "" {
		redisTls = true
	}
	if host := os.Getenv("TEST_REDIS_PRIMARY_HOST"); host != "" {
		redis_secondaries = os.Getenv("TEST_REDIS_SECONDARIES")
		port, err := strconv.Atoi(os.Getenv("TEST_REDIS_PRIMARY_PORT"))
		if err != nil {
			port = 6379
		}
		return func() {}, host, port
	}
	if env := os.Getenv("TEST_REDIS_CLUSTER"); env != "" {
		redis_cluster_hosts = env
		return func() {}, env, -1
	}

	if env := os.Getenv("TEST_REDIS_SENTINELS"); env != "" {
		redis_sentinel_hosts = env
		env = os.Getenv("TEST_REDIS_SENTINEL_MASTER_NAME")
		if env != "" {
			redis_sentinel_master_name = env
		}
		return func() {}, env, -2
	}

	// redver should match a redis repository tag. Default to latest.
	redver := os.Getenv("REDIS_VERSION")
	if redver == "" {
		redver = "latest"
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Failed to connect to docker: %s", err)
	}

	ro := &dockertest.RunOptions{
		Repository:   "docker.io/redis",
		Tag:          redver,
		ExposedPorts: []string{"6379"},
		PortBindings: map[dc.Port][]dc.PortBinding{
			"6379": {
				{HostIP: "0.0.0.0", HostPort: "6379"},
			},
		},
	}
	resource, err := pool.RunWithOptions(ro)
	if err != nil {
		t.Fatalf("Could not start local redis docker container: %s", err)
	}

	cleanup := func() {
		err := pool.Retry(func() error {
			return pool.Purge(resource)
		})
		if err != nil {
			if strings.Contains(err.Error(), "No such container") {
				return
			}
			t.Fatalf("Failed to cleanup local container: %s", err)
		}
	}

	address := "127.0.0.1:6379"

	if err = pool.Retry(func() error {
		t.Log("Waiting for the database to start...")
		poolConfig := radix.PoolConfig{}
		_, err := poolConfig.New(context.Background(), "tcp", address)
		if err != nil {
			return err
		}

		return nil
	}); err != nil {
		t.Fatalf("Could not connect to redis: %s", err)
		cleanup()
	}
	time.Sleep(3 * time.Second)
	return cleanup, "0.0.0.0", 6379
}

func TestDriver(t *testing.T) {
	var err error
	var cleanup func()

	if os.Getenv("TEST_REDIS_TLS") != "" {
		caCertFile := os.Getenv("CA_CERT_FILE")
		_, err = os.ReadFile(caCertFile)
		if err != nil {
			t.Fatal(fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", caCertFile, err))
		}
	}

	// Spin up container Redis or process environment variables to connect to test Redis instances
	cleanup, redis_host, redis_port = prepareRedisTestContainer(t)
	defer cleanup()

	err, persistence_mode = checkPersistenceMode(defaultUsername, defaultPassword)
	if err != nil {
		t.Log("Check for ACLSAVE persistence mode did not pass.")
		persistence_mode = "None"
	}

	err = createUser(defaultUsername, defaultPassword, "Administrator", "password", aclCat)
	if err != nil {
		t.Fatalf("Failed to create Administrator user using 'default' user: %s", err)
	}
	err = createUser(adminUsername, adminPassword, "rotate-root", "rotate-rootpassword", aclCat)
	if err != nil {
		t.Fatalf("Failed to create rotate-root test user: %s", err)
	}
	err = createUser(adminUsername, adminPassword, "vault-edu", "password", aclCat)
	if err != nil {
		t.Fatalf("Failed to create vault-edu test user: %s", err)
	}

	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_NoTLS(t) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_persistence(t) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_TLS(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_DefaultRule(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_plusRole(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_groupOnly(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_roleAndSelector(t) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_persistAclFile(t) })
	// t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreate_persistConfig(t, host, port) })
	t.Run("Rotate", func(t *testing.T) { testRedisDBRotateRootCredentials(t) })
	t.Run("Creds", func(t *testing.T) { testRedisDBSetCredentials(t) })
	t.Run("Secret", func(t *testing.T) { testConnectionProducerSecretValues(t) })
	t.Run("TimeoutCalc", func(t *testing.T) { testComputeTimeout(t) })
}

func setupRedisDBInitialize(t *testing.T, connectionDetails map[string]interface{}) (err error) {
	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err = db.Initialize(context.Background(), initReq)
	if err != nil {
		return err
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	err = db.Close()
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testRedisDBInitialize_NoTLS(t *testing.T) {
	if redisTls {
		t.Skip("skipping plain text Init() test in TLS mode")
	}

	t.Log("Testing plain text Init()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	err := setupRedisDBInitialize(t, connectionDetails)
	if err != nil {
		t.Fatalf("Testing Init() failed: error: %s", err)
	}
}

func testRedisDBInitialize_TLS(t *testing.T) {
	if !redisTls {
		t.Skip("skipping TLS Init() test in plain text mode")
	}

	t.Log("Testing TLS Init()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}
	err := setupRedisDBInitialize(t, connectionDetails)
	if err != nil {
		t.Fatalf("Testing TLS Init() failed: error: %s", err)
	}
}

func testRedisDBInitialize_persistence(t *testing.T) {
	if redisTls {
		t.Skip("skipping plain text Init() with persistence_mode test in TLS mode")
	}

	t.Log("Testing plain text Init() with persistence_mode")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "garbage")

	err := setupRedisDBInitialize(t, connectionDetails)

	if err == nil {
		t.Fatalf("Testing Init() should have failed as the perstence_mode is garbage.")
	}

	connectionDetails = make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "rewrite")

	err = setupRedisDBInitialize(t, connectionDetails)
	if err != nil {
		t.Fatalf("Testing Init() with perstence_mode rewrite failed: %s.", err)
	}

	connectionDetails = make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "aclfile")

	err = setupRedisDBInitialize(t, connectionDetails)

	if persistence_mode == "None" && err == nil {
		t.Fatalf("Testing Init() with persistence_node detected as \"None\" should have failed but did not.")
	}

	if err != nil && persistence_mode == "ACLFILE" {
		t.Fatalf("Testing Init() with perstence_mode aclfile failed: %s", err)
	}
}

func testRedisDBCreateUser(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser()")

	var rule []string
	// if it is a cluster then these two rules are needed for the user to be able to connect.
	if len(redis_cluster_hosts) != 0 {
		rule = []string{`["+readonly", "+cluster"]`}
	}

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("Failed to initialize database: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: rule,
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func checkCredsExist(t *testing.T, username, password string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing checkCredsExist()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, username, password, "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()

	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	return nil
}

func checkRuleAllowed(t *testing.T, username, password, cmd string, rules []string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing checkRuleAllowed()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, username, password, "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}
	var response string
	err = db.client.Do(context.Background(), radix.Cmd(&response, cmd, rules...))
	if err != nil {
		return fmt.Errorf("Response in checkRules for %s %w", response, err)
	}

	return err
}

func revokeUser(t *testing.T, username string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing RevokeUser()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	delUserReq := dbplugin.DeleteUserRequest{Username: username}

	_, err = db.DeleteUser(context.Background(), delUserReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}
	return nil
}

func testRedisDBCreateUser_DefaultRule(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser_DefaultRule()")

	var rules []string
	// cluster user needs additional permissions.
	if len(redis_cluster_hosts) != 0 {
		rules = []string{`["~foo", "+@read", "+readonly", "+cluster"]`}
	} else {
		rules = []string{`["~foo", "+@read"]`}
	}

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	username := "test"
	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: username,
			RoleName:    username,
		},
		Statements: dbplugin.Statements{
			Commands: rules,
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute * 5),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}
	params := []string{"foo"}
	if err := checkRuleAllowed(t, userResp.Username, password, "get", params); err != nil {
		t.Fatalf("get failed for user %s with +@read rule: %s", userResp.Username, err)
	}

	params = []string{"foo", "bar"}
	if err = checkRuleAllowed(t, userResp.Username, password, "set", params); err == nil {
		t.Fatalf("set did not fail user %s with +@read rule: %s", userResp.Username, err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}

	db.Close()
}

func testRedisDBCreateUser_plusRole(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser_plusRole()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisRole, "+@all")},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

/* [TODO] groupOnly hang over from Couchbase */
func testRedisDBCreateUser_groupOnly(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisGroup)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func testRedisDBCreateUser_roleAndSelector(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing CreateUser() with selector rule")

	var rules []string
	// cluster user needs additional permissions.
	if len(redis_cluster_hosts) != 0 {
		rules = []string{`["+GET", "allkeys", "(+SET ~app1*)", "+readonly", "+cluster"]`}
	} else {
		rules = []string{`["+GET", "allkeys", "(+SET ~app1*)"]`}
	}

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: rules,
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func testRedisDBCreateUser_persistAclFile(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	if persistence_mode == "None" {
		t.Skip("Skipping persist config as this REDIS installation is not configured to use an acl file.")
	}

	t.Log("Testing CreateUser_persist()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "aclfile")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	password := "y8fva_sdVA3rasf"

	createReq := dbplugin.NewUserRequest{
		UsernameConfig: dbplugin.UsernameMetadata{
			DisplayName: "test",
			RoleName:    "test",
		},
		Statements: dbplugin.Statements{
			Commands: []string{fmt.Sprintf(testRedisGroup)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func testRedisDBRotateRootCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	t.Log("Testing RotateRootCredentials()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "rotate-root", "rotate-rootpassword", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	defer db.Close()

	updateReq := dbplugin.UpdateUserRequest{
		Username: "rotate-root",
		Password: &dbplugin.ChangePassword{
			NewPassword: "newpassword",
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	// defer setting the password back in case the test fails.
	defer doRedisDBSetCredentials(t, "rotate-root", "rotate-rootpassword")

	if err := checkCredsExist(t, db.Username, "newpassword"); err != nil {
		t.Fatalf("Could not connect with new RotatedRootcredentials: %s", err)
	}
}

func doRedisDBSetCredentials(t *testing.T, username, password string) {
	t.Log("Testing SetCredentials()")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, "", "", "")

	if err := setupCertificates(&connectionDetails); err != nil {
		t.Fatal(fmt.Errorf("Issue encounted processing X509 inputs: %w", err))
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err := db.Initialize(context.Background(), initReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if !db.Initialized {
		t.Fatal("Database should be initialized")
	}

	// test that SetCredentials fails if the user does not exist...
	updateReq := dbplugin.UpdateUserRequest{
		Username: "userThatDoesNotExist",
		Password: &dbplugin.ChangePassword{
			NewPassword: "goodPassword",
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5000*time.Millisecond)
	defer cancel()
	_, err = db.UpdateUser(ctx, updateReq)
	if err == nil {
		t.Fatalf("err: did not error on setting password for userThatDoesNotExist")
	}

	updateReq = dbplugin.UpdateUserRequest{
		Username: username,
		Password: &dbplugin.ChangePassword{
			NewPassword: password,
		},
	}

	_, err = db.UpdateUser(context.Background(), updateReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, username, password); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func testRedisDBSetCredentials(t *testing.T) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	doRedisDBSetCredentials(t, "vault-edu", "password")
}

func testConnectionProducerSecretValues(t *testing.T) {
	t.Log("Testing redisDBConnectionProducer.secretValues()")

	cp := &redisDBConnectionProducer{
		Username: "USR",
		Password: "PWD",
	}

	if cp.secretValues()["USR"] != "[username]" &&
		cp.secretValues()["PWD"] != "[password]" {
		t.Fatal("redisDBConnectionProducer.secretValues() test failed.")
	}
}

func testComputeTimeout(t *testing.T) {
	t.Log("Testing computeTimeout")
	if computeTimeout(context.Background()) != defaultTimeout {
		t.Fatalf("Background timeout not set to %s milliseconds.", defaultTimeout)
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	defer cancel()
	if computeTimeout(ctx) == defaultTimeout {
		t.Fatal("WithTimeout failed")
	}
}

func checkPersistenceMode(adminUsername, adminPassword string) (err error, mode string) {
	fmt.Printf("Checking the supported persistence mode.\n")

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, adminUsername, adminPassword, "")

	if err := setupCertificates(&connectionDetails); err != nil {
		return fmt.Errorf("Issue encounted processing X509 inputs: %w", err), ""
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: false, // false as we don't want the built in persistence check
	}

	db := new()
	_, err = db.Initialize(context.Background(), initReq)
	if err != nil {
		return fmt.Errorf("Failed to initialize database: %s", err), ""
	}

	if !db.Initialized {
		return fmt.Errorf("Database should be initialized"), ""
	}

	ctx, _ := context.WithTimeout(context.Background(), 5000*time.Millisecond)

	client, err := db.getConnection(ctx)
	if err != nil {
		return err, ""
	}

	err = checkPersistence(ctx, client.(radix.MultiClient))

	db.Close()

	if err == nil {
		return nil, "ACLFILE"
	}
	return err, ""
}

func createUser(adminUsername, adminPassword, username, password, aclRule string) (err error) {
	fmt.Printf("Creating test user %s\n", username)

	var cluster_rules []string
	// extra rules needed to access cluster information
	if len(redis_cluster_hosts) != 0 {
		cluster_rules = []string{"+readonly", "+cluster"}
	}

	connectionDetails := make(map[string]interface{})

	setupParameters(&connectionDetails, adminUsername, adminPassword, "")

	if err := setupCertificates(&connectionDetails); err != nil {
		return fmt.Errorf("Issue encounted processing X509 inputs: %w", err)
	}

	initReq := dbplugin.InitializeRequest{
		Config:           connectionDetails,
		VerifyConnection: true,
	}

	db := new()
	_, err = db.Initialize(context.Background(), initReq)
	if err != nil {
		return fmt.Errorf("Failed to initialize database: %s", err)
	}

	if !db.Initialized {
		return fmt.Errorf("Database should be initialized")
	}

	// setup REDIS command
	aclargs := []string{"SETUSER", username, "ON", ">" + password, aclRule}
	aclargs = append(aclargs, cluster_rules...)

	var response string
	var replicaSets map[string]radix.ReplicaSet
	var connType string

	connType, replicaSets, err = getReplicaSets(db.client)

	if err != nil {
		return fmt.Errorf("retrieving %s clients failed error: %w", connType, err)
	}

	ctx, _ := context.WithTimeout(context.Background(), 5000*time.Millisecond)

	for node, rs := range replicaSets {
		for _, v := range getClientsFromRS(rs) {

			err = v.Do(ctx, radix.Cmd(&response, "ACL", aclargs...))
			if err != nil {
				return fmt.Errorf("Response in %s newUser: %s for node %s, error: %w", connType, node, response, err)
			}
		}
	}

	return nil
}

func setupParameters(connectionDetails *map[string]interface{}, username, password, pmode string) {
	(*connectionDetails)["primary_host"] = redis_host
	(*connectionDetails)["primary_port"] = redis_port
	(*connectionDetails)["secondaries"] = redis_secondaries
	(*connectionDetails)["cluster"] = redis_cluster_hosts
	(*connectionDetails)["sentinels"] = redis_sentinel_hosts
	(*connectionDetails)["sentinel_master_name"] = redis_sentinel_master_name
	if len(username) == 0 {
		(*connectionDetails)["username"] = adminUsername
	} else {
		(*connectionDetails)["username"] = username
	}
	if len(password) == 0 {
		(*connectionDetails)["password"] = adminPassword
	} else {
		(*connectionDetails)["password"] = password
	}
	(*connectionDetails)["sentinel_username"] = sentinelUsername
	(*connectionDetails)["sentinel_password"] = sentinelPassword
	if len(pmode) != 0 {
		(*connectionDetails)["persistence_mode"] = pmode
	}
}

func setupCertificates(connectionDetails *map[string]interface{}) (err error) {
	if !redisTls {
		return nil
	}

	var TLSCert, TLSKey []byte

	CACertFile := os.Getenv("CA_CERT_FILE")
	CACert, err := os.ReadFile(CACertFile)
	if err != nil {
		return fmt.Errorf("unable to read CA_CERT_FILE at %v: %w", CACertFile, err)
	}

	TLSCertFile := os.Getenv("TLS_CERT_FILE")
	if TLSCertFile != "" {
		TLSCert, err = os.ReadFile(TLSCertFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS_CERT_FILE at %v: %w", TLSCertFile, err)
		}
	}
	TLSKeyFile := os.Getenv("TLS_KEY_FILE")
	if TLSKeyFile != "" {
		TLSKey, err = os.ReadFile(TLSKeyFile)
		if err != nil {
			return fmt.Errorf("unable to read TLS_KEY_FILE at %v: %w", TLSKeyFile, err)
		}
	}

	if (len(TLSCert) != 0 && len(TLSKey) == 0) ||
		(len(TLSCert) == 0 && len(TLSKey) != 0) {
		return fmt.Errorf("For mutual TLS both tls_cert and tls_key parameter must be set")
	}
	(*connectionDetails)["tls"] = true
	(*connectionDetails)["ca_cert"] = CACert
	(*connectionDetails)["insecure_tls"] = false
	(*connectionDetails)["tls_cert"] = TLSCert
	(*connectionDetails)["tls_key"] = TLSKey

	return nil
}
