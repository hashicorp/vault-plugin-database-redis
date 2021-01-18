package redis

import (
	"context"
	"fmt"
	"os"
	"strings"
	"strconv"
	"testing"
	"time"

	//	"github.com/cenkalti/backoff"
	"github.com/mediocregopher/radix/v3"
	dbplugin "github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/ory/dockertest"
	dc "github.com/ory/dockertest/docker"
)

const (
	adminUsername = "Administrator"
	adminPassword = "password"
	aclCat        = "+@admin"
)

var redis_tls = false

func prepareRedisTestContainer(t *testing.T) (func(), string, int) {
	if os.Getenv("REDIS_TLS") != "" {
		redis_tls = true
	}
	if os.Getenv("REDIS_CLUSTER") != "" {
		return func() {}, os.Getenv("REDIS_CLUSTER"), -1
		}
	if os.Getenv("REDIS_HOST") != "" {
		if os.Getenv("REDIS_PORT") != "" {
			p, err := strconv.Atoi(os.Getenv("REDIS_PORT"))
			if err != nil {
				t.Fatalf("Failed to parse REDIS_PORT: %s", err)
			}
			return func() {}, os.Getenv("REDIS_HOST"), p
		}
		return func() {}, os.Getenv("REDIS_HOST"), 6379
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
		_, err := radix.NewPool("tcp", address, 1) 
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
	// Spin up redis
	cleanup, host, port := prepareRedisTestContainer(t)

	defer cleanup()

	err := createUser(host, port, redis_tls, caCrt, "default", "", "Administrator", "password",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create Administrator user using 'default' user: %s", err)
	}
	err = createUser(host, port, redis_tls, caCrt, adminUsername, adminPassword, "rotate-root", "rotate-rootpassword",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create rotate-root test user: %s", err)
	}
	err = createUser(host, port, redis_tls, caCrt, adminUsername, adminPassword, "vault-edu", "password",
		aclCat)
	if err != nil {
		t.Fatalf("Failed to create vault-edu test user: %s", err)
	}

	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_NoTLS(t, host, port) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_persistence(t, host, port) })
	t.Run("Init", func(t *testing.T) { testRedisDBInitialize_TLS(t, host, port) })

	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_DefaultRule(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_plusRole(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreateUser_persist(t, host, port) })
	t.Run("Create/Revoke", func(t *testing.T) { testRedisDBCreate_persistConfig(t, host, port) })
	t.Run("Rotate", func(t *testing.T) { testRedisDBRotateRootCredentials(t, host, port) })
	t.Run("Creds", func(t *testing.T) { testRedisDBSetCredentials(t, host, port) })
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

func testRedisDBInitialize_NoTLS(t *testing.T, host string, port int) {
	if redis_tls {
		t.Skip("skipping test in TLS mode")
	}
	
	t.Log("Testing plain text Init()")

	var cluster_hosts string;

	if port == -1 {
		cluster_hosts = host
		host = ""
	}


	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
	}
	err := setupRedisDBInitialize(t, connectionDetails)

	if err != nil {
		t.Fatalf("Testing Init() failed: error: %s", err)
	}

}
func testRedisDBInitialize_TLS(t *testing.T, host string, port int) {
	if !redis_tls {
		t.Skip("skipping test in plain text mode")
	}

	t.Log("Testing TLS Init()")

	var cluster_hosts string;

	if port == -1 {
		cluster_hosts = host
		host = ""
	}


	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
		"tls":      true,
		"cacrt":    caCrt,
	}
	err := setupRedisDBInitialize(t, connectionDetails)

	if err != nil {
		t.Fatalf("Testing TLS Init() failed: error: %s", err)
	}

}
func testRedisDBInitialize_persistence(t *testing.T, host string, port int) {
	if redis_tls {
		t.Skip("skipping test in TLS mode")
	}

	t.Log("Testing plain text Init() with persistence_mode")

	var cluster_hosts string;

	if port == -1 {
		cluster_hosts = host
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
		"persistence_mode": "garbage",
	}
	
	err := setupRedisDBInitialize(t, connectionDetails)

	if err == nil {
		t.Fatalf("Testing Init() should have failed as the perstence_mode is garbage.")
	}
	
	connectionDetails = map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
		"persistence_mode": "rewrite",
	}
	
	err = setupRedisDBInitialize(t, connectionDetails)

	if err != nil {
		t.Fatalf("Testing Init() with perstence_mode rewrite failed: %s.", err)
	}
	
	connectionDetails = map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
		"persistence_mode": "aclfile",
	}
	
	err = setupRedisDBInitialize(t, connectionDetails)

	if err != nil {
		t.Fatalf("Testing Init() with perstence_mode is aclfile failed: %s", err)
	}

}
func testRedisDBCreateUser(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser()")

	var cluster_hosts string;
	host := address
	rule := ""

	if port == -1 {
		cluster_hosts = address
		host = ""
		rule = `["+cluster"]`
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
			Commands: []string{rule},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

func checkCredsExist(t *testing.T, username, password, address string, port int) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing checkCredsExist()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": username,
		"password": password,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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

func checkRuleAllowed(t *testing.T, username, password, address string, port int, cmd string, rules []string) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing checkRuleAllowed()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": username,
		"password": password,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
	err = db.client.Do(radix.Cmd(&response, cmd, rules...))

	return err
}

func revokeUser(t *testing.T, username, address string, port int) error {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing RevokeUser()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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

func testRedisDBCreateUser_DefaultRule(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser_DefaultRule()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
			Commands: []string{`["~foo", "+@read", "+cluster"]`},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}
	rules := []string{"foo"}
	if err := checkRuleAllowed(t, userResp.Username, password, address, port, "get", rules); err != nil {
		t.Fatalf("get failed for user %s with +@read rule: %s", userResp.Username, err)
	}

	rules = []string{"foo", "bar"}
	if err = checkRuleAllowed(t, userResp.Username, password, address, port, "set", rules); err == nil {
		t.Fatalf("set did not fail with +@read rule: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", username)
	}

	db.Close()
}

func testRedisDBCreateUser_plusRole(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing CreateUser_plusRole()")

	var cluster_hosts string;
	host := address

	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":             host,
		"port":             port,
		"cluster":          cluster_hosts,
		"username":         adminUsername,
		"password":         adminPassword,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
			Commands: []string{fmt.Sprintf(testRedisRole, aclCat)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}

// g1 & g2 must exist in the database.
func testRedisDBCreateUser_persist(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	t.Log("Testing CreateUser_persist()")

	connectionDetails := map[string]interface{}{
		"host":             host,
		"port":             port,
		"cluster":          cluster_hosts,
		"username":         adminUsername,
		"password":         adminPassword,
		"persistence_mode": "aclfile",
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}
func testRedisDBCreate_persistConfig(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	var cluster_hosts string;
	host := address

	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	t.Log("Testing Create_persistConfig()")

	connectionDetails := map[string]interface{}{
		"host":             host,
		"port":             port,
		"cluster":          cluster_hosts,
		"username":         adminUsername,
		"password":         adminPassword,
		"persistence_mode": "REWRITE",
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
			Commands: []string{fmt.Sprintf(testRedisRoleAndGroup, aclCat)},
		},
		Password:   password,
		Expiration: time.Now().Add(time.Minute),
	}

	userResp, err := db.NewUser(context.Background(), createReq)
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	db.Close()

	if err := checkCredsExist(t, userResp.Username, password, address, port); err != nil {
		t.Fatalf("Could not connect with new credentials: %s", err)
	}

	err = revokeUser(t, userResp.Username, address, port)
	if err != nil {
		t.Fatalf("Could not revoke user: %s", userResp.Username)
	}
}
func testRedisDBRotateRootCredentials(t *testing.T, address string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}
	t.Log("Testing RotateRootCredentials()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": "rotate-root",
		"password": "rotate-rootpassword",
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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
	defer doRedisDBSetCredentials(t, "rotate-root", "rotate-rootpassword", address, port)

	if err := checkCredsExist(t, db.Username, "newpassword", address, port); err != nil {
		t.Fatalf("Could not connect with new RotatedRootcredentials: %s", err)
	}
}

func doRedisDBSetCredentials(t *testing.T, username, password, address string, port int) {

	t.Log("Testing SetCredentials()")

	var cluster_hosts string;
	host := address
	
	if port == -1 {
		cluster_hosts = address
		host = ""
	}

	connectionDetails := map[string]interface{}{
		"host":     host,
		"port":     port,
		"cluster":  cluster_hosts,
		"username": adminUsername,
		"password": adminPassword,
	}

	if redis_tls {
		connectionDetails["tls"] = true
		connectionDetails["cacrt"] = caCrt
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

	if err := checkCredsExist(t, username, password, address, port); err != nil {
		t.Fatalf("Could not connect with rotated credentials: %s", err)
	}
}

func testRedisDBSetCredentials(t *testing.T, host string, port int) {
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	doRedisDBSetCredentials(t, "vault-edu", "password", host, port)
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

const testRedisRole = `["%s"]`
const testRedisGroup = `["+@all"]`
const testRedisRoleAndGroup = `["%s"]`
const caCrt = "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURMRENDQWhTZ0F3SUJBZ0lVZWlJdWtVYUJmWkx3V3VGbkVUdm5ITG5oeUJZd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0V6RVJNQThHQTFVRUF4TUliWGt0Y21Wa2FYTXdIaGNOTWpFd01URTBNVGt4TnpBM1doY05Nakl3TVRFMApNVGt4TnpNMldqQVRNUkV3RHdZRFZRUURFd2h0ZVMxeVpXUnBjekNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFECmdnRVBBRENDQVFvQ2dnRUJBTGV4QUsvZVF0c0M5bW1yQU81U0t5NHV4cU5YMUJ5eTFybTJvODBna0NRTUFiK0sKVk9tUDN0bEtnRlI3YmZCcEF0Z3hUMTdlWXhxQkRNeTdVY3lxdVIrSXdNaTJPT0tJWjdIZ3J2QzI4WHdLdDZ6RAptVXk0OUJSOFREQmU1QTI3ZnpwajUxbnN5a09aNkNpMGlXZldwaDUvR0FNQ1JibjVTdWRMKy9OcnFCL1Q4bElCCmNmUktVejFVN0VWdWY1MkYyVHU0UlU4R054dGpUdllub2dmQkM2bXJjR3UxblVYNWprOTkwcFpid05aUmpMTHkKTnpSblZPY2swVjE5TTMrSEtnbGYzWFZNLzJiUWczaGxnZ0EvTEFOWlBtUVgxN3hMSGlka05IbFNVRWpTTUUvdgpzeVEwc201dUxKdG56WUxXdXhLNkdSVG5pWmNmWjZodXIwbWM3OTBDQXdFQUFhTjRNSFl3RGdZRFZSMFBBUUgvCkJBUURBZ0VHTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SFFZRFZSME9CQllFRk5ueUdFdmZCS3lTS1RQaW1wMDUKSVVXaktRbHBNQjhHQTFVZEl3UVlNQmFBRk5ueUdFdmZCS3lTS1RQaW1wMDVJVVdqS1FscE1CTUdBMVVkRVFRTQpNQXFDQ0cxNUxYSmxaR2x6TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFDd1RoRmlDcWpPTXNEYmYxTExCRDF2CnlCUE5zZzBxdzlLeEVFY2hleldrcUgrWlBIVTIvV3Y2TklETTV0MnZNOUhnUUVHRnlubGEwb3Z2dkE3U2tselEKY0hINVVHdVk0UFpnb1NLTjAxRDNCTkJObHB4b3h0b0VSQXFpMWhzRVlYb2VmcnArdEtkNHlzdTJ5cWFGWnNwNwpwenlJMTNSWVE4b1czUWZpeVovUzlEcittdWJhQnZHRE5PZ3k3K05HajNWdjBKRW51cTZGNTlQc2VhZWZ5QWRHCmlWSExqQjlDRVV6Z0t4Nk1NQWZTbXBjUVo3RnhTcDNzaE9haUp0QkZkZWk0WTBnNHp3Q3U4S1NqVDdJOGdPOVkKbEZTVVZCSzZpeG1FOFFzay9vcXN0bDl5L3E1UkFRNHpIbFI0b3c2c3VEdm52SFJzcWtjME52UXNpbTlhL1lmYwotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t"
