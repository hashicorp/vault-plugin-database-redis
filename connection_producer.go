package redis

import (
	"context"
	"crypto/x509"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"time"
	
	"github.com/mediocregopher/radix/v3"
	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
)

type redisDBConnectionProducer struct {
	PublicKey   string `json:"public_key"`
	PrivateKey  string `json:"private_key"`
	ProjectID   string `json:"project_id"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Cluster     string `json:"cluster"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	CaCrt       string `json:"cacrt"`
	Persistence string `json:"persistence_mode"`

	Initialized bool
	rawConfig   map[string]interface{}
	Type        string
	client      radix.Client
	Connected   bool
	Addr        string
	sync.Mutex
}

func (c *redisDBConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password: "[password]",
		c.Username: "[username]",
	}
}

func (c *redisDBConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {

	c.Lock()
	defer c.Unlock()

	c.rawConfig = initConfig

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "json",
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(initConfig)
	if err != nil {
		return nil, err
	}

	switch {
	case len(c.Host) == 0 && len(c.Cluster) == 0:
		return nil, fmt.Errorf("cluster and host cannot be empty")
	case len(c.Cluster) == 0 && c.Port == 0:
		return nil, fmt.Errorf("port cannot be empty")
	case len(c.Username) == 0:
		return nil, fmt.Errorf("username cannot be empty")
	case len(c.Password) == 0:
		return nil, fmt.Errorf("password cannot be empty")
	}

	c.Addr = fmt.Sprintf("%s:%d", c.Host, c.Port)
	
	c.Initialized = true
	c.Connected = false

	if len(c.Persistence) != 0 {
		c.Persistence = strings.ToUpper(c.Persistence)
		if c.Persistence != "REWRITE" && "ACLFILE" != c.Persistence {
			return nil, fmt.Errorf("persistence_mode can only be 'REWRITE' or 'ACLFILE', not %s", c.Persistence)
		}
	}

	if c.TLS {
                if len(c.CaCrt) == 0 {
                        return nil, fmt.Errorf("cacrt cannot be empty")
                }
	}
	
	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, errwrap.Wrapf("error verifying connection: {{err}}", err)
		}
	}

	return initConfig, nil
}

func (c *redisDBConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}
func (c *redisDBConnectionProducer) Connection(ctx context.Context) (radix.Client, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.Connected == true {
		return c.client, nil
	}
	var err error
	var pem []byte
	var customConnFunc radix.ConnFunc
	
	if c.TLS {
                pem, err = base64.StdEncoding.DecodeString(c.CaCrt)
                if err != nil {
                        return nil, errwrap.Wrapf("error decoding CaCrt: {{err}}", err)
                }
                rootCAs := x509.NewCertPool()
                ok := rootCAs.AppendCertsFromPEM([]byte(pem))
                if !ok {
                        return nil, fmt.Errorf("failed to parse root certificate")
                }
		customConnFunc = func(network, addr string) (radix.Conn, error) {
			return radix.Dial(network, addr,
				radix.DialTimeout(1 * time.Minute),
				radix.DialAuthUser(c.Username, c.Password),
				radix.DialUseTLS(&tls.Config{
					RootCAs: rootCAs,
					InsecureSkipVerify: true,
				}),
			)
                }
        } else {

		customConnFunc = func(network, addr string) (radix.Conn, error) {
			return radix.Dial(network, addr,
				radix.DialTimeout(1 * time.Minute),
				radix.DialAuthUser(c.Username, c.Password),
			)
		}
	}

	poolFunc := func(network, addr string) (radix.Client, error) {
		return radix.NewPool(network, addr, 1, radix.PoolConnFunc(customConnFunc))
	}

	if len(c.Cluster) != 0 {
		hosts := strings.Split(c.Cluster, ",")
		c.client, err =  radix.NewCluster(hosts, radix.ClusterPoolFunc(poolFunc))
		if err != nil {
			return nil, errwrap.Wrapf(fmt.Sprintf("error in Cluster connection %v: {{err}}", hosts), err)
		}
	} else {
		c.client, err = radix.NewPool("tcp", c.Addr, 1, radix.PoolConnFunc(customConnFunc)) // [TODO] poolopts for timeout from ctx??
		if err != nil {
			return nil, errwrap.Wrapf("error in pool Connection: {{err}}", err)
		}
	}
	c.Connected = true
	return c.client, nil
}

// close terminates the database connection without locking
func (c *redisDBConnectionProducer) close() error {
	if c.Connected == true {
		if err := c.client.Close(); err != nil {
			return err
		}
	}

	c.Connected = false
	return nil
}

// Close terminates the database connection with locking
func (c *redisDBConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	return c.close()
}

// Handle connecting to REDIS node or cluster
func getRedisClient(cluster, hostname string, port int, useTls bool, caCrt, username, password string) (client radix.Client, err error) {
	var customConnFunc radix.ConnFunc
	
	if useTls {
                pem, err := base64.StdEncoding.DecodeString(caCrt)
                if err != nil {
                        return nil, errwrap.Wrapf("error decoding CaCrt: {{err}}", err)
                }
                rootCAs := x509.NewCertPool()
                ok := rootCAs.AppendCertsFromPEM([]byte(pem))
                if !ok {
                        return nil, fmt.Errorf("failed to parse root certificate")
                }
		customConnFunc = func(network, addr string) (radix.Conn, error) {
			return radix.Dial(network, addr,
				radix.DialTimeout(1 * time.Minute),
				radix.DialAuthUser(username, password),
				radix.DialUseTLS(&tls.Config{
					RootCAs: rootCAs,
					InsecureSkipVerify: true,
				}),
			)
                }
        } else {

		customConnFunc = func(network, addr string) (radix.Conn, error) {
			return radix.Dial(network, addr,
				radix.DialTimeout(1 * time.Minute),
				radix.DialAuthUser(username, password),
			)
		}
	}

	poolFunc := func(network, addr string) (radix.Client, error) {
		return radix.NewPool(network, addr, 1, radix.PoolConnFunc(customConnFunc))
	}

	if len(cluster) != 0 {
		hosts := strings.Split(cluster, ",")
		client, err =  radix.NewCluster(hosts, radix.ClusterPoolFunc(poolFunc))
		if err != nil {
			return nil, errwrap.Wrapf(fmt.Sprintf("error in Cluster connection %v: {{err}}", hosts), err)
		}
	} else {
		addr := fmt.Sprintf("%s:%d", hostname, port)
		client, err = radix.NewPool("tcp", addr, 1, radix.PoolConnFunc(customConnFunc)) // [TODO] poolopts for timeout from ctx??
		if err != nil {
			return nil, errwrap.Wrapf("error in pool Connection: {{err}}", err)
		}
	}
	return client, nil
}
