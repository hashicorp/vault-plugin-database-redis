// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mediocregopher/radix/v4"
	"github.com/mitchellh/mapstructure"
)

type redisDBConnectionProducer struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Secondaries string `json:"secondaries"`
	Cluster     string `json:"cluster"`
	Sentinels   string `json:"sentinels"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	CACert      string `json:"ca_cert"`
	Persistence string `json:"persistence_mode"`

	Initialized bool
	rawConfig   map[string]interface{}
	Type        string
	client      radix.MultiClient // radix.Client
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
	case len(c.Host) == 0 && len(c.Cluster) == 0 && len(c.Sentinels) == 0:
		return nil, fmt.Errorf("host, cluster and sentinels cannot be empty")
	case len(c.Cluster) == 0 && len(c.Sentinels) == 0 && c.Port == 0:
		return nil, fmt.Errorf("port cannot be empty")
	case len(c.Username) == 0:
		return nil, fmt.Errorf("username cannot be empty")
	case len(c.Password) == 0:
		return nil, fmt.Errorf("password cannot be empty")
	}

	c.Addr = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))

	if c.TLS {
		if len(c.CACert) == 0 {
			return nil, fmt.Errorf("ca_cert cannot be empty")
		}
	}

	// ??c.Connected = false

	if len(c.Persistence) != 0 {
		c.Persistence = strings.ToUpper(c.Persistence)
		if c.Persistence != "REWRITE" && "ACLFILE" != c.Persistence {
			return nil, fmt.Errorf("persistence_mode can only be 'REWRITE' or 'ACLFILE', not %s", c.Persistence)
		}
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			return nil, fmt.Errorf("error verifying connection with user %s: %w", c.Username, err)
		}
	}

	return initConfig, nil
}

func (c *redisDBConnectionProducer) Initialize(ctx context.Context, config map[string]interface{}, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}

func (c *redisDBConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it. (The locking patterns could be refactored to be more consistent/clear.)

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.client != nil {
		return c.client, nil
	}
	var err error
	var poolConfig radix.PoolConfig
	var clusterConfig radix.ClusterConfig

	if c.TLS {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(c.CACert))
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: c.Username,
				AuthPass: c.Password,
				NetDialer: &tls.Dialer{
					Config: &tls.Config{
						RootCAs:            rootCAs,
						InsecureSkipVerify: c.InsecureTLS,
					},
				},
			},
		}
	} else {
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: c.Username,
				AuthPass: c.Password,
			},
		}
	}

	if len(c.Cluster) != 0 {
		hosts := strings.Split(c.Cluster, ",")
		clusterConfig = radix.ClusterConfig{
			PoolConfig: poolConfig,
		}
		c.client, err = clusterConfig.New(ctx, hosts)
		if err != nil {
			return nil, err
		}
	} else if len(c.Sentinels) != 0 {
		hosts := strings.Split(c.Sentinels, ",")
		sentinelConfig := radix.SentinelConfig{
			PoolConfig: poolConfig,
		}
		c.client, err = sentinelConfig.New(ctx, "mymaster", hosts)
		if err != nil {
			return nil, err
		}
	} else {
		var client radix.Client
		var secondaries []radix.Client

		client, err = poolConfig.New(ctx, "tcp", c.Addr)
		if err != nil {
			return nil, err
		}
		if len(c.Secondaries) != 0 {
			hosts := strings.Split(c.Secondaries, ",")
			for _, addr := range hosts {
				client, err := poolConfig.New(ctx, "tcp", addr)
				if err != nil {
					return nil, err
				}
				secondaries = append(secondaries, client)
			}
		}
		rs := radix.ReplicaSet{
			Primary:     client,
			Secondaries: secondaries,
		}
		c.client = radix.NewMultiClient(rs)
	}

	return c.client, nil
}

// close terminates the database connection without locking
func (c *redisDBConnectionProducer) close() error {
	if c.client != nil {
		if err := c.client.Close(); err != nil {
			return err
		}
	}

	c.client = nil
	return nil
}

// Close terminates the database connection with locking
func (c *redisDBConnectionProducer) Close() error {
	c.Lock()
	defer c.Unlock()

	return c.close()
}
