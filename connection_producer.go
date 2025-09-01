// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"sync"

	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mediocregopher/radix/v4"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/net/proxy"
)

type redisDBConnectionProducer struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	TLS         bool   `json:"tls"`
	InsecureTLS bool   `json:"insecure_tls"`
	CACert      string `json:"ca_cert"`

	Initialized bool
	rawConfig   map[string]interface{}
	Type        string
	client      radix.Client
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
	case len(c.Host) == 0:
		return nil, fmt.Errorf("host cannot be empty")
	case c.Port == 0:
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

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, fmt.Errorf("error verifying connection: %w", err)
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

	var dialer radix.Dialer

	var tlsDialer *tls.Dialer
	if c.TLS {
		rootCAs := x509.NewCertPool()
		ok := rootCAs.AppendCertsFromPEM([]byte(c.CACert))
		if !ok {
			return nil, fmt.Errorf("failed to parse root certificate")
		}
		tlsDialer = &tls.Dialer{
			Config: &tls.Config{
				RootCAs:            rootCAs,
				InsecureSkipVerify: c.InsecureTLS,
			},
		}
	}

	if proxyURL, ok := os.LookupEnv("ALL_PROXY"); ok {
		u, err := url.Parse(proxyURL)
		if err != nil {
			return nil, err
		}
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{
				User:     u.User.Username(),
				Password: password,
			}
		}
		var forward proxy.Dialer
		if tlsDialer != nil {
			forward = tlsDialer
		} else {
			forward = proxy.Direct
		}

		d, err := proxy.SOCKS5("tcp", u.Host, auth, forward)
		if err != nil {
			return nil, err
		}
		dialer = radix.Dialer{
			AuthUser:  c.Username,
			AuthPass:  c.Password,
			NetDialer: d.(proxy.ContextDialer),
		}
	} else {
		if tlsDialer != nil {
			dialer = radix.Dialer{
				AuthUser:  c.Username,
				AuthPass:  c.Password,
				NetDialer: tlsDialer,
			}
		} else {
			dialer = radix.Dialer{
				AuthUser: c.Username,
				AuthPass: c.Password,
			}
		}
	}

	poolConfig = radix.PoolConfig{
		Dialer: dialer,
	}

	client, err := poolConfig.New(ctx, "tcp", c.Addr)
	if err != nil {
		return nil, err
	}
	c.client = client

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
