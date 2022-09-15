package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/mediocregopher/radix/v4"
)

func createUser(hostname string, port int, redisTls bool, caCrt, adminuser, adminpassword, username, password, aclRule string) (err error) {
	pem, err := base64.StdEncoding.DecodeString(caCrt)
	if err != nil {
		return fmt.Errorf("error decoding CaCrt")
	}
	rootCAs := x509.NewCertPool()
	ok := rootCAs.AppendCertsFromPEM([]byte(pem))
	if !ok {
		return fmt.Errorf("failed to parse root certificate")
	}

	var poolConfig radix.PoolConfig

	if redisTls {
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: adminuser,
				AuthPass: adminpassword,
				NetDialer: &tls.Dialer{
					Config: &tls.Config{
						RootCAs:            rootCAs,
						InsecureSkipVerify: true,
					},
				},
			},
		}
	} else {
		poolConfig = radix.PoolConfig{
			Dialer: radix.Dialer{
				AuthUser: adminuser,
				AuthPass: adminpassword,
			},
		}
	}

	addr := fmt.Sprintf("%s:%d", hostname, port)
	client, err := poolConfig.New(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}

	var response string
	err = client.Do(context.Background(), radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">"+password, aclRule))

	fmt.Printf("Response in createUser: %s\n", response)

	if err != nil {
		return err
	}

	if client != nil {
		if err = client.Close(); err != nil {
			return err
		}
	}

	return nil
}
