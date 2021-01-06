package redis

import (
//	"encoding/base64"
//	"encoding/json"
	"fmt"
//	"io/ioutil"
//	"net/http"
//	"net/url"
	"strings"
	"time"

	"github.com/mediocregopher/radix/v3"
	"github.com/hashicorp/errwrap"
//	"github.com/cenkalti/backoff"
//	"github.com/hashicorp/go-version"
)

func createUser(hostname string, port int, adminuser, adminpassword, username, password, aclRule string) (err error) {

	customConnFunc := func(network, addr string) (radix.Conn, error) {
		return radix.Dial(network, addr,
			radix.DialTimeout(1 * time.Minute),
			radix.DialAuthUser(adminuser, adminpassword),
		)
	}

	poolFunc := func(network, addr string) (radix.Client, error) {
		return radix.NewPool(network, addr, 1, radix.PoolConnFunc(customConnFunc))
	}

	var client radix.Client
	var cluster *radix.Cluster
	
	if port == -1 {
		cluster_hosts := strings.Split(hostname, ",")
		cluster, err = radix.NewCluster(cluster_hosts, radix.ClusterPoolFunc(poolFunc))
		if err != nil {
			return errwrap.Wrapf("error in Cluster connection: {{err}}", err)
		}
	} else {
		
		addr := fmt.Sprintf("%s:%d", hostname, port)

		client, err = radix.NewPool("tcp", addr, 1, radix.PoolConnFunc(customConnFunc)) // [TODO] poolopts for timeout from ctx??
		if err != nil {
			return errwrap.Wrapf("error in Connection: {{err}}", err)
		}
	}

	var response string

	if port == -1 {
		topo := cluster.Topo()
		client = cluster
		nodes := topo.Map()
		for key := range nodes {
			cl, err := cluster.Client(key)
			if err != nil {
				return err
			}
			err = cl.Do(radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">" + password, aclRule))
			if err != nil {
				return err
			}
		}

	} else {
	
		err = client.Do(radix.Cmd(&response, "ACL", "SETUSER", username, "on", ">" + password, aclRule))
		
		fmt.Printf("Response in client createUser: %s\n", response)

		if err != nil {
			return err
		}

	}

	fmt.Printf("Client is of type %T\n", client)

	if client != nil {
		if err = client.Close(); err != nil {
			return err
		}
	}


	return nil
}


