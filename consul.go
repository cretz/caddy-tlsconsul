package tlsconsul

import (
	"crypto/aes"
	"fmt"
	"github.com/hashicorp/consul/api"
	"github.com/mholt/caddy"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"github.com/mholt/caddy/caddytls"
	"log"
	"net/url"
	"strconv"
)

type tlsConsul struct {
	tlsConfig *caddytls.Config
	verbose   bool
	aesKey    []byte
	prefix    string
	// Amount of time the lock can be held for.
	// We will default this to 5 minutes (i.e. 300s)
	lockTTLSeconds int
	// Amount of time we will wait to try to acquire the lock.
	// Defaults to Consul's default which is 15 seconds.
	lockWaitSeconds int
	*api.Client
}

// Result can be nil without error
func applyTLSConsul(c *caddy.Controller) error {
	// If there is no config, we do nothing
	if !c.Next() {
		return nil, nil
	}

	// There has to be a TLS config for this to even apply
	httpCfg := httpserver.GetConfig(c)
	if httpCfg.TLS == nil {
		return nil, nil
	}

	tc := new(tlsConsul)
	tc.tlsConfig = httpCfg.TLS
	consulCfg := api.DefaultConfig()

	// Parse the config...we only allow one
	for c.NextBlock() {
		switch c.Val() {
		case "address":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			consulCfg.Address = c.Val()
		case "scheme":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			consulCfg.Scheme = c.Val()
		case "datacenter":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			consulCfg.Datacenter = c.Val()
		case "username":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			if consulCfg.HttpAuth == nil {
				consulCfg.HttpAuth = new(api.HttpBasicAuth)
			}
			consulCfg.HttpAuth.Username = c.Val()
		case "password":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			if consulCfg.HttpAuth == nil {
				consulCfg.HttpAuth = new(api.HttpBasicAuth)
			}
			consulCfg.HttpAuth.Password = c.Val()
		case "token":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			consulCfg.Token = c.Val()
		case "verbose":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			tc.verbose = c.Val() == "true"
		case "aesKey":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			tc.aesKey = []byte(c.Val())
			// Just create a new block to see if we can
			if _, err := aes.NewCipher(tc.aesKey); err != nil {
				return nil, c.Errf("Invalid AES key: %v", err)
			}
		case "prefix":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			tc.prefix = c.Val()
		case "lock_ttl_seconds":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			var err error
			tc.lockTTLSeconds, err = strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.Errf("Invalid TTL seconds format: %v", err)
			} else if tc.lockTTLSeconds < 10 || tc.lockTTLSeconds > 86400 {
				return nil, c.Errf("Lock TTL seconds of %v is out of range", tc.lockTTLSeconds)
			}
		case "lock_wait_seconds":
			if !c.NextArg() {
				return nil, c.ArgErr()
			}
			var err error
			tc.lockWaitSeconds, err = strconv.Atoi(c.Val())
			if err != nil {
				return nil, c.Errf("Invalid wait seconds format: %v", err)
			}
		default:
			return nil, c.ArgErr()
		}
	}
	// Error if there is another config
	if c.Next() {
		return nil, c.Err("tlsconsul only accepts a single block, multiple values are not supported")
	}

	// Try to ping consul w/ the config
	var err error
	tc.Client, err = api.NewClient(consulCfg)
	if err != nil {
		return nil, fmt.Errorf("Unable to create Consul client: %v", err)
	}
	nodeName, err := tc.Agent().NodeName()
	if err != nil {
		return nil, fmt.Errorf("Unable to ping Consul: %v", err)
	}
	if tc.verbose {
		log.Printf("[INFO] tlsconsul connected to node %v", nodeName)
	}

	// Now we can set the storage creator factory function
	tc.tlsConfig.StorageCreator = tc.createStorage
	return nil
}

func (t *tlsConsul) createStorage(caURL *url.URL) (caddytls.Storage, error) {
	return newTLSConsulStorage(caURL, t), nil
}

func init() {
	caddy.RegisterPlugin("tlsconsul", caddy.Plugin{Action: applyTLSConsul})
}
