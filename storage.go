package tlsconsul

import (
	"fmt"
	"github.com/hashicorp/consul/api"
	"github.com/mholt/caddy/caddytls"
	"log"
	"net/url"
	"path"
	"time"
)

const defaultLockTTLSeconds = 300

type tlsConsulStorage struct {
	*tlsConsul
	caHost string
	locks  map[string]*api.Lock
}

func newTLSConsulStorage(caURL *url.URL, t *tlsConsul) *tlsConsulStorage {
	ret := &tlsConsulStorage{
		tlsConsul: t,
		caHost:    caURL.Host,
		locks:     make(map[string]*api.Lock),
	}
	// We must listen to events to know when to invalidate
	go ret.runEventListener()
	return ret
}

func (t *tlsConsulStorage) key(suffix string) string {
	return path.Join(t.prefix, t.caHost, suffix)
}

func (t *tlsConsulStorage) eventKey() string {
	return t.key("domainevent")
}

func (t *tlsConsulStorage) runEventListener() {
	// In a go routine, just loop checking events forever. Based on simple
	// inspection of Consul source, calling the API this way should be
	// thread safe.
	eventKey := t.eventKey()
	queryOpts := new(api.QueryOptions)
	var domainName string
	for {
		evts, meta, err := t.Event().List(eventKey, queryOpts)
		if err != nil {
			log.Printf("[ERROR] Unable to read events: %v", err)
			continue
		}
		queryOpts.WaitIndex = meta.LastIndex
		for _, evt := range evts {
			if err = t.fromBytes(evt.Payload, &domainName); err != nil {
				log.Printf("[ERROR] Failed to decode domain names: %v", err)
				continue
			}
			if _, err = caddytls.CacheManagedCertificate(domainName, t.tlsConfig); err != nil {
				log.Printf("[ERROR] Unable to invalidate cache for %v: %v", domainName, err)
			}
		}
	}
}

func (t *tlsConsulStorage) siteKey(domain string) string {
	return t.key(path.Join("sites", domain))
}

func (t *tlsConsulStorage) SiteExists(domain string) bool {
	kv, _, _ := t.KV().Get(t.siteKey(domain), &api.QueryOptions{RequireConsistent: true})
	return kv != nil
}

func (t *tlsConsulStorage) LoadSite(domain string) (*caddytls.SiteData, error) {
	kv, _, err := t.KV().Get(t.siteKey(domain), &api.QueryOptions{RequireConsistent: true})
	if err != nil {
		return nil, fmt.Errorf("Unable to obtain site data for %v: %v", domain, err)
	} else if kv == nil {
		return nil, caddytls.ErrStorageNotFound
	}
	ret := new(caddytls.SiteData)
	if err = t.fromBytes(kv.Value, ret); err != nil {
		return nil, fmt.Errorf("Unable to decode site data for %v: %v", domain, err)
	}
	return ret, nil
}

func (t *tlsConsulStorage) StoreSite(domain string, data *caddytls.SiteData) error {
	kv := &api.KVPair{Key: t.siteKey(domain)}
	var err error
	kv.Value, err = t.toBytes(data)
	if err != nil {
		return fmt.Errorf("Unable to encode site data for %v: %v", domain, err)
	}
	if err = t.KV().Put(kv, nil); err != nil {
		return fmt.Errorf("Unable to store site data for %v: %v", domain, err)
	}
	// We need to fire an event here to invalidate the cache elsewhere
	evt := &api.UserEvent{Name: t.eventKey()}
	if evt.Payload, err = t.toBytes(domain); err != nil {
		return fmt.Errorf("Unable to create domain-changed event for %v: %v", domain, err)
	}
	// TODO: we know that we are going to receive our own event. Should I store the
	// resulting ID somewhere so I know not to act on it and reload it? Or is it
	// harmless to reload it?
	if err = t.Event().Fire(evt, nil); err != nil {
		return fmt.Errorf("Unable to send domain-changed event for %v: %v", domain, err)
	}
	return nil
}

func (t *tlsConsulStorage) DeleteSite(domain string) error {
	// In order to delete properly and know whether it took, we must first
	// get and do a CAS operation because delete is idempotent
	// (ref: https://github.com/hashicorp/consul/issues/348). This can
	// cause race conditions on multiple servers. But since this is a
	// user-initiated action (i.e. revoke), they will see the error.
	kv, _, err := t.KV().Get(t.siteKey(domain), &api.QueryOptions{RequireConsistent: true})
	if err != nil {
		return fmt.Errorf("Unable to obtain site data for %v: %v", domain, err)
	} else if kv == nil {
		return caddytls.ErrStorageNotFound
	}
	if success, _, err := t.KV().DeleteCAS(kv, nil); err != nil {
		return fmt.Errorf("Unable to delete site data for %v: %v", domain, err)
	} else if !success {
		return fmt.Errorf("Failed to lock site data delete for %v", domain)
	}
	// TODO: on revoke, what do we do here? Send out an event?
	return nil
}

func (t *tlsConsulStorage) lockKey(domain string) string {
	return t.key(path.Join("locks", domain))
}

func (t *tlsConsulStorage) LockRegister(domain string) (bool, error) {
	// We can trust this isn't double called in the same process
	ttlSeconds := t.lockTTLSeconds
	if ttlSeconds == 0 {
		ttlSeconds = defaultLockTTLSeconds
	}
	opts := &api.LockOptions{
		Key:         t.lockKey(domain),
		SessionTTL:  ttlSeconds + "s",
		LockTryOnce: true,
	}
	if t.lockWaitSeconds != 0 {
		opts.LockWaitTime = t.lockWaitSeconds * time.Second
	}
	lock, err := t.LockOpts(opts)
	if err != nil {
		return false, fmt.Errorf("Failed creating lock for %v: %v", domain, err)
	}
	leaderCh, err := lock.Lock(nil)
	if err != nil && err != api.ErrLockHeld {
		return false, fmt.Errorf("Unexpected error attempting to take lock for %v: %v", domain, err)
	} else if leaderCh == nil || err != nil {
		return false, nil
	}
	// We don't care if we lose the leaderCh...
	t.locks[domain] = lock
	return true, nil
}

func (t *tlsConsulStorage) UnlockRegister(domain string) error {
	if lock := t.locks[domain]; lock != nil {
		if err := lock.Unlock(); err != nil && err != api.ErrLockNotHeld {
			return fmt.Errorf("Failed unlocking lock for %v: %v", domain, err)
		}
	}
	return nil
}

func (t *tlsConsulStorage) LoadUser(email string) (*caddytls.UserData, error) {
	panic("no impl")
}

func (t *tlsConsulStorage) StoreUser(email string, data *caddytls.UserData) error {
	panic("no impl")
}

func (t *tlsConsulStorage) MostRecentUserEmail() string {
	panic("no impl")
}
