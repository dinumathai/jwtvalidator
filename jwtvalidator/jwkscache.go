package jwtvalidator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"sync"
	"time"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type OpenIDWellKnownConfig struct {
	JwksURI string `json:"jwks_uri"`
}

type JWKSCache struct {
	wellKnownURI    string
	refreshInterval time.Duration
	keyMapCache     map[string]*rsa.PublicKey
	cacheMutex      sync.RWMutex
	stopChan        chan struct{}
}

func NewJWKSCache(openidWellKnownURL string, refreshInterval time.Duration) *JWKSCache {
	cache := &JWKSCache{
		wellKnownURI:    openidWellKnownURL,
		refreshInterval: refreshInterval,
		stopChan:        make(chan struct{}),
	}
	cache.refreshJWKSCache()
	go cache.startPeriodicRefresh()
	return cache
}

// fetchOpenIDConfig fetches the OpenID configuration and extracts the jwks_uri.
func (c *JWKSCache) fetchOpenIDConfig() (string, error) {
	resp, err := http.Get(c.wellKnownURI)
	if err != nil {
		return "", fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	var config OpenIDWellKnownConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return "", fmt.Errorf("failed to parse JSON: %w", err)
	}

	return config.JwksURI, nil
}

// fetchAndCacheJWKS fetches the JWKS content and caches it in memory.
func (c *JWKSCache) fetchAndCacheJWKS(jwksURI string) ([]byte, error) {
	resp, err := http.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	return respBody, nil
}

func (c *JWKSCache) makePublicKeyMap(respBody []byte) (map[string]*rsa.PublicKey, error) {
	publicKeys := make(map[string]*rsa.PublicKey)
	var jwks JWKS
	if err := json.Unmarshal(respBody, &jwks); err != nil {
		return publicKeys, fmt.Errorf("failed to unmarshal JWKS: %w", err)
	}

	for _, key := range jwks.Keys {
		pubKey, err := c.constructPublicKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to construct public key: %w", err)
		}
		publicKeys[key.Kid] = pubKey
	}

	return publicKeys, nil
}

// constructPublicKey constructs an rsa.PublicKey from a JWK response
func (c *JWKSCache) constructPublicKey(key JWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode E: %w", err)
	}

	pubKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
	return pubKey, nil
}

// startPeriodicRefresh periodically refreshes the JWKS content.
func (c *JWKSCache) startPeriodicRefresh() {
	ticker := time.NewTicker(c.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.refreshJWKSCache()
		case <-c.stopChan:
			return
		}
	}
}

func (c *JWKSCache) refreshJWKSCache() error {
	jwksURI, err := c.fetchOpenIDConfig()
	if err != nil {
		return err
	}
	jwksBytes, err := c.fetchAndCacheJWKS(jwksURI)
	if err != nil {
		return err
	}
	publicKeyMap, err := c.makePublicKeyMap(jwksBytes)
	if err != nil {
		return err
	}
	c.cacheMutex.Lock()
	c.keyMapCache = publicKeyMap
	c.cacheMutex.Unlock()
	return nil
}

// getCachedJWKS safely retrieves the cached JWKS content.
func (c *JWKSCache) GetJWKS(keyId string) (*rsa.PublicKey, bool) {
	c.cacheMutex.RLock()
	defer c.cacheMutex.RUnlock()
	pubKey, ok := c.keyMapCache[keyId]
	return pubKey, ok
}

func (c *JWKSCache) Stop() {
	close(c.stopChan)
}
