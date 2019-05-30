package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"sync/atomic"
	"time"
)

// AuthData contains proxy ip to passwords and authorized ips map,
// master password and backconnect server ips list
type AuthData struct {
	IPToCredentials    map[string]map[string]bool `json:"ips_to_credentials"`
	IPToAllowedIPs     map[string]map[string]bool `json:"ips_to_authorized_ips"`
	MasterPassword     string                     `json:"master_password"`
	BackconnectServers []string                   `json:"backconnect_servers"`
}

// APIData contains data needed to access api
type APIData struct {
	APIAddr  string
	APIKey   string
	ServerID int
}

// Authorization represents authorization for proxy
type Authorization struct {
	apiData *APIData

	credentialsHash string
	AuthData        atomic.Value

	authHashURI string
	authDataURI string

	httpClient *http.Client
}

func (auth *Authorization) getCurrentAuthData() ([]byte, error) {
	req, err := http.NewRequest("GET", auth.authDataURI, nil)
	if err != nil {
		return nil, errors.New("Fail")
	}
	req.SetBasicAuth("api", auth.apiData.APIKey)

	resp, err := auth.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("Fail")
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.New("Fail")
	}

	r, err := gzip.NewReader(bytes.NewBuffer(bodyBytes))
	if err != nil {
		return nil, errors.New("Fail")
	}
	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return nil, errors.New("Fail")
	}

	return resB.Bytes(), nil
}

func (auth *Authorization) getCurrentAuthHash() string {
	req, err := http.NewRequest("GET", auth.authHashURI, nil)
	if err != nil {
		return ""
	}
	req.SetBasicAuth("api", auth.apiData.APIKey)

	resp, err := auth.httpClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	return string(bodyBytes)
}

func (auth *Authorization) updateAuth() {
	newHash := auth.getCurrentAuthHash()

	if newHash != "" && newHash != auth.credentialsHash {
		authDataRaw, err := auth.getCurrentAuthData()
		if err == nil {
			var newData AuthData
			json.Unmarshal(authDataRaw, &newData)
			auth.credentialsHash = newHash
			auth.AuthData.Store(&newData)
		}
	}
}

func (auth *Authorization) checkForNewAuth() {
	for {
		time.Sleep(60 * time.Second)
		auth.updateAuth()
	}
}

// NewAuthorization returns a pointer to instance of Authorization with given
// api address and api key
func NewAuthorization(apiData *APIData) *Authorization {
	auth := &Authorization{
		apiData:     apiData,
		authHashURI: fmt.Sprintf("%v/server/%v/auth_config_hash", apiData.APIAddr, apiData.ServerID),
		authDataURI: fmt.Sprintf("%v/server/%v/auth_config", apiData.APIAddr, apiData.ServerID),
		httpClient:  &http.Client{Timeout: time.Second * 10},
	}

	auth.updateAuth()
	go auth.checkForNewAuth()

	return auth
}

// CanLogin checks cache and issues a request to api to determine if
// a user with login and password can use proxy with given ip.
func (auth *Authorization) CanLogin(proxyIP string, credentials string, remoteIP string) bool {
	authData := auth.AuthData.Load().(*AuthData)
	if credentials == authData.MasterPassword {
		return true
	}

	for _, ip := range authData.BackconnectServers {
		if remoteIP == ip {
			return true
		}
	}

	val, ok := authData.IPToAllowedIPs[proxyIP]
	if ok {
		if _, ok = val[remoteIP]; ok {
			return true
		}
	}

	if credentials != "ipauth:ipauth" {
		val, ok = authData.IPToCredentials[proxyIP]
		if !ok {
			return false
		}

		_, ok = val[credentials]

		return ok
	}
	return false
}
