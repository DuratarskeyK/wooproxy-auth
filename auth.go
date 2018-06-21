package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthData contains data needed to access api
type AuthData struct {
	APIAddr  string
	APIKey   string
	ServerID int
}

// Authorization represents authorization for proxy
type Authorization struct {
	authData          *AuthData
	credentialsHash   string
	credentials       map[string]map[string]bool
	credentialsMutex  *sync.RWMutex
	masterLogin       string
	masterPassword    string
	authHashURI       string
	authDataURI       string
	masterPasswordURI string
}

const (
	stateIP       = iota
	stateLogin    = iota
	statePassword = iota
)

func parseAuthOutput(output string) map[string]map[string]bool {
	currentState := stateIP
	result := make(map[string]map[string]bool)
	strArr := strings.Split(output, "\n")

	currentIP := ""
	currentLogin := ""
	var currentMap map[string]bool
	for _, v := range strArr {
		if v == "" {
			continue
		}
		if strings.HasPrefix(v, "IP=") {
			if currentMap != nil {
				result[currentIP] = currentMap
			}
			currentMap = make(map[string]bool)
			currentState = stateIP
		}
		switch currentState {
		case stateIP:
			currentIP = strings.Replace(v, "IP=", "", 1)
			currentState = stateLogin
		case stateLogin:
			currentLogin = v
			currentState = statePassword
		case statePassword:
			authStr := fmt.Sprintf("%v\x00%v", currentLogin, v)
			currentMap[authStr] = true
			currentState = stateLogin
		}
	}
	if currentMap != nil {
		result[currentIP] = currentMap
	}

	return result
}

func (auth *Authorization) getCurrentAuthData() string {
	req, err := http.NewRequest("GET", auth.authDataURI, nil)
	if err != nil {
		return ""
	}
	req.SetBasicAuth("api", auth.authData.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return ""
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return ""
	}

	r, err := gzip.NewReader(bytes.NewBuffer(bodyBytes))
	if err != nil {
		return ""
	}
	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return ""
	}

	return string(resB.Bytes())
}

func (auth *Authorization) getCurrentAuthHash() string {
	req, err := http.NewRequest("GET", auth.authHashURI, nil)
	if err != nil {
		return ""
	}
	req.SetBasicAuth("api", auth.authData.APIKey)

	resp, err := http.DefaultClient.Do(req)
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

func (auth *Authorization) updateMasterPassword() {
	req, err := http.NewRequest("GET", auth.masterPasswordURI, nil)
	if err != nil {
		return
	}
	req.SetBasicAuth("api", auth.authData.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	masterCredentials := strings.Split(string(bodyBytes), ":")
	auth.masterLogin = masterCredentials[0]
	auth.masterPassword = masterCredentials[1]
}

func (auth *Authorization) updateAuth() {
	newHash := auth.getCurrentAuthHash()

	if newHash != "" && newHash != auth.credentialsHash {
		auth.credentialsHash = newHash
		authDataString := auth.getCurrentAuthData()
		if authDataString != "" {
			parsedOutput := parseAuthOutput(authDataString)
			if parsedOutput != nil {
				auth.credentialsMutex.Lock()
				auth.credentials = parsedOutput
				auth.credentialsMutex.Unlock()
			}
		}
	}
}

func (auth *Authorization) checkForNewAuth() {
	for true {
		time.Sleep(60 * time.Second)
		auth.updateMasterPassword()
		auth.updateAuth()
	}
}

// NewAuthorization returns a pointer to instance of Authorization with given
// api address and api key
func NewAuthorization(authData *AuthData) *Authorization {
	auth := &Authorization{
		authData:          authData,
		credentialsHash:   "",
		credentialsMutex:  &sync.RWMutex{},
		authHashURI:       fmt.Sprintf("%v/server/%v/auth_hash", authData.APIAddr, authData.ServerID),
		authDataURI:       fmt.Sprintf("%v/server/%v/auth_data", authData.APIAddr, authData.ServerID),
		masterPasswordURI: fmt.Sprintf("%v/master_password/get", authData.APIAddr)}

	auth.updateMasterPassword()
	auth.updateAuth()
	go auth.checkForNewAuth()

	return auth
}

// CanLogin checks cache and issues a request to api to determine if
// a user with login and password can use proxy with given ip.
func (auth *Authorization) CanLogin(ip string, login string, password string) bool {
	auth.credentialsMutex.RLock()
	defer auth.credentialsMutex.RUnlock()

	if login == auth.masterLogin && password == auth.masterPassword {
		return true
	}

	val, ok := auth.credentials[ip]
	if !ok {
		return false
	}
	authStr := fmt.Sprintf("%v\x00%v", login, password)
	_, ok = val[authStr]

	return ok
}
