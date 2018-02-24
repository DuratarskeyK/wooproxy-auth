package main

import (
	"fmt"
	"net/http"
)

// Authorization represents authorization for proxy
// with caching requests
type Authorization struct {
	denied  *HashTTL
	allowed *HashTTL
	apiAddr string
	apiKey  string
}

// NewAuthorization returns a pointer to instance of Authorization with given
// api address and api key
func NewAuthorization(apiAddr string, apiKey string) *Authorization {
	return &Authorization{denied: NewHashTTL(180),
		allowed: NewHashTTL(720),
		apiAddr: apiAddr,
		apiKey:  apiKey}
}

func (a *Authorization) authRequest(ip string, login string, password string) bool {
	uri := fmt.Sprintf("%v/ip/%v/can_login?proxy_login=%v&proxy_password=%v", a.apiAddr, ip, login, password)
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth("api", a.apiKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	body := make([]byte, 3)
	_, err = resp.Body.Read(body)
	if string(body) == "yes" {
		return true
	}

	return false
}

// CanLogin checks cache and issues a request to api to determine if
// a user with login and password can use proxy with given ip.
func (a *Authorization) CanLogin(ip string, login string, password string) bool {
	key := fmt.Sprintf("%v\x00%v\x00%v", ip, login, password)
	_, p := a.denied.Get(key)
	if p {
		return false
	}
	_, p = a.allowed.Get(key)
	if p {
		return true
	}
	canLogin := a.authRequest(ip, login, password)
	if canLogin {
		a.allowed.Set(key, true)
	} else {
		a.denied.Set(key, true)
	}
	return canLogin
}
