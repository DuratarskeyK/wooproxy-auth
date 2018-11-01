package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

func getAPIInfoFromFile(path string) (*APIData, error) {
	if path == "" {
		return nil, errors.New("Empty path")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dataSplit := strings.Split(string(data), "\n")
	ret := &APIData{}
	ret.APIAddr = dataSplit[0]
	ret.APIKey = dataSplit[1]
	serverID, err := strconv.Atoi(dataSplit[2])
	if err != nil {
		return nil, err
	}
	ret.ServerID = serverID
	return ret, nil
}

var OK = []byte("OK\n")
var BH = []byte("BH\n")
var ERR = []byte("ERR\n")

func main() {
	apiInfoFileCmd := flag.String("api_info_file", "", "Path to file with api address and api key, split by new line.")
	flag.Parse()

	authData, err := getAPIInfoFromFile(*apiInfoFileCmd)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading api info file\n")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	authBackend := NewAuthorization(authData)

	for scanner.Scan() {
		inputString := scanner.Text()
		authStringSplit := strings.Split(inputString, " ")
		if len(authStringSplit) != 4 {
			os.Stdout.Write(BH)
		} else {
			login := authStringSplit[0]
			password := authStringSplit[1]
			proxyIP := authStringSplit[2]
			remoteIP := authStringSplit[3]
			canLogin := authBackend.CanLogin(proxyIP, fmt.Sprintf("%s:%s", login, password), remoteIP)
			if canLogin {
				os.Stdout.Write(OK)
			} else {
				os.Stdout.Write(ERR)
			}
		}
	}
}
