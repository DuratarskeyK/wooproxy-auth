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

func authTask(authTasks chan string, output chan string, authBackend *Authorization) {
	for {
		authStringSplit := strings.Split(<-authTasks, " ")
		canLogin := authBackend.CanLogin(authStringSplit[3], authStringSplit[1], authStringSplit[2])
		if canLogin {
			output <- fmt.Sprintf("%s OK", authStringSplit[0])
		} else {
			output <- fmt.Sprintf("%s ERR", authStringSplit[0])
		}
	}
}

func outputToSquid(output chan string) {
	b := bufio.NewWriter(os.Stdout)
	for {
		outputStr := <-output
		fmt.Fprintln(b, outputStr)
		b.Flush()
	}
}

func checkStringForValidity(squidStr string) bool {
	split := strings.Split(squidStr, " ")
	if len(split) != 4 {
		return false
	}
	if split[3] == "-" {
		return false
	}

	return true
}

func getAPIInfoFromFile(path string) (*AuthData, error) {
	if path == "" {
		return nil, errors.New("Empty path")
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	dataSplit := strings.Split(string(data), "\n")
	ret := &AuthData{}
	ret.APIAddr = dataSplit[0]
	ret.APIKey = dataSplit[1]
	serverID, err := strconv.Atoi(dataSplit[2])
	if err != nil {
		return nil, err
	}
	ret.ServerID = serverID
	return ret, nil
}

func main() {
	authThreads := flag.Int("auth_threads", 1, "How many auth threads to launch.")
	apiInfoFileCmd := flag.String("api_info_file", "", "Path to file with api address and api key, split by new line.")
	flag.Parse()

	authData, err := getAPIInfoFromFile(*apiInfoFileCmd)

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading api info file\n")
		os.Exit(1)
	}

	if *authThreads < 1 {
		fmt.Fprint(os.Stderr, "auth_threads must be greater than 0.\n")
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	authTasks := make(chan string)
	output := make(chan string)

	authBackend := NewAuthorization(authData)

	go outputToSquid(output)

	for i := 0; i < *authThreads; i++ {
		go authTask(authTasks, output, authBackend)
	}

	for scanner.Scan() {
		inputString := scanner.Text()
		if checkStringForValidity(inputString) {
			authTasks <- inputString
		} else {
			inputStringSplit := strings.Split(inputString, " ")
			output <- fmt.Sprintf("%s BH", inputStringSplit[0])
		}
	}

}
