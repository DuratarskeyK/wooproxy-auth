package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
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

func getAPIInfoFromFile(path string) (string, string) {
	if path == "" {
		return "", ""
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return "", ""
	}

	dataSplit := strings.Split(string(data), "\n")
	return dataSplit[0], dataSplit[1]
}

func main() {
	authThreads := flag.Int("auth_threads", 1, "How many auth threads to launch.")
	apiAddrCmd := flag.String("api_addr", "", "Address for Proxy Api endpoint. If empty, API_ADDR env is used. Priority is - command line, env, file.")
	apiKeyCmd := flag.String("api_key", "", "Api key for the Proxy Api. If empty, API_KEY env is used. Priority is - command line, env, file.")
	apiInfoFileCmd := flag.String("api_info_file", "", "Path to file with api address and api key, split by new line.")
	flag.Parse()
	apiAddr := *apiAddrCmd
	apiKey := *apiKeyCmd

	apiAddrFile, apiKeyFile := getAPIInfoFromFile(*apiInfoFileCmd)

	if *authThreads < 1 {
		fmt.Fprint(os.Stderr, "auth_threads must be greater than 0.\n")
		os.Exit(1)
	}

	if apiAddr == "" {
		apiAddr = os.Getenv("API_ADDR")
		if apiAddr == "" {
			apiAddr = apiAddrFile
			if apiAddr == "" {
				fmt.Fprint(os.Stderr, "api_addr can't be empty.\n")
				os.Exit(1)
			}
		}
	}

	if apiKey == "" {
		apiKey = os.Getenv("API_KEY")
		if apiKey == "" {
			apiKey = apiKeyFile
			if apiKey == "" {
				fmt.Fprint(os.Stderr, "api_key can't be empty.\n")
				os.Exit(1)
			}
		}
	}
	scanner := bufio.NewScanner(os.Stdin)

	authTasks := make(chan string)
	output := make(chan string)

	authBackend := NewAuthorization(apiAddr, apiKey)

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
