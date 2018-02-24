package main

import (
	"bufio"
	"flag"
	"fmt"
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

func main() {
	authThreads := flag.Int("auth_threads", 1, "How many auth threads to launch")
	apiAddr := flag.String("api_addr", "", "Address for Proxy Api endpoint")
	apiKey := flag.String("api_key", "", "Api key for the Proxy Api")
	flag.Parse()

	if *authThreads < 1 {
		fmt.Fprint(os.Stderr, "auth_threads must be positive.\n")
		os.Exit(1)
	}

	if *apiAddr == "" {
		fmt.Fprint(os.Stderr, "api_addr can't be empty.\n")
		os.Exit(1)
	}

	if *apiKey == "" {
		fmt.Fprint(os.Stderr, "api_key can't be empty.\n")
		os.Exit(1)
	}
	scanner := bufio.NewScanner(os.Stdin)

	authTasks := make(chan string)
	output := make(chan string)
	authBackend := NewAuthorization(*apiAddr, *apiKey)

	go outputToSquid(output)

	for i := 0; i < *authThreads; i++ {
		go authTask(authTasks, output, authBackend)
	}

	for scanner.Scan() {
		inputString := scanner.Text()
		if checkStringForValidity(inputString) {
			authTasks <- inputString
		}
	}

}
