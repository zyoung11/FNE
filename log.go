package main

import "fmt"

const (
	logBlue   = "\x1b[38;2;138;173;244m"
	logGreen  = "\x1b[38;2;166;218;149m"
	logYellow = "\x1b[38;2;238;212;159m"
	logRed    = "\x1b[38;2;237;135;150m"
	logReset  = "\x1b[0m"
)

// logPrompt prints a user selection prompt line
func logPrompt(msg string) {
	fmt.Println(logBlue + "[?] " + msg + logReset)
}

// logInput prints a user input prompt without a trailing newline
func logInput(msg string) {
	fmt.Print(logBlue + "[>] " + msg + logReset)
}

// logInfo prints a status information line
func logInfo(msg string) {
	fmt.Println(logBlue + "[i] " + msg + logReset)
}

// logSuccess prints a success line
func logSuccess(msg string) {
	fmt.Println(logGreen + "[+] " + msg + logReset)
}

// logWarn prints a warning line
func logWarn(msg string) {
	fmt.Println(logYellow + "[!] " + msg + logReset)
}

// logError prints an error line
func logError(msg string) {
	fmt.Println(logRed + "[-] " + msg + logReset)
}
