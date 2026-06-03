package utils

import (
	"log"
	"strings"
)

func SetupLogging(verbose bool) {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	if verbose {
		log.Println("[DEBUG] Verbose logging level initialized")
	}
}

func FlushLogs() {}

func SelectLinesWithPrefix(text string, prefixes []string) []string {
	var matchedLines []string
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	for _, line := range lines {
		for _, prefix := range prefixes {
			if strings.HasPrefix(line, prefix) {
				matchedLines = append(matchedLines, line)
				break
			}
		}
	}
	return matchedLines
}
