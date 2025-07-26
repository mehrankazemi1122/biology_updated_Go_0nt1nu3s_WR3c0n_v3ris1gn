package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
)

func main() {
	if len(os.Args) < 3 {
		log.Println("Usage: go run . <wordlist_file> <website_address>")
		return
	}

	wordlistFile := os.Args[1]
	websiteAddress := os.Args[2]
	outputFile := "output." + websiteAddress + ".txt"
	prevOutputFile := "prev_output." + websiteAddress + ".txt"
	httpxOutputFile := "httpx_res.txt"
	prevHttpxOutputFile := "prev_httpx_res.txt"

	log.Println("Starting subdomain enumeration...")
	var allSubs []string
	for i := 0; i < 3; i++ {
		log.Printf("Running shuffledns scan #%d...", i+1)
		tempOutputFile := fmt.Sprintf("output_%d.txt", i)
		runShuffledns(wordlistFile, websiteAddress, tempOutputFile)
		subs, _ := readLines(tempOutputFile)
		allSubs = append(allSubs, subs...)
		os.Remove(tempOutputFile)
	}

	log.Println("Consolidating and deduplicating results...")
	allSubs = removeDuplicates(allSubs)
	writeLines(allSubs, outputFile)

	log.Println("Comparing subdomain lists...")
	currentSubs, _ := readLines(outputFile)
	prevSubs, _ := readLines(prevOutputFile)

	addedSubs := findAdded(currentSubs, prevSubs)
	deletedSubs := findDeleted(currentSubs, prevSubs)

	notifySubdomainChanges(addedSubs, deletedSubs)

	log.Println("Updating previous subdomain list...")
	os.Rename(outputFile, prevOutputFile)

	log.Println("Starting HTTP service analysis...")
	runHttpx(prevOutputFile, httpxOutputFile)

	log.Println("Comparing HTTP service scan results...")
	currentHttpx, _ := readLines(httpxOutputFile)
	prevHttpx, _ := readLines(prevHttpxOutputFile)

	changes := findAdded(currentHttpx, prevHttpx)
	notifyHttpxChanges(changes)

	log.Println("Updating previous HTTP service scan results...")
	os.Rename(httpxOutputFile, prevHttpxOutputFile)

	log.Println("Process completed successfully.")
}

func runShuffledns(wordlistFile, websiteAddress, outputFile string) {
	cmd := exec.Command("shuffledns",
		"-w", wordlistFile,
		"-d", websiteAddress,
		"-r", "resolvers.txt",
		"-o", outputFile,
		"-mode", "bruteforce",
	)
	if err := cmd.Run(); err != nil {
		log.Fatalf("shuffledns command failed: %v", err)
	}
	log.Println("shuffledns command executed successfully")
}

func runHttpx(inputFile, outputFile string) {
	cmd := exec.Command("sh", "-c",
		"cat "+inputFile+" | dnsx -silent | httpx -silent -follow-host-redirects -nc -title -status-code -cdn -tech-detect "+
			`-H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:108.0) Gecko/20100101 Firefox/108.0" `+
			"> "+outputFile,
	)
	if err := cmd.Run(); err != nil {
		log.Fatalf("httpx command failed: %v", err)
	}
	log.Println("httpx command executed successfully")
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func findAdded(current, previous []string) []string {
	prevMap := make(map[string]bool)
	for _, item := range previous {
		prevMap[item] = true
	}

	var added []string
	for _, item := range current {
		if !prevMap[item] {
			added = append(added, item)
		}
	}
	return added
}

func findDeleted(current, previous []string) []string {
	currentMap := make(map[string]bool)
	for _, item := range current {
		currentMap[item] = true
	}

	var deleted []string
	for _, item := range previous {
		if !currentMap[item] {
			deleted = append(deleted, item)
		}
	}
	return deleted
}

func removeDuplicates(elements []string) []string {
	encountered := make(map[string]bool)
	var result []string
	for _, v := range elements {
		if !encountered[v] {
			encountered[v] = true
			result = append(result, v)
		}
	}
	return result
}

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func notifySubdomainChanges(added, deleted []string) {
	if len(added) > 0 {
		log.Println("Subdomains Added:")
		for _, sub := range added {
			log.Println(sub)
			sendDiscordNotification("Subdomain Added: " + sub)
		}
	}
	if len(deleted) > 0 {
		log.Println("Subdomains Deleted:")
		for _, sub := range deleted {
			log.Println(sub)
			sendDiscordNotification("Subdomain Deleted: " + sub)
		}
	}
}

func notifyHttpxChanges(changes []string) {
	if len(changes) > 0 {
		log.Println("Service changes:")
		for _, change := range changes {
			log.Println(change)
			sendDiscordNotification("Service change: " + change)
		}
	}
}

func sendDiscordNotification(message string) {
	webhookURL := os.Getenv("DISCORD_TOKEN")
	//webhookURL := "https://discordapp.com/api/webhooks/1398701724046327849/fbvvWnLdj3j5GfSdxII60agmdXbJP61Ur_SDlOcFXzCm4hIvxetzFEjPaxazT8fkXXe"
	if webhookURL == "" {
		log.Println("DISCORD_TOKEN environment variable not set. Skipping notification.")
		return
	}
	payload := struct {
		Content string `json:"content"`
	}{
		Content: message,
	}
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Printf("failed to marshal discord payload: %v", err)
		return
	}
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("failed to send discord notification: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("discord notification failed with status code: %d", resp.StatusCode)
	}
}
