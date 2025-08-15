package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/goccy/go-yaml"
)

var (
	debug           bool
	errConfigLoad   = errors.New("config load error")
	errConfigCreate = errors.New("config create error")
	errDBEncrypt    = errors.New("database encryption error")
	errDBDecrypt    = errors.New("database decryption error")
)

type RepoConfig struct {
	DBFile            string              `yaml:"db_file"`
	ExcludeFromGlobal bool                `yaml:"exclude_from_global"`
	SubjectTag        *string             `yaml:"subject_tag"`
	IMAPMailbox       *string             `yaml:"imap_mailbox"`
	Reactions         map[string]string   `yaml:"reactions"`
	MarkAs            map[string]string   `yaml:"mark_as"`
	Permissions       map[string][]string `yaml:"permissions"`
}

type GlobalConfig struct {
	IMAPServer        string              `yaml:"imap_server"`
	IMAPUsername      string              `yaml:"imap_username"`
	IMAPPassword      string              `yaml:"imap_password"`
	SMTPServer        string              `yaml:"smtp_server"`
	SMTPUsername      string              `yaml:"smtp_username"`
	SMTPPassword      string              `yaml:"smtp_password"`
	SMTPFromAddr      string              `yaml:"smtp_from_addr"`
	SMTPFromAlias     *string             `yaml:"smtp_from_alias,omitempty"`
	DBEncryptionKey   string              `yaml:"db_encryption_key"`
	DisableEncryption bool                `yaml:"disable_encryption"`
	SubjectTag        string              `yaml:"subject_tag"`
	IMAPMailbox       string              `yaml:"imap_mailbox"`
	Reactions         map[string]string   `yaml:"reactions"`
	MarkAs            map[string]string   `yaml:"mark_as"`
	GlobalDBFile      string              `yaml:"global_db_file"`
	Permissions       map[string][]string `yaml:"permissions"`
}

type Config struct {
	Global GlobalConfig            `yaml:"global"`
	Repos  map[string]RepoConfig   `yaml:"repos"`
}

type ResolvedRepoConfig struct {
	Name        string
	DBFile      string
	SubjectTag  string
	IMAPMailbox string
	Reactions   map[string]string
	MarkAs      map[string]string
	Permissions map[string][]string
}

type EditRecord struct {
	Timestamp time.Time `json:"timestamp"`
	Body      string    `json:"body"`
}

type Reaction struct {
	Emoji  string `json:"emoji"`
	Author string `json:"author"`
}

type Comment struct {
	ID        int          `json:"id"`
	Author    string       `json:"author"`
	Body      string       `json:"body"`
	CreatedAt time.Time    `json:"createdAt"`
	Reactions []Reaction   `json:"reactions"`
	History   []EditRecord `json:"history,omitempty"`
}

type Issue struct {
	ID          int          `json:"id"`
	Title       string       `json:"title"`
	Author      string       `json:"author"`
	Body        string       `json:"body"`
	CreatedAt   time.Time    `json:"createdAt"`
	Comments    []Comment    `json:"comments"`
	Reactions   []Reaction   `json:"reactions"`
	History     []EditRecord `json:"history,omitempty"`
	IsClosed    bool         `json:"isClosed"`
	Status      string       `json:"status"`
	StatusClass string       `json:"statusClass"`
}

type RepoDatabase struct {
	Issues        map[int]*Issue      `json:"issues"`
	NextIssueID   int                 `json:"nextIssueId"`
	NextCommentID int                 `json:"nextCommentId"`
	ProcessedUIDs map[imap.UID]bool   `json:"processedUids"`
	RejectedUIDs  map[imap.UID]string `json:"rejectedUids,omitempty"`
	RepoName      string              `json:"repoName"`
	Reactions     map[string]string   `json:"reactions"`
	MarkAs        map[string]string   `json:"mark_as"`
	IssuesEmail   string              `json:"issuesEmail"`
	SubjectTag    string              `json:"subjectTag"`
	mu            sync.Mutex          `json:"-"`
}

type GlobalDatabase struct {
	Repos        map[string]*RepoDatabase `json:"repos"`
	AliasToEmail map[string]string        `json:"aliasToEmail"`
	EmailToAlias map[string]string        `json:"emailToAlias"`
	mu           sync.Mutex               `json:"-"`
}

// RejectionMail is an item in the queue for sending rejection emails.
type RejectionMail struct {
	To     string
	Reason string
	Cfg    *GlobalConfig
}

// RejectionResult is used to pass rejection data back from goroutines.
type RejectionResult struct {
	UID    imap.UID
	Reason string
}

func main() {
	var configPath string
	flag.BoolVar(&debug, "debug", false, "Enable verbose IMAP debug output to stderr")
	flag.StringVar(&configPath, "config", "pgitBot.yml", "Path to config.yml file")
	flag.Parse()

	log.Println("Starting pgitBot...")

	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	rejectionQueue := make(chan RejectionMail, 100)
	var appWg sync.WaitGroup
	appWg.Add(1)
	go rejectionSender(&appWg, rejectionQueue)

	var globalDB *GlobalDatabase
	if cfg.Global.GlobalDBFile != "" {
		globalDB, err = loadGlobalDatabase(cfg.Global.GlobalDBFile, &cfg.Global)
		if err != nil {
			log.Fatalf("Failed to load global database '%s': %v", cfg.Global.GlobalDBFile, err)
		}
		log.Printf("Global database enabled at '%s'", cfg.Global.GlobalDBFile)
	}

	c, err := connectIMAP(&cfg.Global)
	if err != nil {
		log.Fatalf("IMAP connection failed: %v", err)
	}
	defer func() {
		if err := c.Logout().Wait(); err != nil {
			log.Printf("Logout error: %v", err)
		}
	}()
	log.Println("Successfully connected to IMAP server.")

	for repoName, repoCfg := range cfg.Repos {
		log.Printf("--- Processing repository: %s ---", repoName)

		resolvedCfg := resolveRepoConfig(repoName, &cfg.Global, &repoCfg)

		var repoDB *RepoDatabase
		if resolvedCfg.DBFile != "" {
			repoDB, err = loadRepoDatabase(resolvedCfg.DBFile, &cfg.Global)
			if err != nil {
				log.Printf("ERROR: Could not load repo database for '%s', skipping: %v", repoName, err)
				continue
			}
		} else {
			log.Printf("Repo '%s' has no db_file, will process in-memory.", repoName)
			repoDB = newRepoDatabase()
		}

		repoDB.RepoName = resolvedCfg.Name
		repoDB.Reactions = resolvedCfg.Reactions
		repoDB.MarkAs = resolvedCfg.MarkAs
		repoDB.IssuesEmail = cfg.Global.SMTPFromAddr
		repoDB.SubjectTag = resolvedCfg.SubjectTag

		if err := processEmails(c, repoDB, &cfg.Global, &resolvedCfg, globalDB, rejectionQueue); err != nil {
			log.Printf("An error occurred during email processing for repo %s: %v", repoName, err)
		}

		if resolvedCfg.DBFile != "" {
			if err := saveRepoDatabase(resolvedCfg.DBFile, repoDB, &cfg.Global); err != nil {
				log.Printf("Failed to save database for repo %s: %v", repoName, err)
			}
		}

		if globalDB != nil && !repoCfg.ExcludeFromGlobal {
			log.Printf("Merging repo '%s' into global database.", repoName)
			globalDB.mu.Lock()
			dbCopy := *repoDB
			dbCopy.ProcessedUIDs = nil
			// Don't merge rejection history into the global DB.
			dbCopy.RejectedUIDs = nil
			globalDB.Repos[repoName] = &dbCopy
			globalDB.mu.Unlock()
		}

		if err := cleanupOldRejections(c, &resolvedCfg); err != nil {
			log.Printf("WARNING: Failed to clean up old rejection emails for repo %s: %v", repoName, err)
		}

		log.Printf("--- Finished processing repository: %s ---", repoName)
	}

	if globalDB != nil {
		if err := saveGlobalDatabase(cfg.Global.GlobalDBFile, globalDB, &cfg.Global); err != nil {
			log.Printf("FATAL: Failed to save global database: %v", err)
		}
	}

	log.Println("All repositories processed. Closing rejection queue...")
	close(rejectionQueue)
	appWg.Wait()

	log.Println("pgitBot finished.")
}

// processEnvVars finds placeholders like {{ env.VAR_NAME }} and replaces them
// with the corresponding environment variable's value.
func processEnvVars(data []byte) ([]byte, error) {
	re := regexp.MustCompile(`\{\{\s*env\.(\w+)\s*\}\}`)
	var firstError error

	processed := re.ReplaceAllStringFunc(string(data), func(match string) string {
		if firstError != nil {
			return "" // Stop processing if an error has occurred
		}

		varName := re.FindStringSubmatch(match)[1]
		value := os.Getenv(varName)

		if value == "" {
			firstError = fmt.Errorf("environment variable '%s' not set or is empty", varName)
			return ""
		}
		return value
	})

	if firstError != nil {
		return nil, firstError
	}

	return []byte(processed), nil
}

func loadConfig(configPath string) (*Config, error) {
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("Config file not found at '%s'. Creating a default one.", configPath)
		if err := createDefaultConfigAt(configPath); err != nil {
			return nil, fmt.Errorf("%w: %v", errConfigCreate, err)
		}
		log.Println("Please edit the default pgitBot.yml and restart the application.")
		os.Exit(1)
	}

	yamlFile, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read yaml file: %v", errConfigLoad, err)
	}

	// Pre-process the YAML to substitute environment variables
	processedYaml, err := processEnvVars(yamlFile)
	if err != nil {
		return nil, fmt.Errorf("%w: could not process environment variables in config: %v", errConfigLoad, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(processedYaml, &cfg); err != nil {
		return nil, fmt.Errorf("%w: could not unmarshal yaml: %v", errConfigLoad, err)
	}

	applyGlobalDefaults(&cfg.Global)
	return &cfg, nil
}

func applyGlobalDefaults(g *GlobalConfig) {
	if g.IMAPMailbox == "" {
		g.IMAPMailbox = "INBOX"
	}
	if g.SubjectTag == "" {
		g.SubjectTag = "[pgit]"
	}
	if g.Reactions == nil {
		g.Reactions = map[string]string{
			"thumbs-up": "👍", "thumbs-down": "👎", "laugh": "😄", "hooray": "🎉",
			"confused": "😕", "heart": "❤️", "rocket": "🚀", "eyes": "👀",
		}
	}
	if g.MarkAs == nil {
		g.MarkAs = map[string]string{
			"Open": "open", "In Progress": "in-progress", "Resolved": "resolved",
			"Not Planned": "not-planned", "Duplicate": "duplicate",
		}
	}
}

func resolveRepoConfig(name string, g *GlobalConfig, r *RepoConfig) ResolvedRepoConfig {
	resolved := ResolvedRepoConfig{
		Name:   name,
		DBFile: r.DBFile,
	}

	if r.SubjectTag != nil {
		resolved.SubjectTag = *r.SubjectTag
	} else {
		// Example: global [pgit], repo gbc -> [pgit-gbc]
		baseTag := strings.TrimSuffix(strings.TrimPrefix(g.SubjectTag, "["), "]")
		resolved.SubjectTag = fmt.Sprintf("[%s-%s]", baseTag, name)
	}

	if r.IMAPMailbox != nil {
		resolved.IMAPMailbox = *r.IMAPMailbox
	} else {
		resolved.IMAPMailbox = g.IMAPMailbox
	}

	if r.Reactions != nil {
		resolved.Reactions = r.Reactions
	} else {
		resolved.Reactions = g.Reactions
	}

	if r.MarkAs != nil {
		resolved.MarkAs = r.MarkAs
	} else {
		resolved.MarkAs = g.MarkAs
	}

	// Merge permissions. Repo-specific permissions override global ones.
	resolved.Permissions = make(map[string][]string)
	if g.Permissions != nil {
		for k, v := range g.Permissions {
			resolved.Permissions[k] = v
		}
	}
	if r.Permissions != nil {
		for k, v := range r.Permissions {
			resolved.Permissions[k] = v
		}
	}

	return resolved
}

func createDefaultConfigAt(path string) error {
	defaultConfig := `
global:
  imap_server: "imap.gmail.com:993"
  imap_username: "your-email@gmail.com"
  # Use environment variables for sensitive data.
  # Example: export IMAP_PASSWORD="your-app-password"
  imap_password: "{{ env.IMAP_PASSWORD }}"
  smtp_server: "smtp.gmail.com:587"
  smtp_username: "your-email@gmail.com"
  smtp_password: "{{ env.SMTP_PASSWORD }}"
  smtp_from_addr: "bot-sender@example.com"
  # smtp_from_alias: "PGIT Bot <alias@example.com>" # Optional
  # Generate a key with: openssl rand -hex 32
  db_encryption_key: "{{ env.DB_ENCRYPTION_KEY }}"
  disable_encryption: false
  subject_tag: "[pgit]"
  imap_mailbox: "INBOX"
  global_db_file: "pgit-global.json"
  reactions:
    lovebear: "ʕ♥ᴥ♥ʔ"
    smiley: "☺︎"
  mark_as:
    Open: "open"
    Closed: "closed"
  # Permissions block.
  # Rules are checked in order: exact email > wildcard domain > global wildcard "*".
  # If a permissions block is defined, any user not matching a rule is denied.
  # If this entire permissions block is removed, all users are allowed.
  permissions:
    "admin@example.com": ["all"]
    "user@example.com": ["create-issue", "add-comment", "react", "unreact", "edit", "mark-as"]
    "*@trusted-company.com": ["create-issue", "add-comment"]
    "spammer@domain.com": [] # Explicitly deny
    "*": ["react", "unreact"]

repos:
  # Tag will be [pgit-my-first-repo]
  my-first-repo:
    db_file: "repo1-issues.json"
  my-second-repo:
    db_file: "repo2-issues.json"
    subject_tag: "[repo2-custom]"
  my-secret-repo:
    db_file: "secret-issues.json"
    subject_tag: "[secret]"
    exclude_from_global: true
    permissions:
      "project-lead@example.com": ["all"]
      "*": [] # Only the project lead can act on this repo.
`
	return os.WriteFile(path, []byte(defaultConfig), 0600)
}

func connectIMAP(cfg *GlobalConfig) (*imapclient.Client, error) {
	options := &imapclient.Options{}
	if debug {
		log.Println("DEBUG mode enabled. Raw IMAP commands will be logged.")
		options.DebugWriter = os.Stderr
	}

	c, err := imapclient.DialTLS(cfg.IMAPServer, options)
	if err != nil {
		return nil, fmt.Errorf("failed to dial IMAP server: %w", err)
	}

	if err := c.Login(cfg.IMAPUsername, cfg.IMAPPassword).Wait(); err != nil {
		c.Logout().Wait()
		return nil, fmt.Errorf("failed to login: %w", err)
	}
	return c, nil
}

// processEmails fetches emails, processes their content in parallel, and then
// marks them as seen on the server.
func processEmails(c *imapclient.Client, db *RepoDatabase, globalCfg *GlobalConfig, repoCfg *ResolvedRepoConfig, globalDB *GlobalDatabase, rejectionQueue chan<- RejectionMail) error {
	selectCmd := c.Select(repoCfg.IMAPMailbox, nil)
	_, err := selectCmd.Wait()
	if err != nil {
		return fmt.Errorf("failed to select '%s' mailbox: %w", repoCfg.IMAPMailbox, err)
	}

	// Search for UNSEEN emails with the subject tag. This uses the IMAP server
	// as the source of truth, preventing reprocessing if the local DB is lost.
	searchCriteria := &imap.SearchCriteria{
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: repoCfg.SubjectTag},
		},
		NotFlag: []imap.Flag{imap.FlagSeen},
	}

	searchCmd := c.UIDSearch(searchCriteria, nil)
	searchData, err := searchCmd.Wait()
	if err != nil {
		return fmt.Errorf("email search failed: %w", err)
	}
	uids := searchData.AllUIDs()

	if len(uids) == 0 {
		log.Printf("No new (unseen) emails with subject tag '%s' found in '%s' mailbox.", repoCfg.SubjectTag, repoCfg.IMAPMailbox)
		return nil
	}

	var processingWg sync.WaitGroup
	processedUIDsChan := make(chan imap.UID, len(uids))
	rejectedUIDsChan := make(chan RejectionResult, len(uids))

	fetchOptions := &imap.FetchOptions{
		BodySection: []*imap.FetchItemBodySection{{}},
	}

	log.Printf("Found %d new emails to process for repo '%s'.", len(uids), repoCfg.Name)

	// Sequentially fetch emails to avoid overwhelming the IMAP server.
	for _, uid := range uids {
		// This local check is redundant due to the UNSEEN search, but kept as a safeguard.
		db.mu.Lock()
		_, isProcessed := db.ProcessedUIDs[uid]
		_, isRejected := db.RejectedUIDs[uid]
		db.mu.Unlock()

		if isProcessed || isRejected {
			continue
		}

		uidSet := imap.UIDSetNum(uid)
		fetchCmd := c.Fetch(uidSet, fetchOptions)
		msg := fetchCmd.Next()
		if msg == nil {
			fetchCmd.Close()
			log.Printf("UID %v: Fetch command returned no message data.", uid)
			continue
		}

		msgBuffer, err := msg.Collect()
		if err != nil {
			fetchCmd.Close()
			log.Printf("UID %v: Failed to collect message data: %v", uid, err)
			continue
		}
		fetchCmd.Close()

		bodyBytes := msgBuffer.FindBodySection(&imap.FetchItemBodySection{})
		if bodyBytes == nil {
			log.Printf("Could not find message body for UID %v, skipping.", uid)
			continue
		}

		processingWg.Add(1)
		go func(body []byte, currentUID imap.UID) {
			defer processingWg.Done()
			err := processSingleEmail(bytes.NewReader(body), db, globalCfg, repoCfg, globalDB, rejectionQueue)
			if err != nil {
				log.Printf("UID %v: Rejected. Reason: %v", currentUID, err)
				rejectedUIDsChan <- RejectionResult{UID: currentUID, Reason: err.Error()}
			} else {
				log.Printf("UID %v: Successfully processed for repo '%s' with tag '%s'.", currentUID, repoCfg.Name, repoCfg.SubjectTag)
				processedUIDsChan <- currentUID
			}
		}(bodyBytes, uid)
	}

	go func() {
		processingWg.Wait()
		close(processedUIDsChan)
		close(rejectedUIDsChan)
	}()

	var uidsToMarkSeen imap.UIDSet
	db.mu.Lock()
	for uid := range processedUIDsChan {
		db.ProcessedUIDs[uid] = true
		uidsToMarkSeen.AddNum(uid)
	}
	for rejection := range rejectedUIDsChan {
		db.RejectedUIDs[rejection.UID] = rejection.Reason
		uidsToMarkSeen.AddNum(rejection.UID)
	}
	db.mu.Unlock()

	if len(uidsToMarkSeen) > 0 {
		log.Printf("Marking %d emails as seen on server.", len(uidsToMarkSeen))
		storeCmd := c.Store(uidsToMarkSeen, &imap.StoreFlags{
			Op:     imap.StoreFlagsAdd,
			Silent: true,
			Flags:  []imap.Flag{imap.FlagSeen},
		}, nil)
		if err := storeCmd.Close(); err != nil {
			log.Printf("Failed to mark emails as seen on server: %v", err)
		}
	}

	return nil
}

func extractTextFromMIMEMessage(msg *mail.Message) (string, error) {
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		return "", fmt.Errorf("cannot parse Content-Type: %w", err)
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		mr := multipart.NewReader(msg.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", fmt.Errorf("error reading multipart body: %w", err)
			}
			partMediaType, _, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
			if err != nil {
				continue
			}
			if strings.HasPrefix(partMediaType, "text/plain") {
				bodyBytes, err := io.ReadAll(p)
				if err != nil {
					return "", fmt.Errorf("error reading part body: %w", err)
				}
				return string(bodyBytes), nil
			}
		}
		return "", errors.New("no text/plain part found in multipart message")
	} else if strings.HasPrefix(mediaType, "text/plain") {
		bodyBytes, err := io.ReadAll(msg.Body)
		if err != nil {
			return "", fmt.Errorf("error reading simple text body: %w", err)
		}
		return string(bodyBytes), nil
	}

	return "", fmt.Errorf("unsupported Content-Type: %s", mediaType)
}

func processSingleEmail(body io.Reader, db *RepoDatabase, globalCfg *GlobalConfig, repoCfg *ResolvedRepoConfig, globalDB *GlobalDatabase, rejectionQueue chan<- RejectionMail) error {
	msg, err := mail.ReadMessage(body)
	if err != nil {
		return fmt.Errorf("failed to parse email: %w", err)
	}

	fromAddr, err := mail.ParseAddress(msg.Header.Get("From"))
	if err != nil {
		fromAddr = &mail.Address{Address: "unknown@example.com"}
	}

	subject := msg.Header.Get("Subject")
	forwardPrefixes := []string{"Fwd:", "FW:", "fwd:", "fw:"}
	trimmedSubject := strings.TrimSpace(subject)
	for _, prefix := range forwardPrefixes {
		if strings.HasPrefix(trimmedSubject, prefix) {
			rejectionReason := "Forwarded emails are not processed."
			queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
			return errors.New(rejectionReason)
		}
	}

	plainTextBody, err := extractTextFromMIMEMessage(msg)
	if err != nil {
		rejectionReason := fmt.Sprintf("Failed to extract plain text content: %v. pgitBot only supports plain text emails.", err)
		queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
		return errors.New(rejectionReason)
	}

	mainBody, commandBlocks, err := parseCommandBlocks(plainTextBody)
	if err != nil {
		rejectionReason := fmt.Sprintf("Invalid command block: %v", err)
		queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
		return errors.New(rejectionReason)
	}

	if len(commandBlocks) == 0 {
		log.Println("No command blocks found in email, ignoring.")
		return nil
	}

	if len(commandBlocks) > 1 {
		rejectionReason := "Multiple command blocks found. Only one action per email is permitted."
		queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
		return errors.New(rejectionReason)
	}

	block := commandBlocks[0]
	for key, value := range block {
		if !isPrintable(key) || !isPrintable(value) {
			rejectionReason := "Commands contain non-visible or non-printable characters."
			queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
			return errors.New(rejectionReason)
		}
	}

	if err := executeCommand(block, mainBody, fromAddr.Address, db, repoCfg, globalDB); err != nil {
		rejectionReason := fmt.Sprintf("Command execution failed: %v", err)
		queueRejectionEmail(rejectionQueue, fromAddr.Address, rejectionReason, globalCfg)
		return err
	}

	return nil
}

func isPrintable(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func parseCommandBlocks(body string) (string, []map[string]string, error) {
	var blocks []map[string]string
	var mainBody strings.Builder
	scanner := bufio.NewScanner(strings.NewReader(body))
	var currentBlock map[string]string
	inBlock := false
	foundFirstBlock := false

	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)

		if trimmedLine == "---pgitBot---" {
			if !foundFirstBlock {
				foundFirstBlock = true
			}
			if inBlock {
				if currentBlock != nil {
					blocks = append(blocks, currentBlock)
				}
				inBlock = false
				currentBlock = nil
			} else {
				inBlock = true
				currentBlock = make(map[string]string)
			}
			continue
		}

		if inBlock && currentBlock != nil {
			parts := strings.SplitN(trimmedLine, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				currentBlock[key] = value
			}
		} else if !foundFirstBlock {
			mainBody.WriteString(line)
			mainBody.WriteString("\n")
		}
	}

	return strings.TrimSpace(mainBody.String()), blocks, scanner.Err()
}

// hasPermission checks if an author is allowed to execute a specific command.
// Rules are checked in order of specificity: exact email -> wildcard domain -> global wildcard "*".
// If the permissions map is defined but no rule matches, access is denied (default-deny).
// If the permissions map is nil or empty, access is granted (default-allow).
func hasPermission(author, command string, perms map[string][]string) bool {
	if len(perms) == 0 {
		return true // No rules defined, so allow all.
	}

	if allowedCmds, ok := perms[author]; ok {
		if len(allowedCmds) == 1 && allowedCmds[0] == "all" {
			return true
		}
		for _, cmd := range allowedCmds {
			if cmd == command {
				return true
			}
		}
		return false // Rule found, but command not in the allowed list.
	}

	parts := strings.Split(author, "@")
	if len(parts) == 2 {
		wildcardDomain := "*@" + parts[1]
		if allowedCmds, ok := perms[wildcardDomain]; ok {
			if len(allowedCmds) == 1 && allowedCmds[0] == "all" {
				return true
			}
			for _, cmd := range allowedCmds {
				if cmd == command {
					return true
				}
			}
			return false
		}
	}

	if allowedCmds, ok := perms["*"]; ok {
		if len(allowedCmds) == 1 && allowedCmds[0] == "all" {
			return true
		}
		for _, cmd := range allowedCmds {
			if cmd == command {
				return true
			}
		}
		return false
	}

	// No matching rule was found. Since a permissions block exists, deny access.
	return false
}

func executeCommand(cmd map[string]string, body, author string, db *RepoDatabase, repoCfg *ResolvedRepoConfig, globalDB *GlobalDatabase) error {
	command, ok := cmd["command"]
	if !ok {
		return errors.New("command block is missing 'command' key")
	}

	if !hasPermission(author, command, repoCfg.Permissions) {
		return fmt.Errorf("permission denied for user '%s' to execute command '%s'", author, command)
	}

	if command != "alias" && command != "unalias" {
		db.mu.Lock()
		defer db.mu.Unlock()
	}

	switch command {
	case "create-issue":
		title, ok := cmd["title"]
		if !ok || title == "" {
			return errors.New("create-issue requires a 'title'")
		}

		for _, issue := range db.Issues {
			if strings.EqualFold(issue.Title, title) {
				return fmt.Errorf("an issue with the title '%s' already exists (ID #%d)", title, issue.ID)
			}
		}

		newID := db.NextIssueID
		db.NextIssueID++
		db.Issues[newID] = &Issue{
			ID:          newID,
			Title:       title,
			Author:      author,
			Body:        body,
			CreatedAt:   time.Now(),
			Comments:    []Comment{},
			Reactions:   []Reaction{},
			IsClosed:    false,
			Status:      "Open",
			StatusClass: "open",
		}
		log.Printf("Created new issue #%d with title: %s", newID, title)

	case "add-comment":
		issueIDStr, ok := cmd["issue-id"]
		if !ok {
			return errors.New("add-comment requires 'issue-id'")
		}
		issueID, err := strconv.Atoi(issueIDStr)
		if err != nil {
			return fmt.Errorf("invalid 'issue-id' for add-comment: %s", issueIDStr)
		}
		issue, ok := db.Issues[issueID]
		if !ok {
			return fmt.Errorf("issue with ID %d not found", issueID)
		}
		newCommentID := db.NextCommentID
		db.NextCommentID++
		issue.Comments = append(issue.Comments, Comment{
			ID:        newCommentID,
			Author:    author,
			Body:      body,
			CreatedAt: time.Now(),
			Reactions: []Reaction{},
		})
		log.Printf("Added new comment #%d to issue #%d", newCommentID, issueID)

	case "edit":
		itemType, ok := cmd["type"]
		if !ok {
			return errors.New("edit command requires 'type'")
		}
		issueIDStr, ok := cmd["issue-id"]
		if !ok {
			return errors.New("edit command requires 'issue-id'")
		}
		issueID, err := strconv.Atoi(issueIDStr)
		if err != nil {
			return fmt.Errorf("invalid 'issue-id' for edit: %s", issueIDStr)
		}
		issue, ok := db.Issues[issueID]
		if !ok {
			return fmt.Errorf("issue with ID %d not found", issueID)
		}

		switch itemType {
		case "issue":
			if issue.Author != author {
				return fmt.Errorf("permission denied: user %s cannot edit issue by %s", author, issue.Author)
			}
			issue.History = append(issue.History, EditRecord{Timestamp: time.Now(), Body: issue.Body})
			issue.Body = body
			log.Printf("Edited issue #%d", issueID)
		case "comment":
			commentIDStr, ok := cmd["comment-id"]
			if !ok {
				return errors.New("editing a comment requires 'comment-id'")
			}
			commentID, err := strconv.Atoi(commentIDStr)
			if err != nil {
				return fmt.Errorf("invalid 'comment-id' for edit: %s", commentIDStr)
			}
			var targetComment *Comment
			for i := range issue.Comments {
				if issue.Comments[i].ID == commentID {
					targetComment = &issue.Comments[i]
					break
				}
			}
			if targetComment == nil {
				return fmt.Errorf("comment with ID %d not found in issue #%d", commentID, issueID)
			}
			if targetComment.Author != author {
				return fmt.Errorf("permission denied: user %s cannot edit comment by %s", author, targetComment.Author)
			}
			targetComment.History = append(targetComment.History, EditRecord{Timestamp: time.Now(), Body: targetComment.Body})
			targetComment.Body = body
			log.Printf("Edited comment #%d on issue #%d", commentID, issueID)
		default:
			return fmt.Errorf("unknown item type for edit: '%s'", itemType)
		}

	case "mark-as":
		issueIDStr, ok := cmd["issue-id"]
		if !ok {
			return errors.New("mark-as requires 'issue-id'")
		}
		statusName, ok := cmd["status"]
		if !ok {
			return errors.New("mark-as requires 'status'")
		}
		issueID, err := strconv.Atoi(issueIDStr)
		if err != nil {
			return fmt.Errorf("invalid 'issue-id' for mark-as: %s", issueIDStr)
		}
		className, ok := repoCfg.MarkAs[statusName]
		if !ok {
			return fmt.Errorf("unknown status: '%s'. check config.yml", statusName)
		}
		issue, ok := db.Issues[issueID]
		if !ok {
			return fmt.Errorf("issue with ID %d not found", issueID)
		}
		issue.Status = statusName
		issue.StatusClass = className
		if className == "resolved" || className == "not-planned" || className == "closed" {
			issue.IsClosed = true
		} else {
			issue.IsClosed = false
		}
		log.Printf("Marked issue #%d as %s", issueID, statusName)

	case "react":
		itemType, ok := cmd["type"]
		if !ok {
			return errors.New("react command requires 'type' (issue or comment)")
		}
		reactionName, ok := cmd["reaction"]
		if !ok {
			return errors.New("react command requires 'reaction'")
		}
		emoji, ok := repoCfg.Reactions[reactionName]
		if !ok {
			return fmt.Errorf("unknown reaction: '%s'", reactionName)
		}
		issueIDStr, ok := cmd["issue-id"]
		if !ok {
			return errors.New("react command requires 'issue-id'")
		}
		issueID, err := strconv.Atoi(issueIDStr)
		if err != nil {
			return fmt.Errorf("invalid 'issue-id' for react: %s", issueIDStr)
		}
		issue, ok := db.Issues[issueID]
		if !ok {
			return fmt.Errorf("issue with ID %d not found", issueID)
		}

		switch itemType {
		case "issue":
			issue.Reactions = append(issue.Reactions, Reaction{Emoji: emoji, Author: author})
			log.Printf("Added reaction '%s' to issue #%d", emoji, issueID)
		case "comment":
			commentIDStr, ok := cmd["comment-id"]
			if !ok {
				return errors.New("reacting to a comment requires 'comment-id'")
			}
			commentID, err := strconv.Atoi(commentIDStr)
			if err != nil {
				return fmt.Errorf("invalid 'comment-id' for react: %s", commentIDStr)
			}
			var targetComment *Comment
			for i := range issue.Comments {
				if issue.Comments[i].ID == commentID {
					targetComment = &issue.Comments[i]
					break
				}
			}
			if targetComment == nil {
				return fmt.Errorf("comment with ID %d not found in issue #%d", commentID, issueID)
			}
			targetComment.Reactions = append(targetComment.Reactions, Reaction{Emoji: emoji, Author: author})
			log.Printf("Added reaction '%s' to comment #%d on issue #%d", emoji, commentID, issueID)
		default:
			return fmt.Errorf("unknown item type for reaction: '%s'", itemType)
		}

	case "unreact":
		itemType, ok := cmd["type"]
		if !ok {
			return errors.New("unreact command requires 'type'")
		}
		reactionName, ok := cmd["reaction"]
		if !ok {
			return errors.New("unreact command requires 'reaction'")
		}
		emoji, ok := repoCfg.Reactions[reactionName]
		if !ok {
			return fmt.Errorf("unknown reaction: '%s'", reactionName)
		}
		issueIDStr, ok := cmd["issue-id"]
		if !ok {
			return errors.New("unreact command requires 'issue-id'")
		}
		issueID, err := strconv.Atoi(issueIDStr)
		if err != nil {
			return fmt.Errorf("invalid 'issue-id' for unreact: %s", issueIDStr)
		}
		issue, ok := db.Issues[issueID]
		if !ok {
			return fmt.Errorf("issue with ID %d not found", issueID)
		}

		var reactions *[]Reaction
		var itemName string

		switch itemType {
		case "issue":
			reactions = &issue.Reactions
			itemName = fmt.Sprintf("issue #%d", issueID)
		case "comment":
			commentIDStr, ok := cmd["comment-id"]
			if !ok {
				return errors.New("unreacting to a comment requires 'comment-id'")
			}
			commentID, err := strconv.Atoi(commentIDStr)
			if err != nil {
				return fmt.Errorf("invalid 'comment-id' for unreact: %s", commentIDStr)
			}
			var targetComment *Comment
			for i := range issue.Comments {
				if issue.Comments[i].ID == commentID {
					targetComment = &issue.Comments[i]
					break
				}
			}
			if targetComment == nil {
				return fmt.Errorf("comment with ID %d not found in issue #%d", commentID, issueID)
			}
			reactions = &targetComment.Reactions
			itemName = fmt.Sprintf("comment #%d on issue #%d", commentID, issueID)
		default:
			return fmt.Errorf("unknown item type for unreaction: '%s'", itemType)
		}

		found := false
		var updatedReactions []Reaction
		for _, r := range *reactions {
			if r.Emoji == emoji && r.Author == author && !found {
				found = true
				continue
			}
			updatedReactions = append(updatedReactions, r)
		}

		if !found {
			return fmt.Errorf("reaction '%s' by '%s' not found on %s", emoji, author, itemName)
		}

		*reactions = updatedReactions
		log.Printf("Removed reaction '%s' by '%s' from %s", emoji, author, itemName)

	case "alias":
		if globalDB == nil {
			return errors.New("alias command requires a global database, but it's not configured")
		}
		alias, ok := cmd["alias"]
		if !ok || alias == "" {
			return errors.New("alias command requires a non-empty 'alias'")
		}

		globalDB.mu.Lock()
		defer globalDB.mu.Unlock()

		if ownerEmail, exists := globalDB.AliasToEmail[alias]; exists && ownerEmail != author {
			return fmt.Errorf("alias '%s' is already in use", alias)
		}
		if oldAlias, exists := globalDB.EmailToAlias[author]; exists {
			delete(globalDB.AliasToEmail, oldAlias)
		}
		globalDB.AliasToEmail[alias] = author
		globalDB.EmailToAlias[author] = alias
		log.Printf("Set alias for '%s' to '%s'", author, alias)

	case "unalias":
		if globalDB == nil {
			return errors.New("unalias command requires a global database, but it's not configured")
		}
		globalDB.mu.Lock()
		defer globalDB.mu.Unlock()

		if oldAlias, exists := globalDB.EmailToAlias[author]; exists {
			delete(globalDB.AliasToEmail, oldAlias)
			delete(globalDB.EmailToAlias, author)
			log.Printf("Removed alias '%s' for '%s'", oldAlias, author)
		} else {
			log.Printf("User '%s' had no alias to remove", author)
		}

	default:
		return fmt.Errorf("unknown command: %s", command)
	}

	return nil
}

// queueRejectionEmail sends a rejection mail request to a channel for sequential processing.
func queueRejectionEmail(queue chan<- RejectionMail, to, reason string, cfg *GlobalConfig) {
	select {
	case queue <- RejectionMail{To: to, Reason: reason, Cfg: cfg}:
		log.Printf("Queued rejection email for %s", to)
	default:
		// This case is hit if the channel buffer is full.
		log.Printf("WARNING: Rejection email queue is full. Dropping rejection for %s", to)
	}
}

// rejectionSender runs in its own goroutine, processing the rejection queue sequentially.
func rejectionSender(wg *sync.WaitGroup, queue <-chan RejectionMail) {
	defer wg.Done()
	log.Println("Rejection email sender goroutine started.")

	for mail := range queue {
		cfg := mail.Cfg

		from := cfg.SMTPFromAddr
		if cfg.SMTPFromAlias != nil && *cfg.SMTPFromAlias != "" {
			from = *cfg.SMTPFromAlias
		}

		// Add a specific tag to the subject for easier filtering and cleanup later.
		subject := "Subject: [pgitBot-rejection] Your submission was rejected\r\n"
		headers := "From: " + from + "\r\n" +
			"To: " + mail.To + "\r\n" +
			subject

		body := "Your email to pgitBot was rejected for the following reason:\r\n\r\n" +
			mail.Reason + "\r\n\r\n" +
			"Please ensure your emails are plain text and that commands only contain visible characters.\r\n"

		message := []byte(headers + "\r\n" + body)

		// The 'from' argument to smtp.SendMail must be the authentication user.
		auth := smtp.PlainAuth("", cfg.SMTPUsername, cfg.SMTPPassword, strings.Split(cfg.SMTPServer, ":")[0])
		err := smtp.SendMail(cfg.SMTPServer, auth, cfg.SMTPFromAddr, []string{mail.To}, message)

		if err != nil {
			log.Printf("Failed to send rejection email to %s: %v", mail.To, err)
		} else {
			log.Printf("Successfully sent rejection email to %s", mail.To)
		}
		// Add a small delay between sends to avoid being rate-limited or marked as spam.
		time.Sleep(2 * time.Second)
	}

	log.Println("Rejection email sender goroutine finished.")
}

func cleanupOldRejections(c *imapclient.Client, repoCfg *ResolvedRepoConfig) error {
	log.Println("Checking for old rejection emails to clean up...")

	selectCmd := c.Select(repoCfg.IMAPMailbox, nil)
	if _, err := selectCmd.Wait(); err != nil {
		return fmt.Errorf("failed to select mailbox for cleanup: %w", err)
	}

	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	searchCriteria := &imap.SearchCriteria{
		Flag: []imap.Flag{imap.FlagSeen},
		Header: []imap.SearchCriteriaHeaderField{
			{Key: "Subject", Value: "[pgitBot-rejection]"},
		},
		SentBefore: thirtyDaysAgo,
	}

	searchCmd := c.UIDSearch(searchCriteria, nil)
	searchData, err := searchCmd.Wait()
	if err != nil {
		return fmt.Errorf("failed to search for old rejections: %w", err)
	}
	uidsToDelete := searchData.AllUIDs()

	if len(uidsToDelete) == 0 {
		log.Println("No old rejection emails to delete.")
		return nil
	}

	log.Printf("Found %d old rejection emails to delete.", len(uidsToDelete))

	var uidSet imap.UIDSet
	for _, uid := range uidsToDelete {
		uidSet.AddNum(uid)
	}

	storeCmd := c.Store(uidSet, &imap.StoreFlags{
		Op:     imap.StoreFlagsAdd,
		Silent: true,
		Flags:  []imap.Flag{imap.FlagDeleted},
	}, nil)
	if err := storeCmd.Close(); err != nil {
		return fmt.Errorf("failed to mark old rejections for deletion: %w", err)
	}

	if expungeCmd := c.Expunge(); expungeCmd != nil {
		if err := expungeCmd.Close(); err != nil {
			// Not a fatal error, as some servers might auto-expunge.
			log.Printf("Warning: failed to expunge old rejections: %v", err)
		}
	}

	log.Printf("Successfully marked %d old rejection emails for deletion.", len(uidsToDelete))
	return nil
}

func newRepoDatabase() *RepoDatabase {
	return &RepoDatabase{
		Issues:        make(map[int]*Issue),
		NextIssueID:   1,
		NextCommentID: 1,
		ProcessedUIDs: make(map[imap.UID]bool),
		RejectedUIDs:  make(map[imap.UID]string),
		Reactions:     make(map[string]string),
		MarkAs:        make(map[string]string),
	}
}

func loadRepoDatabase(filename string, globalCfg *GlobalConfig) (*RepoDatabase, error) {
	db := newRepoDatabase()

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("Database file '%s' not found, creating a new one.", filename)
		return db, nil
	}

	jsonData, err := readAndDecryptFile(filename, globalCfg)
	if err != nil {
		return nil, err
	}

	if len(jsonData) == 0 {
		log.Printf("Database file '%s' is empty, starting fresh.", filename)
		return db, nil
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if err := json.Unmarshal(jsonData, db); err != nil {
		return nil, fmt.Errorf("could not unmarshal repo db json: %w. Check for corruption or encryption mismatch", err)
	}
	if db.ProcessedUIDs == nil {
		db.ProcessedUIDs = make(map[imap.UID]bool)
	}
	if db.RejectedUIDs == nil {
		db.RejectedUIDs = make(map[imap.UID]string)
	}
	log.Printf("Loaded repo database '%s' with %d issues, %d processed UIDs, and %d rejected UIDs.", filename, len(db.Issues), len(db.ProcessedUIDs), len(db.RejectedUIDs))
	return db, nil
}

func saveRepoDatabase(filename string, db *RepoDatabase, globalCfg *GlobalConfig) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal repo db to json: %w", err)
	}

	if err := encryptAndWriteFile(filename, data, globalCfg); err != nil {
		return err
	}
	log.Printf("Successfully saved repo database to '%s'.", filename)
	return nil
}

func loadGlobalDatabase(filename string, globalCfg *GlobalConfig) (*GlobalDatabase, error) {
	db := &GlobalDatabase{
		Repos:        make(map[string]*RepoDatabase),
		AliasToEmail: make(map[string]string),
		EmailToAlias: make(map[string]string),
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		log.Printf("Global database file '%s' not found, creating a new one.", filename)
		return db, nil
	}

	jsonData, err := readAndDecryptFile(filename, globalCfg)
	if err != nil {
		return nil, err
	}

	if len(jsonData) == 0 {
		log.Printf("Global database file '%s' is empty, starting fresh.", filename)
		return db, nil
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if err := json.Unmarshal(jsonData, db); err != nil {
		return nil, fmt.Errorf("could not unmarshal global db json: %w. Check for corruption or encryption mismatch", err)
	}

	if db.Repos == nil {
		db.Repos = make(map[string]*RepoDatabase)
	}
	if db.AliasToEmail == nil {
		db.AliasToEmail = make(map[string]string)
	}
	if db.EmailToAlias == nil {
		db.EmailToAlias = make(map[string]string)
	}

	for _, repoDB := range db.Repos {
		if repoDB.ProcessedUIDs == nil {
			repoDB.ProcessedUIDs = make(map[imap.UID]bool)
		}
		if repoDB.RejectedUIDs == nil {
			repoDB.RejectedUIDs = make(map[imap.UID]string)
		}
	}

	log.Printf("Loaded global database '%s' with %d repositories and %d aliases.", filename, len(db.Repos), len(db.EmailToAlias))
	return db, nil
}

func saveGlobalDatabase(filename string, db *GlobalDatabase, globalCfg *GlobalConfig) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return fmt.Errorf("could not marshal global db to json: %w", err)
	}

	if err := encryptAndWriteFile(filename, data, globalCfg); err != nil {
		return err
	}
	log.Printf("Successfully saved global database to '%s'.", filename)
	return nil
}

func readAndDecryptFile(filename string, globalCfg *GlobalConfig) ([]byte, error) {
	fileData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("could not read file '%s': %w", filename, err)
	}
	if len(fileData) == 0 {
		return nil, nil // Empty file is valid
	}

	shouldDecrypt := !globalCfg.DisableEncryption && globalCfg.DBEncryptionKey != ""
	if !shouldDecrypt {
		return fileData, nil
	}

	decryptedData, err := decrypt(fileData, globalCfg.DBEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt '%s': %w. If not encrypted, ensure 'db_encryption_key' is empty or 'disable_encryption: true'", filename, err)
	}
	return decryptedData, nil
}

func encryptAndWriteFile(filename string, data []byte, globalCfg *GlobalConfig) error {
	shouldEncrypt := !globalCfg.DisableEncryption && globalCfg.DBEncryptionKey != ""
	var outputData []byte

	if shouldEncrypt {
		encryptedData, err := encrypt(data, globalCfg.DBEncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt data for '%s': %w", filename, err)
		}
		outputData = encryptedData
	} else {
		outputData = data
	}

	dir := filepath.Dir(filename)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("could not create directory for '%s': %w", filename, err)
		}
	}

	if err := os.WriteFile(filename, outputData, 0600); err != nil {
		return fmt.Errorf("could not write file '%s': %w", filename, err)
	}
	return nil
}

func encrypt(plaintext []byte, hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode hex key: %v", errDBEncrypt, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes for AES-256", errDBEncrypt)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decrypt(ciphertext []byte, hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode hex key: %v", errDBDecrypt, err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: key must be 32 bytes for AES-256", errDBDecrypt)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("%w: ciphertext too short", errDBDecrypt)
	}

	nonce, ciphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
