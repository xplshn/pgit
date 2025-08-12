//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/dustin/go-humanize"
	"github.com/gogs/git-module"
	"github.com/urfave/cli/v3"
	"github.com/xplshn/tracerr2"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	gmdhtml "github.com/yuin/goldmark/renderer/html"
	"gopkg.in/yaml.v3"
)

//go:embed html/*.tmpl
var embedFS embed.FS

//go:embed static/*
var staticFS embed.FS

var md = goldmark.New(
	goldmark.WithExtensions(extension.GFM),
	goldmark.WithParserOptions(
		parser.WithAutoHeadingID(),
	),
	goldmark.WithRendererOptions(
		gmdhtml.WithHardWraps(),
		gmdhtml.WithXHTML(),
		gmdhtml.WithUnsafe(),
	),
)

// Structs
type GitAttribute struct {
	Pattern    string
	Attributes map[string]string
}

type RepoConfig struct {
	Outdir             string `yaml:"out"`
	RepoPath           string `yaml:"repo"`
	Revs               []string `yaml:"revs"`
	Desc               string `yaml:"desc"`
	MaxCommits         int    `yaml:"max-commits"`
	Readme             string `yaml:"readme"`
	HideTreeLastCommit bool   `yaml:"hide-tree-last-commit"`
	HomeURL            string `yaml:"home-url"`
	CloneURL           string `yaml:"clone-url"`
	RootRelative       string `yaml:"root-relative"`
	ThemeName          string `yaml:"theme"`
	Label              string `yaml:"label"`
	RenderMarkdown     *bool  `yaml:"renderMarkdown"`
	Cache              sync.Map
	RepoName           string
	Logger             *slog.Logger
	ChromaTheme        *chroma.Style
	Formatter          *html.Formatter
	GitAttributes      []GitAttribute
	Whitelist          map[string]bool `yaml:"-"`
	Blacklist          map[string]bool `yaml:"-"`
}

type RevInfo interface {
	ID() string
	Name() string
}

type RevData struct {
	id     string
	name   string
	Config *RepoConfig
}

func (r *RevData) ID() string   { return r.id }
func (r *RevData) Name() string { return r.name }
func (r *RevData) TreeURL() template.URL { return r.Config.getTreeURL(r) }
func (r *RevData) LogURL() template.URL  { return r.Config.getLogsURL(r) }

type CommitData struct {
	SummaryStr string
	URL        template.URL
	WhenStr    string
	AuthorStr  string
	ShortID    string
	ParentID   string
	Refs       []*RefInfo
	*git.Commit
}

type TreeItem struct {
	IsTextFile bool
	IsDir      bool
	Size       string
	NumLines   int
	Name       string
	Icon       string
	Path       string
	Language   string
	URL        template.URL
	CommitID   string
	CommitURL  template.URL
	Summary    string
	When       string
	Author     *git.Signature
	Entry      *git.TreeEntry
	Crumbs     []*Breadcrumb
}

type DiffRender struct {
	NumFiles       int
	TotalAdditions int
	TotalDeletions int
	Files          []*DiffRenderFile
}

type DiffRenderFile struct {
	FileType     string
	OldMode      git.EntryMode
	OldName      string
	Mode         git.EntryMode
	Name         string
	Content      template.HTML
	NumAdditions int
	NumDeletions int
}

type RefInfo struct {
	ID      string       `json:"ID"`
	Refspec string       `json:"Refspec"`
	URL     template.URL `json:"URL,omitempty"`
}

type SearchIndexEntry struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	URL      string `json:"url"`
	Language string `json:"language"`
}

type SiteURLs struct {
	HomeURL    template.URL
	CloneURL   template.URL
	SummaryURL template.URL
	RefsURL    template.URL
	SearchURL  template.URL
}

type PageData struct {
	Repo     *RepoConfig
	SiteURLs *SiteURLs
	RevData  *RevData
}

type SummaryPageData struct {
	*PageData
	Readme        template.HTML
	LanguageStats []*LanguageStat
	TotalLanguage int64
}

type LanguageStat struct {
	Name       string
	Percentage float64
	Color      string
	URL        template.URL
}

type LanguagePageData struct {
	*PageData
	Language string
	Files    []*SearchIndexEntry
}

type TreePageData struct {
	*PageData
	Tree *TreeRoot
}

type LogPageData struct {
	*PageData
	NumCommits int
	Logs       []*CommitData
}

type FilePageData struct {
	*PageData
	Contents template.HTML
	Item     *TreeItem
	Language string
}

type CommitPageData struct {
	*PageData
	CommitMsg template.HTML
	CommitID  string
	Commit    *CommitData
	Diff      *DiffRender
	Parent    string
	ParentURL template.URL
	CommitURL template.URL
}

type RefPageData struct {
	*PageData
	Refs []*RefInfo
}

type WriteData struct {
	Template string
	Filename string
	Subdir   string
	Data     any
}

// Helper Functions
func (c *RepoConfig) getFileAttributes(filename string) map[string]string {
	var lastMatch *GitAttribute

	for i := range c.GitAttributes {
		attr := &c.GitAttributes[i]
		pattern := attr.Pattern
		matched := false

		// Handle **/<pattern> by matching against the base name.
		// This is a simplification but covers the most common use case.
		if strings.HasPrefix(pattern, "**/") {
			suffixPattern := strings.TrimPrefix(pattern, "**/")
			if m, _ := filepath.Match(suffixPattern, filepath.Base(filename)); m {
				matched = true
			}
		} else {
			// Standard glob matching against the full path.
			if m, _ := filepath.Match(pattern, filename); m {
				matched = true
			}
		}

		if matched {
			// Keep overwriting with the last match found, as this is how .gitattributes works.
			lastMatch = attr
		}
	}

	if lastMatch != nil {
		return lastMatch.Attributes
	}

	return nil
}

func (c *RepoConfig) getLanguageInfo(filename string, data []byte) (displayName string, lexer chroma.Lexer, isText bool) {
	attrs := c.getFileAttributes(filename)
	langOverride := attrs["linguist-language"]
	displayOverride := attrs["linguist-display-name"]

	lexerNameForLookup := ""

	// An explicit language override in .gitattributes is the highest priority for lexer selection.
	if langOverride != "" {
		lexerNameForLookup = langOverride
	} else {
		// If no override, proceed with detection.
		detectedLexer := lexers.Match(filename)
		if detectedLexer == nil && len(data) > 0 {
			detectedLexer = lexers.Analyse(string(data))
		}
		if detectedLexer != nil {
			lexerName := detectedLexer.Config().Name
			// Apply blacklist/whitelist to detected languages.
			isWhitelisted := c.Whitelist == nil || c.Whitelist[lexerName]
			isBlacklisted := c.Blacklist != nil && c.Blacklist[lexerName]
			if isWhitelisted && !isBlacklisted {
				lexerNameForLookup = lexerName
			}
		}
	}

	if lexerNameForLookup != "" {
		lexer = lexers.Get(lexerNameForLookup)
	}

	// Determine the display name. `linguist-display-name` has the highest priority.
	if displayOverride != "" {
		displayName = displayOverride
	} else if lexer != nil {
		displayName = lexer.Config().Name
	} else if langOverride != "" {
		// Fallback for unknown languages specified in .gitattributes
		displayName = langOverride
	}

	// Determine file type and set final fallbacks.
	if data != nil && bytes.Contains(data, []byte{0}) {
		isText = false
		if displayName == "" {
			displayName = "Binary"
		}
	} else {
		isText = true
		if lexer == nil {
			lexer = lexers.Get("plaintext")
		}
		if displayName == "" {
			displayName = "Text"
		}
	}
	return
}

func (c *RepoConfig) highlightSyntax(text, filename string, blob *git.Blob) (template.HTML, string, error) {
	if blob != nil && blob.Size() > 800*1024 {
		return "file too large to display (>800KB)", "Binary", nil
	}

	displayName, lexer, isText := c.getLanguageInfo(filename, []byte(text))
	if !isText {
		return "binary file, cannot display", "Binary", nil
	}

	iterator, err := lexer.Tokenise(nil, text)
	if err != nil {
		return template.HTML(text), displayName, tracerr.Errorf("tokenization failed: %w", err)
	}

	var buf bytes.Buffer
	if err := c.Formatter.Format(&buf, c.ChromaTheme, iterator); err != nil {
		return template.HTML(text), displayName, tracerr.Errorf("formatting failed: %w", err)
	}
	return template.HTML(buf.String()), displayName, nil
}

func diffFileType(t git.DiffFileType) string {
	switch t {
	case git.DiffFileAdd:
		return "A"
	case git.DiffFileChange:
		return "M"
	case git.DiffFileDelete:
		return "D"
	case git.DiffFileRename:
		return "R"
	default:
		return ""
	}
}

func toPretty(b int64) string { return humanize.Bytes(uint64(b)) }
func repoName(root string) string { return filepath.Base(root) }
func readmeFile(repo *RepoConfig) string {
	if repo.Readme == "" {
		return "readme.md"
	}
	return strings.ToLower(repo.Readme)
}

// File Writing
func (c *RepoConfig) executeTemplate(w *os.File, data *WriteData) error {
	ts, err := template.ParseFS(embedFS, data.Template, "html/*.partial.tmpl", "html/base.layout.tmpl")
	if err != nil {
		return tracerr.Errorf("failed to parse template %s: %w", data.Template, err)
	}
	return ts.Execute(w, data.Data)
}

func (c *RepoConfig) writeHTML(data *WriteData) error {
	dir := filepath.Join(c.Outdir, data.Subdir)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return tracerr.Errorf("failed to create directory %s: %w", dir, err)
	}

	fp := filepath.Join(dir, data.Filename)
	c.Logger.Info("writing", "filepath", fp)

	w, err := os.Create(fp)
	if err != nil {
		return tracerr.Errorf("failed to create file %s: %w", fp, err)
	}
	defer w.Close()

	if err := c.executeTemplate(w, data); err != nil {
		c.Logger.Error("failed to execute template", "filepath", fp, "error", err)
		return err
	}
	return nil
}

func (c *RepoConfig) copyStaticFiles() error {
	files, err := staticFS.ReadDir("static")
	if err != nil {
		return tracerr.Errorf("failed to read static dir: %w", err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		srcPath := filepath.Join("static", file.Name())
		destPath := filepath.Join(c.Outdir, file.Name())
		content, err := staticFS.ReadFile(srcPath)
		if err != nil {
			return tracerr.Errorf("failed to read static file %s: %w", srcPath, err)
		}
		c.Logger.Info("writing static file", "filepath", destPath)
		if err := os.WriteFile(destPath, content, 0644); err != nil {
			return tracerr.Errorf("failed to write static file %s: %w", destPath, err)
		}
	}
	return nil
}

func (c *RepoConfig) writePage(template, filename, subdir string, data any) {
	if err := c.writeHTML(&WriteData{template, filename, subdir, data}); err != nil {
		c.Logger.Error("failed to write page", "template", template, "error", err)
	}
}

func (c *RepoConfig) writeRootSummary(data *PageData, readme template.HTML, langStats []*LanguageStat, totalSize int64) {
	c.Logger.Info("writing root summary", "repoPath", c.RepoPath)
	pageData := &SummaryPageData{
		PageData:      data,
		Readme:        readme,
		LanguageStats: langStats,
		TotalLanguage: totalSize,
	}
	c.writePage("html/summary.page.tmpl", "index.html", "", pageData)
}

func (c *RepoConfig) writeTree(data *PageData, tree *TreeRoot) {
	c.Logger.Info("writing tree", "treePath", tree.Path)
	c.writePage("html/tree.page.tmpl", "index.html", tree.Path, &TreePageData{data, tree})
}

func (c *RepoConfig) writeLog(data *PageData, logs []*CommitData) {
	c.Logger.Info("writing log file", "revision", data.RevData.Name())
	c.writePage("html/log.page.tmpl", "index.html", getLogBaseDir(data.RevData), &LogPageData{data, len(logs), logs})
}

func (c *RepoConfig) writeRefs(data *PageData, refs []*RefInfo) {
	c.Logger.Info("writing refs", "repoPath", c.RepoPath)
	c.writePage("html/refs.page.tmpl", "refs.html", "", &RefPageData{data, refs})

	jsonData, err := json.MarshalIndent(refs, "", "  ")
	if err != nil {
		c.Logger.Error("failed to marshal refs to json", "error", err)
		return
	}
	fp := filepath.Join(c.Outdir, "refs.json")
	if err := os.WriteFile(fp, jsonData, 0644); err != nil {
		c.Logger.Error("failed to write refs.json", "error", err)
	}
}

func (c *RepoConfig) writeSearchIndex(searchIndex []*SearchIndexEntry) {
	c.Logger.Info("writing search index")
	jsonData, err := json.Marshal(searchIndex)
	if err != nil {
		c.Logger.Error("failed to marshal search index", "error", err)
		return
	}
	fp := filepath.Join(c.Outdir, "search-index.json")
	if err := os.WriteFile(fp, jsonData, 0644); err != nil {
		c.Logger.Error("failed to write search-index.json", "error", err)
	}
}

func (c *RepoConfig) writeLanguagePage(pageData *PageData, lang string, files []*SearchIndexEntry) {
	c.Logger.Info("writing language page", "language", lang)
	data := &LanguagePageData{
		PageData: pageData,
		Language: lang,
		Files:    files,
	}
	c.writePage("html/language.page.tmpl", fmt.Sprintf("lang-%s.html", lang), "", data)
}

func (c *RepoConfig) writeSearchPage(pageData *PageData) {
	c.Logger.Info("writing search page")
	c.writePage("html/search.page.tmpl", "search.html", "", pageData)
}

func (c *RepoConfig) writeHTMLTreeFile(pageData *PageData, treeItem *TreeItem) (string, string, int64, error) {
	b, err := treeItem.Entry.Blob().Bytes()
	if err != nil {
		return "", "", 0, tracerr.Errorf("failed to get blob bytes for %s: %w", treeItem.Path, err)
	}

	var contentsHTML template.HTML
	displayName := ""
	isMarkdown := (strings.HasSuffix(treeItem.Entry.Name(), ".md") || strings.HasSuffix(treeItem.Entry.Name(), ".markdown"))

	if isMarkdown && *pageData.Repo.RenderMarkdown {
		var buf bytes.Buffer
		if err := md.Convert(b, &buf); err != nil {
			c.Logger.Error("failed to render markdown", "file", treeItem.Entry.Name(), "error", err)
			contentsHTML = template.HTML("Failed to render markdown")
		} else {
			contentsHTML = template.HTML(buf.String())
		}
		displayName = "Markdown"
	} else {
		contentsHTML, displayName, err = c.highlightSyntax(string(b), treeItem.Path, treeItem.Entry.Blob())
		if err != nil {
			c.Logger.Error("failed to highlight syntax", "file", treeItem.Entry.Name(), "error", err)
		}
	}

	treeItem.Language = displayName
	treeItem.IsTextFile = displayName != "Binary"
	if treeItem.IsTextFile {
		treeItem.NumLines = len(strings.Split(string(b), "\n"))
	}

	d := filepath.Dir(treeItem.Path)
	readme := ""
	if d == "." && strings.EqualFold(treeItem.Entry.Name(), readmeFile(pageData.Repo)) {
		readme = string(contentsHTML)
	}

	c.writePage("html/file.page.tmpl", fmt.Sprintf("%s.html", treeItem.Entry.Name()), getFileDir(pageData.RevData, d), &FilePageData{
		PageData: pageData,
		Contents: contentsHTML,
		Item:     treeItem,
		Language: displayName,
	})

	return readme, displayName, treeItem.Entry.Size(), nil
}

func (c *RepoConfig) writeLogDiff(repo *git.Repository, pageData *PageData, commit *CommitData) {
	commitID := commit.ID.String()
	if _, loaded := c.Cache.LoadOrStore(commitID, true); loaded {
		return
	}

	diff, err := repo.Diff(commitID, 0, 0, 0, git.DiffOptions{})
	if err != nil {
		c.Logger.Error("failed to generate diff", "commitID", getShortID(commitID), "error", err)
		return
	}

	rnd := &DiffRender{
		NumFiles:       diff.NumFiles(),
		TotalAdditions: diff.TotalAdditions(),
		TotalDeletions: diff.TotalDeletions(),
	}
	for _, file := range diff.Files {
		var contentBuilder strings.Builder
		for _, section := range file.Sections {
			for _, line := range section.Lines {
				contentBuilder.WriteString(line.Content)
				contentBuilder.WriteByte('\n')
			}
		}
		finContent, _, _ := c.highlightSyntax(contentBuilder.String(), "commit.diff", nil)

		rnd.Files = append(rnd.Files, &DiffRenderFile{
			FileType:     diffFileType(file.Type),
			OldMode:      file.OldMode(),
			OldName:      file.OldName(),
			Mode:         file.Mode(),
			Name:         file.Name,
			NumAdditions: file.NumAdditions(),
			NumDeletions: file.NumDeletions(),
			Content:      finContent,
		})
	}

	c.writePage("html/commit.page.tmpl", fmt.Sprintf("%s.html", commitID), "commits", &CommitPageData{
		PageData:  pageData,
		Commit:    commit,
		CommitID:  getShortID(commitID),
		Diff:      rnd,
		Parent:    getShortID(commit.ParentID),
		CommitURL: c.getCommitURL(commitID),
		ParentURL: c.getCommitURL(commit.ParentID),
	})
}

// URL Generation
func (c *RepoConfig) getSummaryURL() template.URL { return template.URL(c.RootRelative + "index.html") }
func (c *RepoConfig) getRefsURL() template.URL    { return template.URL(c.RootRelative + "refs.html") }
func (c *RepoConfig) getSearchURL() template.URL  { return template.URL(c.RootRelative + "search.html") }
func getRevIDForURL(info RevInfo) string          { return info.Name() }
func getTreeBaseDir(info RevInfo) string          { return filepath.Join("/", "tree", getRevIDForURL(info)) }
func getLogBaseDir(info RevInfo) string           { return filepath.Join("/", "logs", getRevIDForURL(info)) }
func getFileBaseDir(info RevInfo) string          { return filepath.Join(getTreeBaseDir(info), "item") }
func getFileDir(info RevInfo, fname string) string {
	return filepath.Join(getFileBaseDir(info), fname)
}
func (c *RepoConfig) compileURL(parts ...string) template.URL {
	return template.URL(c.RootRelative + strings.TrimPrefix(filepath.Join(parts...), "/"))
}
func (c *RepoConfig) getFileURL(info RevInfo, fname string) template.URL {
	return c.compileURL(getFileBaseDir(info), fmt.Sprintf("%s.html", fname))
}
func (c *RepoConfig) getTreeURL(info RevInfo) template.URL {
	return c.compileURL(getTreeBaseDir(info), "index.html")
}
func (c *RepoConfig) getLogsURL(info RevInfo) template.URL {
	return c.compileURL(getLogBaseDir(info), "index.html")
}
func (c *RepoConfig) getCommitURL(commitID string) template.URL {
	if commitID == "" {
		return ""
	}
	return c.compileURL("commits", fmt.Sprintf("%s.html", commitID))
}
func (c *RepoConfig) getURLs() *SiteURLs {
	return &SiteURLs{
		HomeURL:    template.URL(c.HomeURL),
		CloneURL:   template.URL(c.CloneURL),
		RefsURL:    c.getRefsURL(),
		SummaryURL: c.getSummaryURL(),
		SearchURL:  c.getSearchURL(),
	}
}

func getShortID(id string) string {
	if len(id) < 7 {
		return id
	}
	return id[:7]
}

func parseGitAttributes(path string) (attrs []GitAttribute, whitelist, blacklist map[string]bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, err
	}
	defer file.Close()

	whitelist = make(map[string]bool)
	blacklist = make(map[string]bool)
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		processDirective := func(prefix string, store map[string]bool) bool {
			if strings.HasPrefix(line, prefix) {
				if kv := strings.SplitN(line, "=", 2); len(kv) == 2 {
					for _, lang := range strings.Split(strings.Trim(kv[1], `"`), ",") {
						store[strings.TrimSpace(lang)] = true
					}
				}
				return true
			}
			return false
		}

		if processDirective("pgit-whitelist", whitelist) || processDirective("pgit-blacklist", blacklist) {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		pattern := parts[0]
		attributes := make(map[string]string)
		for _, attrStr := range parts[1:] {
			if kv := strings.SplitN(attrStr, "=", 2); len(kv) == 2 {
				attributes[kv[0]] = strings.Trim(kv[1], `"`)
			} else {
				attributes[attrStr] = "true"
			}
		}
		attrs = append(attrs, GitAttribute{pattern, attributes})
	}

	if len(whitelist) == 0 {
		whitelist = nil
	}
	if len(blacklist) == 0 {
		blacklist = nil
	}
	return attrs, whitelist, blacklist, scanner.Err()
}

func (c *RepoConfig) writeRepo() error {
	c.Logger.Info("writing repo", "repoPath", c.RepoPath)
	repo, err := git.Open(c.RepoPath)
	if err != nil {
		return tracerr.Errorf("failed to open git repo %s: %w", c.RepoPath, err)
	}

	gitAttrPath := filepath.Join(c.RepoPath, ".gitattributes")
	if _, err := os.Stat(gitAttrPath); err == nil {
		var parseErr error
		c.GitAttributes, c.Whitelist, c.Blacklist, parseErr = parseGitAttributes(gitAttrPath)
		if parseErr != nil {
			c.Logger.Warn("failed to parse .gitattributes file", "path", gitAttrPath, "error", parseErr)
		}
	}

	refs, err := repo.ShowRef(git.ShowRefOptions{Heads: true, Tags: true})
	if err != nil {
		return tracerr.Errorf("failed to get refs: %w", err)
	}

	var first *RevData
	var revs []*RevData
	for _, revStr := range c.Revs {
		fullRevID, err := repo.RevParse(revStr)
		if err != nil {
			c.Logger.Warn("failed to parse revision, skipping", "rev", revStr, "error", err)
			continue
		}
		revName := getShortID(fullRevID)
		for _, ref := range refs {
			if revStr == git.RefShortName(ref.Refspec) || revStr == ref.Refspec {
				revName = revStr
				break
			}
		}
		data := &RevData{fullRevID, revName, c}
		if first == nil {
			first = data
		}
		revs = append(revs, data)
	}

	if first == nil {
		return tracerr.New("no valid git references found to process")
	}

	refInfoMap := make(map[string]*RefInfo)
	for _, revData := range revs {
		refInfoMap[revData.Name()] = &RefInfo{revData.ID(), revData.Name(), revData.TreeURL()}
	}
	for _, ref := range refs {
		refspec := git.RefShortName(ref.Refspec)
		if _, exists := refInfoMap[refspec]; !exists {
			refInfoMap[refspec] = &RefInfo{ID: ref.ID, Refspec: refspec}
		}
	}

	refInfoList := make([]*RefInfo, 0, len(refInfoMap))
	for _, val := range refInfoMap {
		refInfoList = append(refInfoList, val)
	}
	sort.Slice(refInfoList, func(i, j int) bool {
		if refInfoList[i].URL != refInfoList[j].URL {
			return refInfoList[i].URL > refInfoList[j].URL
		}
		return refInfoList[i].Refspec < refInfoList[j].Refspec
	})

	var mainReadme template.HTML
	var searchIndex []*SearchIndexEntry
	var langFiles = make(map[string][]*SearchIndexEntry)
	var searchIndexMutex sync.Mutex
	var langFilesMutex sync.Mutex
	var wg sync.WaitGroup

	for i, revData := range revs {
		pageData := &PageData{c, c.getURLs(), revData}
		isFirst := i == 0
		wg.Add(1)
		go func(d *PageData, firstRev bool) {
			defer wg.Done()
			readme, sIndex, lFiles, err := c.writeRevision(repo, d, refInfoList)
			if err != nil {
				c.Logger.Error("failed to write revision", "rev", d.RevData.Name(), "error", err)
				return
			}
			if firstRev {
				mainReadme = readme
				searchIndexMutex.Lock()
				searchIndex = append(searchIndex, sIndex...)
				searchIndexMutex.Unlock()
				langFilesMutex.Lock()
				for lang, files := range lFiles {
					langFiles[lang] = append(langFiles[lang], files...)
				}
				langFilesMutex.Unlock()
			}
		}(pageData, isFirst)
	}
	wg.Wait()

	pageData := &PageData{c, c.getURLs(), first}
	c.writeRefs(pageData, refInfoList)
	c.writeSearchIndex(searchIndex)
	c.writeSearchPage(pageData)
	for lang, files := range langFiles {
		c.writeLanguagePage(pageData, lang, files)
	}

	langStats, totalSize := calculateLanguageStats(repo, first.id, c)
	c.writeRootSummary(pageData, mainReadme, langStats, totalSize)
	return nil
}

type TreeRoot struct {
	Path   string
	Items  []*TreeItem
	Crumbs []*Breadcrumb
}

type TreeWalker struct {
	treeItemChan chan *TreeItem
	treeRootChan chan *TreeRoot
	errChan      chan error
	wg           sync.WaitGroup
	PageData     *PageData
	Repo         *git.Repository
	Config       *RepoConfig
}

type Breadcrumb struct {
	Text   string
	URL    template.URL
	IsLast bool
}

func (tw *TreeWalker) calcBreadcrumbs(curpath string) []*Breadcrumb {
	if curpath == "" {
		return nil
	}
	parts := strings.Split(curpath, string(os.PathSeparator))
	crumbs := make([]*Breadcrumb, len(parts)+1)
	crumbs[0] = &Breadcrumb{
		URL:  tw.Config.getTreeURL(tw.PageData.RevData),
		Text: tw.PageData.Repo.RepoName,
	}
	for i, part := range parts {
		currentCrumbPath := filepath.Join(parts[:i+1]...)
		crumbs[i+1] = &Breadcrumb{
			Text:   part,
			URL:    tw.Config.compileURL(getFileBaseDir(tw.PageData.RevData), currentCrumbPath, "index.html"),
			IsLast: i == len(parts)-1,
		}
	}
	return crumbs
}

func (tw *TreeWalker) newTreeItem(entry *git.TreeEntry, curpath string, crumbs []*Breadcrumb) (*TreeItem, error) {
	fname := filepath.Join(curpath, entry.Name())
	item := &TreeItem{
		Size:   toPretty(entry.Size()),
		Name:   entry.Name(),
		Path:   fname,
		Entry:  entry,
		Crumbs: crumbs,
		IsDir:  entry.Type() == git.ObjectTree,
	}

	if !tw.Config.HideTreeLastCommit {
		lastCommits, err := tw.Repo.RevList([]string{tw.PageData.RevData.ID()}, git.RevListOptions{
			Path:           item.Path,
			CommandOptions: git.CommandOptions{Args: []string{"-1"}},
		})
		if err != nil {
			return nil, tracerr.Errorf("failed to get last commit for %s: %w", item.Path, err)
		}
		if len(lastCommits) > 0 {
			lc := lastCommits[0]
			item.CommitURL = tw.Config.getCommitURL(lc.ID.String())
			item.CommitID = getShortID(lc.ID.String())
			item.Summary = lc.Summary()
			item.When = lc.Author.When.Format(time.DateOnly)
			item.Author = lc.Author
		}
	}

	if item.IsDir {
		item.URL = tw.Config.compileURL(getFileBaseDir(tw.PageData.RevData), fname, "index.html")
	} else {
		item.URL = tw.Config.getFileURL(tw.PageData.RevData, fname)
	}
	return item, nil
}

func (tw *TreeWalker) walk(tree *git.Tree, curpath string) {
	defer tw.wg.Done()

	entries, err := tree.Entries()
	if err != nil {
		tw.errChan <- err
		return
	}

	crumbs := tw.calcBreadcrumbs(curpath)
	var treeEntries []*TreeItem
	for _, entry := range entries {
		item, err := tw.newTreeItem(entry, curpath, crumbs)
		if err != nil {
			tw.errChan <- err
			return
		}
		treeEntries = append(treeEntries, item)

		if item.IsDir {
			subTree, err := tree.Subtree(entry.Name())
			if err != nil {
				tw.errChan <- err
				continue
			}
			tw.wg.Add(1)
			go tw.walk(subTree, item.Path)
		}
		tw.treeItemChan <- item
	}

	sort.Slice(treeEntries, func(i, j int) bool {
		if treeEntries[i].IsDir != treeEntries[j].IsDir {
			return treeEntries[i].IsDir
		}
		return treeEntries[i].Name < treeEntries[j].Name
	})

	fpath := getFileBaseDir(tw.PageData.RevData)
	if curpath != "" {
		fpath = filepath.Join(fpath, curpath)
	} else {
		fpath = getTreeBaseDir(tw.PageData.RevData)
	}

	tw.treeRootChan <- &TreeRoot{Path: fpath, Items: treeEntries, Crumbs: crumbs}
}

func (c *RepoConfig) writeRevision(repo *git.Repository, pageData *PageData, refs []*RefInfo) (template.HTML, []*SearchIndexEntry, map[string][]*SearchIndexEntry, error) {
	c.Logger.Info("compiling revision", "repoName", c.RepoName, "revision", pageData.RevData.Name())
	var wg sync.WaitGroup
	errChan := make(chan error, 20)

	// Process commits
	wg.Add(1)
	go func() {
		defer wg.Done()
		pageSize := c.MaxCommits
		if pageSize == 0 {
			pageSize = 5000
		}
		commits, err := repo.CommitsByPage(pageData.RevData.ID(), 0, pageSize)
		if err != nil {
			errChan <- tracerr.Errorf("failed to get commits for %s: %w", pageData.RevData.ID(), err)
			return
		}

		var logs []*CommitData
		for _, commit := range commits {
			var commitRefs []*RefInfo
			for _, ref := range refs {
				if commit.ID.String() == ref.ID {
					commitRefs = append(commitRefs, ref)
				}
			}
			parentSha, _ := commit.ParentID(0)
			parentID := ""
			if parentSha != nil {
				parentID = parentSha.String()
			}

			logEntry := &CommitData{
				SummaryStr: commit.Summary(),
				URL:        c.getCommitURL(commit.ID.String()),
				ShortID:    getShortID(commit.ID.String()),
				AuthorStr:  commit.Author.Name,
				WhenStr:    commit.Author.When.Format(time.DateOnly),
				Commit:     commit,
				Refs:       commitRefs,
				ParentID:   parentID,
			}
			logs = append(logs, logEntry)

			wg.Add(1)
			go func(cm *CommitData) {
				defer wg.Done()
				c.writeLogDiff(repo, pageData, cm)
			}(logEntry)
		}
		c.writeLog(pageData, logs)
	}()

	// Process tree
	tree, err := repo.LsTree(pageData.RevData.ID())
	if err != nil {
		return "", nil, nil, tracerr.Errorf("failed to list tree for %s: %w", pageData.RevData.ID(), err)
	}

	var readme template.HTML
	var readmeMutex sync.Mutex
	var searchIndex []*SearchIndexEntry
	var langFiles = make(map[string][]*SearchIndexEntry)
	var mu sync.Mutex

	treeItemChan := make(chan *TreeItem, 100)
	treeRootChan := make(chan *TreeRoot, 20)
	tw := &TreeWalker{
		Config:       c,
		PageData:     pageData,
		Repo:         repo,
		treeItemChan: treeItemChan,
		treeRootChan: treeRootChan,
		errChan:      errChan,
	}

	tw.wg.Add(1)
	go tw.walk(tree, "")

	wg.Add(1)
	go func() {
		defer wg.Done()
		var fileWg sync.WaitGroup
		for item := range treeItemChan {
			if item.IsDir {
				continue
			}
			fileWg.Add(1)
			go func(entry *TreeItem) {
				defer fileWg.Done()
				readmeStr, lang, _, err := c.writeHTMLTreeFile(pageData, entry)
				if err != nil {
					errChan <- err
					return
				}
				if readmeStr != "" {
					readmeMutex.Lock()
					readme = template.HTML(readmeStr)
					readmeMutex.Unlock()
				}
				fileInfo := &SearchIndexEntry{
					Name:     entry.Name,
					Path:     entry.Path,
					URL:      string(entry.URL),
					Language: lang,
				}
				mu.Lock()
				searchIndex = append(searchIndex, fileInfo)
				if lang != "Binary" && lang != "Text" {
					langFiles[lang] = append(langFiles[lang], fileInfo)
				}
				mu.Unlock()
			}(item)
		}
		fileWg.Wait()
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		var treeWg sync.WaitGroup
		for t := range treeRootChan {
			treeWg.Add(1)
			go func(tr *TreeRoot) {
				defer treeWg.Done()
				c.writeTree(pageData, tr)
			}(t)
		}
		treeWg.Wait()
	}()

	go func() {
		tw.wg.Wait()
		close(treeItemChan)
		close(treeRootChan)
	}()

	go func() {
		wg.Wait()
		close(errChan)
	}()

	for err := range errChan {
		if e, ok := err.(*tracerr.Error); ok {
			e.Print()
		} else {
			c.Logger.Error("an error occurred during revision processing", "error", err)
		}
		return "", nil, nil, err
	}

	c.Logger.Info("compilation complete", "repoName", c.RepoName, "revision", pageData.RevData.Name())
	return readme, searchIndex, langFiles, nil
}

// Language Stats & Theme
var langColors = map[string]string{
	"Go":         "#00ADD8",
	"C":          "#555555",
	"C++":        "#F34B7D",
	"Python":     "#3572A5",
	"JavaScript": "#F1E05A",
	"TypeScript": "#2B7489",
	"HTML":       "#E34F26",
	"CSS":        "#563D7C",
	"Shell":      "#89E051",
	"Makefile":   "#427819",
	"Dockerfile": "#384D54",
	"Markdown":   "#083FA1",
	"JSON":       "#292929",
	"YAML":       "#CB171E",
	"B":          "#555555",
	"Nim":        "#ffe953",
}

func getLanguageColor(lang string) string {
	if color, ok := langColors[lang]; ok {
		return color
	}
	hash := 0
	for _, char := range lang {
		hash = int(char) + ((hash << 5) - hash)
	}
	return fmt.Sprintf("#%06x", (hash&0x00FFFFFF))
}

func calculateLanguageStats(repo *git.Repository, rev string, config *RepoConfig) ([]*LanguageStat, int64) {
	tree, err := repo.LsTree(rev)
	if err != nil {
		config.Logger.Error("failed to get tree for language stats", "error", err)
		return nil, 0
	}

	langSizes := make(map[string]int64)
	langHexColors := make(map[string]string)
	var totalSize int64
	var mu sync.Mutex
	var wg sync.WaitGroup

	var walkTree func(*git.Tree, string)
	walkTree = func(t *git.Tree, currentPath string) {
		defer wg.Done()
		entries, _ := t.Entries()
		for _, entry := range entries {
			fullPath := filepath.Join(currentPath, entry.Name())
			if entry.Type() == git.ObjectBlob {
				blob := entry.Blob()
				data, _ := blob.Bytes()
				displayName, _, isText := config.getLanguageInfo(fullPath, data)
				if isText && displayName != "Text" && displayName != "Binary" {
					attrs := config.getFileAttributes(fullPath)
					hexColor := attrs["linguist-hex-color"]

					mu.Lock()
					langSizes[displayName] += blob.Size()
					totalSize += blob.Size()
					if hexColor != "" {
						langHexColors[displayName] = hexColor
					}
					mu.Unlock()
				}
			} else if entry.Type() == git.ObjectTree {
				subTree, err := t.Subtree(entry.Name())
				if err == nil {
					wg.Add(1)
					go walkTree(subTree, fullPath)
				}
			}
		}
	}

	wg.Add(1)
	walkTree(tree, "")
	wg.Wait()

	if totalSize == 0 {
		return nil, 0
	}

	stats := make([]*LanguageStat, 0, len(langSizes))
	for lang, size := range langSizes {
		color := langHexColors[lang]
		if color == "" {
			color = getLanguageColor(lang)
		}

		stats = append(stats, &LanguageStat{
			Name:       lang,
			Percentage: (float64(size) / float64(totalSize)) * 100,
			Color:      color,
			URL:        config.compileURL(fmt.Sprintf("lang-%s.html", lang)),
		})
	}

	sort.Slice(stats, func(i, j int) bool {
		return stats[i].Percentage > stats[j].Percentage
	})
	return stats, totalSize
}

func generateThemeCSS(theme *chroma.Style) string {
	bg := theme.Get(chroma.Background)
	txt := theme.Get(chroma.Text)
	kw := theme.Get(chroma.Keyword)
	nv := theme.Get(chroma.NameVariable)
	cm := theme.Get(chroma.Comment)
	ln := theme.Get(chroma.LiteralNumber)
	return fmt.Sprintf(`:root {
 --bg-color: %s; --text-color: %s; --border: %s;
 --link-color: %s; --hover: %s; --visited: %s;
}`, bg.Background, txt.Colour, cm.Colour, nv.Colour, kw.Colour, ln.Colour)
}

type PgitConfig struct {
	Repos []RepoConfig `yaml:"repos"`
}

func loadConfig(path string, logger *slog.Logger) (*PgitConfig, error) {
	logger.Info("loading configuration file", "path", path)
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		return nil, tracerr.Errorf("error reading config file %s: %w", path, err)
	}
	var pgitConfig PgitConfig
	if err := yaml.Unmarshal(yamlFile, &pgitConfig); err != nil {
		return nil, tracerr.Errorf("error parsing YAML file: %w", err)
	}
	return &pgitConfig, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	app := &cli.Command{
		Name:  "pgit",
		Usage: "A static site generator for git repositories",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Value: "pgit.yaml", Usage: "Path to config file"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			pgitConfig, err := loadConfig(cmd.String("config"), logger)
			if err != nil {
				return err
			}
			if len(pgitConfig.Repos) == 0 {
				logger.Warn("no repositories found in configuration")
				return nil
			}

			var wg sync.WaitGroup
			formatter := html.New(html.WithLineNumbers(true), html.WithLinkableLineNumbers(true, ""), html.WithClasses(true))

			for _, repoCfg := range pgitConfig.Repos {
				wg.Add(1)
				go func(config RepoConfig) {
					defer wg.Done()
					if config.Label == "" {
						config.Label = repoName(config.RepoPath)
					}
					config.RepoName = config.Label
					if len(config.Revs) == 0 {
						logger.Error("you must provide revs for repo", "repo", config.RepoPath)
						return
					}
					if config.RenderMarkdown == nil {
						t := true
						config.RenderMarkdown = &t
					}

					config.Logger = logger
					config.ChromaTheme = styles.Get(config.ThemeName)
					if config.ChromaTheme == nil {
						config.ChromaTheme = styles.Fallback
					}
					config.Formatter = formatter

					if err := config.writeRepo(); err != nil {
						logger.Error("failed to write repo", "repo", config.RepoPath, "error", err)
						if e, ok := err.(*tracerr.Error); ok {
							e.Print()
						}
						return
					}

					if err := config.copyStaticFiles(); err != nil {
						logger.Error("failed to copy static files", "repo", config.RepoPath, "error", err)
						return
					}

					if err := os.WriteFile(filepath.Join(config.Outdir, "vars.css"), []byte(generateThemeCSS(config.ChromaTheme)), 0644); err != nil {
						logger.Error("failed to write vars.css", "repo", config.RepoPath, "error", err)
					}

					fp := filepath.Join(config.Outdir, "syntax.css")
					w, err := os.Create(fp)
					if err != nil {
						logger.Error("failed to create syntax.css", "repo", config.RepoPath, "error", err)
						return
					}
					defer w.Close()
					if err = formatter.WriteCSS(w, config.ChromaTheme); err != nil {
						logger.Error("failed to write syntax.css", "repo", config.RepoPath, "error", err)
					}
				}(repoCfg)
			}
			wg.Wait()
			logger.Info("all repositories processed successfully")
			return nil
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		if e, ok := err.(*tracerr.Error); ok {
			e.Print()
		} else {
			logger.Error("application failed to run", "error", err)
		}
		os.Exit(1)
	}
}
