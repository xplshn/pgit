//usr/bin/env go run "$0" "$@"; exit "$?"
package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"net/http"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/dustin/go-humanize"
	"github.com/gogs/git-module"
	"github.com/urfave/cli/v3"
	"github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli-altsrc/v3/yaml"
	"github.com/h2non/filetype"
)

//go:embed html/*.tmpl
var embedFS embed.FS

//go:embed static/*
var staticFS embed.FS

type RepoConfig struct {
	// required params
	Outdir string `yaml:"out"`
	// abs path to git repo
	RepoPath string `yaml:"repo"`

	// optional params
	// generate logs and tree based on the git revisions provided
	Revs []string `yaml:"revs"`
	// description of repo used in the header of site
	Desc string `yaml:"desc"`
	// maximum number of commits that we will process in descending order
	MaxCommits int `yaml:"max-commits"`
	// name of the readme file
	Readme string `yaml:"readme"`
	// In order to get the latest commit per file we do a `git rev-list {ref} {file}`
	// which is n+1 where n is a file in the tree.
	// We offer a way to disable showing the latest commit in the output
	// for those who want a faster build time
	HideTreeLastCommit bool `yaml:"hide-tree-last-commit"`

	// user-defined urls
	HomeURL  string `yaml:"home-url"`
	CloneURL string `yaml:"clone-url"`

	// https://developer.mozilla.org/en-US/docs/Web/API/URL_API/Resolving_relative_references#root_relative
	RootRelative string `yaml:"root-relative"`

	ThemeName string `yaml:"theme"`

	Label string `yaml:"label"`

	// computed
	// cache for skipping commits, trees, etc.
	Cache map[string]bool
	// mutex for Cache
	Mutex sync.RWMutex
	// pretty name for the repo
	RepoName string
	// logger
	Logger *slog.Logger
	// chroma style
	Theme     *chroma.Style
	Formatter *html.Formatter
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

func (r *RevData) ID() string {
	return r.id
}

func (r *RevData) Name() string {
	return r.name
}

func (r *RevData) TreeURL() template.URL {
	return r.Config.getTreeURL(r)
}

func (r *RevData) LogURL() template.URL {
	return r.Config.getLogsURL(r)
}

type TagData struct {
	Name string
	URL  template.URL
}

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
	ID      string `json:"ID"`
	Refspec string `json:"Refspec"`
	URL     template.URL `json:"URL"`
}

type BranchOutput struct {
	Readme     string
	LastCommit *git.Commit
}

type SiteURLs struct {
	HomeURL    template.URL
	CloneURL   template.URL
	SummaryURL template.URL
	RefsURL    template.URL
}

type PageData struct {
	Repo     *RepoConfig
	SiteURLs *SiteURLs
	RevData  *RevData
}

type SummaryPageData struct {
	*PageData
	Readme template.HTML
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

func bail(err error) {
	if err != nil {
		panic(err)
	}
}

func diffFileType(_type git.DiffFileType) string {
	switch _type {
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

// converts contents of files in git tree to pretty formatted code.
func (c *RepoConfig) parseText(filename string, text string, blob *git.Blob) (string, string, error) {
	// Check file size
	if blob != nil && blob.Size() > 800*1024 { // 800KB
		return "file too large to display (>800KB)", "", nil
	}

	lexer := lexers.Match(filename)
	if lexer == nil {
		lexer = lexers.Analyse(text)
	}
	if lexer == nil {
		lexer = lexers.Get("plaintext")
	}
	lang := "Text"
	if lexer != nil {
		lang = lexer.Config().Name
	}
	iterator, err := lexer.Tokenise(nil, text)
	if err != nil {
		return text, lang, err
	}
	var buf bytes.Buffer
	err = c.Formatter.Format(&buf, c.Theme, iterator)
	if err != nil {
		return text, lang, err
	}
	return buf.String(), lang, nil
}

// isText reports whether a significant prefix of s looks like correct UTF-8;
// that is, if it is likely that s is human-readable text.
func isText(s string) bool {
	const max = 1024 // at least utf8.UTFMax
	if len(s) > max {
		s = s[0:max]
	}
	for i, c := range s {
		if i+utf8.UTFMax > len(s) {
			// last char may be incomplete - ignore
			break
		}
		if c == 0xFFFD || c < ' ' && c != '\n' && c != '\t' && c != '\f' && c != '\r' {
			// decoding error or control character - not a text file
			return false
		}
	}
	return true
}

// isTextFile reports whether the file has a known extension indicating
// a text file, or if a significant chunk of the specified file looks like
// correct UTF-8; that is, if it is likely that the file contains human-
// readable text.
func isTextFile(text string, blob *git.Blob) bool {
	// Check file size
	if blob != nil && blob.Size() > 800*1024 { // 800KB
		return false
	}

	// Check if file is binary
	ft, err := filetype.Match([]byte(text))
	if err != nil {
		return false
	}
	if !strings.HasPrefix("text", ft.MIME.Type) {
		return false
	}

	num := math.Min(float64(len(text)), 1024)
	return isText(text[0:int(num)])
}

func toPretty(b int64) string {
	return humanize.Bytes(uint64(b))
}

func repoName(root string) string {
	_, file := filepath.Split(root)
	return file
}

func readmeFile(repo *RepoConfig) string {
	if repo.Readme == "" {
		return "readme.md"
	}

	return strings.ToLower(repo.Readme)
}

func (c *RepoConfig) writeHtml(writeData *WriteData) {
	ts, err := template.ParseFS(
		embedFS,
		writeData.Template,
		"html/header.partial.tmpl",
		"html/footer.partial.tmpl",
		"html/base.layout.tmpl",
	)
	bail(err)

	dir := filepath.Join(c.Outdir, writeData.Subdir)
	err = os.MkdirAll(dir, os.ModePerm)
	bail(err)

	fp := filepath.Join(dir, writeData.Filename)
	c.Logger.Info("writing", "filepath", fp)

	w, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	bail(err)

	err = ts.Execute(w, writeData.Data)
	bail(err)
}

func (c *RepoConfig) copyStatic(dir string) error {
	entries, err := staticFS.ReadDir(dir)
	bail(err)

	for _, e := range entries {
		infp := filepath.Join(dir, e.Name())
		if e.IsDir() {
			continue
		}

		w, err := staticFS.ReadFile(infp)
		bail(err)
		fp := filepath.Join(c.Outdir, e.Name())
		c.Logger.Info("writing", "filepath", fp)
		err = os.WriteFile(fp, w, 0644)
		bail(err)
	}

	return nil
}

func (c *RepoConfig) writeRootSummary(data *PageData, readme template.HTML) {
	c.Logger.Info("writing root html", "repoPath", c.RepoPath)
	c.writeHtml(&WriteData{
		Filename: "index.html",
		Template: "html/summary.page.tmpl",
		Data: &SummaryPageData{
			PageData: data,
			Readme:   readme,
		},
	})
}

func (c *RepoConfig) writeTree(data *PageData, tree *TreeRoot) {
	c.Logger.Info("writing tree", "treePath", tree.Path)
	c.writeHtml(&WriteData{
		Filename: "index.html",
		Subdir:   tree.Path,
		Template: "html/tree.page.tmpl",
		Data: &TreePageData{
			PageData: data,
			Tree:     tree,
		},
	})
}

func (c *RepoConfig) writeLog(data *PageData, logs []*CommitData) {
	c.Logger.Info("writing log file", "revision", data.RevData.Name())
	c.writeHtml(&WriteData{
		Filename: "index.html",
		Subdir:   getLogBaseDir(data.RevData),
		Template: "html/log.page.tmpl",
		Data: &LogPageData{
			PageData:   data,
			NumCommits: len(logs),
			Logs:       logs,
		},
	})
}

func (c *RepoConfig) writeRefs(data *PageData, refs []*RefInfo) {
	c.Logger.Info("writing refs", "repoPath", c.RepoPath)
	c.writeHtml(&WriteData{
		Filename: "refs.html",
		Template: "html/refs.page.tmpl",
		Data: &RefPageData{
			PageData: data,
			Refs:     refs,
		},
	})

	// write refs.json
	jsonData, err := json.Marshal(refs)
	bail(err)
	fp := filepath.Join(c.Outdir, "refs.json")
	err = os.WriteFile(fp, jsonData, 0644)
	bail(err)
}

func (c *RepoConfig) writeHTMLTreeFile(pageData *PageData, treeItem *TreeItem) string {
	readme := ""
	b, err := treeItem.Entry.Blob().Bytes()
	bail(err)
	str := string(b)

	treeItem.IsTextFile = isTextFile(str, treeItem.Entry.Blob())

	contentsStr := "binary file, cannot display"
	lang := ""
	numLines := 0
	if treeItem.IsTextFile {
		numLines = len(strings.Split(str, "\n"))
		contentsStr, lang, err = c.parseText(treeItem.Entry.Name(), str, treeItem.Entry.Blob())
		bail(err)
	}
	treeItem.NumLines = numLines

	d := filepath.Dir(treeItem.Path)

	nameLower := strings.ToLower(treeItem.Entry.Name())
	summary := readmeFile(pageData.Repo)
	if d == "." && nameLower == summary {
		readme = contentsStr
	}

	c.writeHtml(&WriteData{
		Filename: fmt.Sprintf("%s.html", treeItem.Entry.Name()),
		Template: "html/file.page.tmpl",
		Data: &FilePageData{
			PageData: pageData,
			Contents: template.HTML(contentsStr),
			Item:     treeItem,
			Language: lang,
		},
		Subdir: getFileDir(pageData.RevData, d),
	})
	return readme
}

func (c *RepoConfig) writeLogDiff(repo *git.Repository, pageData *PageData, commit *CommitData) {
	commitID := commit.ID.String()

	c.Mutex.RLock()
	hasCommit := c.Cache[commitID]
	c.Mutex.RUnlock()

	if hasCommit {
		c.Logger.Info("commit file already generated, skipping", "commitID", getShortID(commitID))
		return
	}

	c.Mutex.Lock()
	c.Cache[commitID] = true
	c.Mutex.Unlock()

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
	fls := []*DiffRenderFile{}
	for _, file := range diff.Files {
		fl := &DiffRenderFile{
			FileType:     diffFileType(file.Type),
			OldMode:      file.OldMode(),
			OldName:      file.OldName(),
			Mode:         file.Mode(),
			Name:         file.Name,
			NumAdditions: file.NumAdditions(),
			NumDeletions: file.NumDeletions(),
		}
		content := ""
		for _, section := range file.Sections {
			for _, line := range section.Lines {
				content += fmt.Sprintf("%s\n", line.Content)
			}
		}
		finContent, _, err := c.parseText("commit.diff", content, nil)
		if err != nil {
			c.Logger.Error("failed to parse diff content", "commitID", getShortID(commitID), "error", err)
			continue
		}

		fl.Content = template.HTML(finContent)
		fls = append(fls, fl)
	}
	rnd.Files = fls

	commitData := &CommitPageData{
		PageData:  pageData,
		Commit:    commit,
		CommitID:  getShortID(commitID),
		Diff:      rnd,
		Parent:    getShortID(commit.ParentID),
		CommitURL: c.getCommitURL(commitID),
		ParentURL: c.getCommitURL(commit.ParentID),
	}

	c.writeHtml(&WriteData{
		Filename: fmt.Sprintf("%s.html", commitID),
		Template: "html/commit.page.tmpl",
		Subdir:   "commits",
		Data:     commitData,
	})
}

func (c *RepoConfig) getSummaryURL() template.URL {
	url := c.RootRelative + "index.html"
	return template.URL(url)
}

func (c *RepoConfig) getRefsURL() template.URL {
	url := c.RootRelative + "refs.html"
	return template.URL(url)
}

// controls the url for trees and logs
// - /logs/getRevIDForURL()/index.html
// - /tree/getRevIDForURL()/item/file.x.html.
func getRevIDForURL(info RevInfo) string {
	return info.Name()
}

func getTreeBaseDir(info RevInfo) string {
	subdir := getRevIDForURL(info)
	return filepath.Join("/", "tree", subdir)
}

func getLogBaseDir(info RevInfo) string {
	subdir := getRevIDForURL(info)
	return filepath.Join("/", "logs", subdir)
}

func getFileBaseDir(info RevInfo) string {
	return filepath.Join(getTreeBaseDir(info), "item")
}

func getFileDir(info RevInfo, fname string) string {
	return filepath.Join(getFileBaseDir(info), fname)
}

func (c *RepoConfig) getFileURL(info RevInfo, fname string) template.URL {
	return c.compileURL(getFileBaseDir(info), fname)
}

func (c *RepoConfig) compileURL(dir, fname string) template.URL {
	purl := c.RootRelative + strings.TrimPrefix(dir, "/")
	url := filepath.Join(purl, fname)
	return template.URL(url)
}

func (c *RepoConfig) getTreeURL(info RevInfo) template.URL {
	dir := getTreeBaseDir(info)
	return c.compileURL(dir, "index.html")
}

func (c *RepoConfig) getLogsURL(info RevInfo) template.URL {
	dir := getLogBaseDir(info)
	return c.compileURL(dir, "index.html")
}

func (c *RepoConfig) getCommitURL(commitID string) template.URL {
	url := fmt.Sprintf("%scommits/%s.html", c.RootRelative, commitID)
	return template.URL(url)
}

func (c *RepoConfig) getURLs() *SiteURLs {
	return &SiteURLs{
		HomeURL:    template.URL(c.HomeURL),
		CloneURL:   template.URL(c.CloneURL),
		RefsURL:    c.getRefsURL(),
		SummaryURL: c.getSummaryURL(),
	}
}

func getShortID(id string) string {
	return id[:7]
}

func (c *RepoConfig) writeRepo() *BranchOutput {
	c.Logger.Info("writing repo", "repoPath", c.RepoPath)
	repo, err := git.Open(c.RepoPath)
	bail(err)

	refs, err := repo.ShowRef(git.ShowRefOptions{Heads: true, Tags: true})
	bail(err)

	var first *RevData
	revs := []*RevData{}
	for _, revStr := range c.Revs {
		fullRevID, err := repo.RevParse(revStr)
		bail(err)

		revID := getShortID(fullRevID)
		revName := revID
		// if it's a reference then label it as such
		for _, ref := range refs {
			if revStr == git.RefShortName(ref.Refspec) || revStr == ref.Refspec {
				revName = revStr
				break
			}
		}

		data := &RevData{
			id:     fullRevID,
			name:   revName,
			Config: c,
		}

		if first == nil {
			first = data
		}
		revs = append(revs, data)
	}

	if first == nil {
		bail(fmt.Errorf("could find find a git reference that matches criteria"))
	}

	refInfoMap := map[string]*RefInfo{}
	for _, revData := range revs {
		refInfoMap[revData.Name()] = &RefInfo{
			ID:      revData.ID(),
			Refspec: revData.Name(),
			URL:     revData.TreeURL(),
		}
	}

	// loop through ALL refs that don't have URLs
	// and add them to the map
	for _, ref := range refs {
		refspec := git.RefShortName(ref.Refspec)
		if refInfoMap[refspec] != nil {
			continue
		}

		refInfoMap[refspec] = &RefInfo{
			ID:      ref.ID,
			Refspec: refspec,
		}
	}

	// gather lists of refs to display on refs.html page
	refInfoList := []*RefInfo{}
	for _, val := range refInfoMap {
		refInfoList = append(refInfoList, val)
	}
	sort.Slice(refInfoList, func(i, j int) bool {
		urlI := refInfoList[i].URL
		urlJ := refInfoList[j].URL
		refI := refInfoList[i].Refspec
		refJ := refInfoList[j].Refspec
		if urlI == urlJ {
			return refI < refJ
		}
		return urlI > urlJ
	})

	// we assume the first revision in the list is the "main" revision which mostly
	// means that's the README we use for the default summary page.
	mainOutput := &BranchOutput{}
	var wg sync.WaitGroup
	for i, revData := range revs {
		c.Logger.Info("writing revision", "revision", revData.Name())
		data := &PageData{
			Repo:     c,
			RevData:  revData,
			SiteURLs: c.getURLs(),
		}

		if i == 0 {
			branchOutput := c.writeRevision(repo, data, refInfoList)
			mainOutput = branchOutput
		} else {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c.writeRevision(repo, data, refInfoList)
			}()
		}
	}
	wg.Wait()

	// use the first revision in our list to generate
	// the root summary, logs, and tree the user can click
	revData := &RevData{
		id:     first.ID(),
		name:   first.Name(),
		Config: c,
	}

	data := &PageData{
		RevData:  revData,
		Repo:     c,
		SiteURLs: c.getURLs(),
	}
	c.writeRefs(data, refInfoList)
	c.writeRootSummary(data, template.HTML(mainOutput.Readme))
	return mainOutput
}

type TreeRoot struct {
	Path   string
	Items  []*TreeItem
	Crumbs []*Breadcrumb
}

type TreeWalker struct {
	treeItem           chan *TreeItem
	tree               chan *TreeRoot
	HideTreeLastCommit bool
	PageData           *PageData
	Repo               *git.Repository
	Config             *RepoConfig
}

type Breadcrumb struct {
	Text   string
	URL    template.URL
	IsLast bool
}

func (tw *TreeWalker) calcBreadcrumbs(curpath string) []*Breadcrumb {
	if curpath == "" {
		return []*Breadcrumb{}
	}
	parts := strings.Split(curpath, string(os.PathSeparator))
	rootURL := tw.Config.compileURL(
		getTreeBaseDir(tw.PageData.RevData),
		"index.html",
	)

	crumbs := make([]*Breadcrumb, len(parts)+1)
	crumbs[0] = &Breadcrumb{
		URL:  rootURL,
		Text: tw.PageData.Repo.RepoName,
	}

	cur := ""
	for idx, d := range parts {
		crumb := filepath.Join(getFileBaseDir(tw.PageData.RevData), cur, d)
		crumbUrl := tw.Config.compileURL(crumb, "index.html")
		crumbs[idx+1] = &Breadcrumb{
			Text: d,
			URL:  crumbUrl,
		}
		if idx == len(parts)-1 {
			crumbs[idx+1].IsLast = true
		}
		cur = filepath.Join(cur, d)
	}

	return crumbs
}

func filenameToDevIcon(filename string) string {
	ext := filepath.Ext(filename)
	extMappr := map[string]string{
		".html": "html5",
		".go":   "go",
		".py":   "python",
		".css":  "css3",
		".js":   "javascript",
		".md":   "markdown",
		".ts":   "typescript",
		".tsx":  "react",
		".jsx":  "react",
	}

	nameMappr := map[string]string{
		"Makefile":   "cmake",
		"Dockerfile": "docker",
	}

	icon := extMappr[ext]
	if icon == "" {
		icon = nameMappr[filename]
	}

	return fmt.Sprintf("devicon-%s-original", icon)
}

func (tw *TreeWalker) NewTreeItem(entry *git.TreeEntry, curpath string, crumbs []*Breadcrumb) *TreeItem {
	typ := entry.Type()
	fname := filepath.Join(curpath, entry.Name())
	item := &TreeItem{
		Size:   toPretty(entry.Size()),
		Name:   entry.Name(),
		Path:   fname,
		Entry:  entry,
		URL:    tw.Config.getFileURL(tw.PageData.RevData, fname),
		Crumbs: crumbs,
	}

	// `git rev-list` is pretty expensive here, so we have a flag to disable
	if tw.HideTreeLastCommit {
		// c.Logger.Info("skipping the process of finding the last commit for each file")
	} else {
		id := tw.PageData.RevData.ID()
		lastCommits, err := tw.Repo.RevList([]string{id}, git.RevListOptions{
			Path:           item.Path,
			CommandOptions: git.CommandOptions{Args: []string{"-1"}},
		})
		bail(err)

		var lc *git.Commit
		if len(lastCommits) > 0 {
			lc = lastCommits[0]
		}
		item.CommitURL = tw.Config.getCommitURL(lc.ID.String())
		item.CommitID = getShortID(lc.ID.String())
		item.Summary = lc.Summary()
		item.When = lc.Author.When.Format(time.DateOnly)
		item.Author = lc.Author
	}

	fpath := tw.Config.getFileURL(tw.PageData.RevData, fmt.Sprintf("%s.html", fname))
	switch typ {
	case git.ObjectTree:
		item.IsDir = true
		fpath = tw.Config.compileURL(
			filepath.Join(
				getFileBaseDir(tw.PageData.RevData),
				curpath,
				entry.Name(),
			),
			"index.html",
		)
	case git.ObjectBlob:
		item.Icon = filenameToDevIcon(item.Name)
	}
	item.URL = fpath

	return item
}

func (tw *TreeWalker) walk(tree *git.Tree, curpath string) {
	entries, err := tree.Entries()
	bail(err)

	crumbs := tw.calcBreadcrumbs(curpath)
	treeEntries := []*TreeItem{}
	for _, entry := range entries {
		typ := entry.Type()
		item := tw.NewTreeItem(entry, curpath, crumbs)

		switch typ {
	case git.ObjectTree:
		item.IsDir = true
		re, _ := tree.Subtree(entry.Name())
		tw.walk(re, item.Path)
		treeEntries = append(treeEntries, item)
		tw.treeItem <- item
	case git.ObjectBlob:
		treeEntries = append(treeEntries, item)
		tw.treeItem <- item
		}
	}

	sort.Slice(treeEntries, func(i, j int) bool {
		nameI := treeEntries[i].Name
		nameJ := treeEntries[j].Name
		if treeEntries[i].IsDir && treeEntries[j].IsDir {
			return nameI < nameJ
		}

		if treeEntries[i].IsDir && !treeEntries[j].IsDir {
			return true
		}

		if !treeEntries[i].IsDir && treeEntries[j].IsDir {
			return false
		}

		return nameI < nameJ
	})

	fpath := filepath.Join(
		getFileBaseDir(tw.PageData.RevData),
		curpath,
	)
	// root gets a special spot outside of `item` subdir
	if curpath == "" {
		fpath = getTreeBaseDir(tw.PageData.RevData)
	}

	tw.tree <- &TreeRoot{
		Path:   fpath,
		Items:  treeEntries,
		Crumbs: crumbs,
	}

	if curpath == "" {
		close(tw.tree)
		close(tw.treeItem)
	}
}

func (c *RepoConfig) writeRevision(repo *git.Repository, pageData *PageData, refs []*RefInfo) *BranchOutput {
	c.Logger.Info(
		"compiling revision",
		"repoName", c.RepoName,
		"revision", pageData.RevData.Name(),
	)

	output := &BranchOutput{}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		pageSize := pageData.Repo.MaxCommits
		if pageSize == 0 {
			pageSize = 5000
		}
		commits, err := repo.CommitsByPage(pageData.RevData.ID(), 0, pageSize)
		bail(err)

		logs := []*CommitData{}
		for i, commit := range commits {
			if i == 0 {
				output.LastCommit = commit
			}

			tags := []*RefInfo{}
			for _, ref := range refs {
				if commit.ID.String() == ref.ID {
					tags = append(tags, ref)
				}
			}

			parentSha, _ := commit.ParentID(0)
			parentID := ""
			if parentSha == nil {
				parentID = commit.ID.String()
			} else {
				parentID = parentSha.String()
			}
			logs = append(logs, &CommitData{
				ParentID:   parentID,
				URL:        c.getCommitURL(commit.ID.String()),
				ShortID:    getShortID(commit.ID.String()),
				SummaryStr: commit.Summary(),
				AuthorStr:  commit.Author.Name,
				WhenStr:    commit.Author.When.Format(time.DateOnly),
				Commit:     commit,
				Refs:       tags,
			})
		}

		c.writeLog(pageData, logs)

		for _, cm := range logs {
			wg.Add(1)
			go func(commit *CommitData) {
				defer wg.Done()
				c.writeLogDiff(repo, pageData, commit)
			}(cm)
		}
	}()

	tree, err := repo.LsTree(pageData.RevData.ID())
	bail(err)

	readme := ""
	entries := make(chan *TreeItem)
	subtrees := make(chan *TreeRoot)
	tw := &TreeWalker{
		Config:   c,
		PageData: pageData,
		Repo:     repo,
		treeItem: entries,
		tree:     subtrees,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tw.walk(tree, "")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range entries {
			wg.Add(1)
			go func(entry *TreeItem) {
				defer wg.Done()
				if entry.IsDir {
					return
				}

				readmeStr := c.writeHTMLTreeFile(pageData, entry)
				if readmeStr != "" {
					readme = readmeStr
				}
			}(e)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for t := range subtrees {
			wg.Add(1)
			go func(tree *TreeRoot) {
				defer wg.Done()
				c.writeTree(pageData, tree)
			}(t)
		}
	}()

	wg.Wait()

	c.Logger.Info(
		"compilation complete",
		"repoName", c.RepoName,
		"revision", pageData.RevData.Name(),
	)

	output.Readme = readme
	return output
}

func style(theme chroma.Style) string {
	bg := theme.Get(chroma.Background)
	txt := theme.Get(chroma.Text)
	kw := theme.Get(chroma.Keyword)
	nv := theme.Get(chroma.NameVariable)
	cm := theme.Get(chroma.Comment)
	ln := theme.Get(chroma.LiteralNumber)
	return fmt.Sprintf(`:root {
  --bg-color: %s;
  --text-color: %s;
  --border: %s;
  --link-color: %s;
  --hover: %s;
  --visited: %s;
}`,
		bg.Background.String(),
		txt.Colour.String(),
		cm.Colour.String(),
		nv.Colour.String(),
		kw.Colour.String(),
		ln.Colour.String(),
	)
}

func main() {
	formatter := html.New(
		html.WithLineNumbers(true),
		html.WithLinkableLineNumbers(true, ""),
		html.WithClasses(true),
	)

	logger := slog.Default()

	configFile := "pgit.yaml"

	app := &cli.Command{
		Name: "pgit",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "out",
				Value:   "./public",
				Usage:   "output directory",
				Sources: cli.NewValueSourceChain(yaml.YAML("out", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "repo",
				Value:   ".",
				Usage:   "path to git repo",
				Sources: cli.NewValueSourceChain(yaml.YAML("repo", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringSliceFlag{
				Name:    "revs",
				Value:   []string{"HEAD"},
				Usage:   "list of revs to generate logs and tree (e.g. main,v1,c69f86f,HEAD)",
				Sources: cli.NewValueSourceChain(yaml.YAML("revs", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "theme",
				Value:   "dracula",
				Usage:   "theme to use for syntax highlighting",
				Sources: cli.NewValueSourceChain(yaml.YAML("theme", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "label",
				Value:   "",
				Usage:   "pretty name for the subdir where we create the repo, default is last folder in --repo",
				Sources: cli.NewValueSourceChain(yaml.YAML("label", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "clone-url",
				Value:   "",
				Usage:   "git clone URL for upstream",
				Sources: cli.NewValueSourceChain(yaml.YAML("cloneUrl", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "home-url",
				Value:   "",
				Usage:   "URL for breadcrumbs to go to root page, hidden if empty",
				Sources: cli.NewValueSourceChain(yaml.YAML("homeUrl", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "desc",
				Value:   "",
				Usage:   "description for repo",
				Sources: cli.NewValueSourceChain(yaml.YAML("desc", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:    "root-relative",
				Value:   "/",
				Usage:   "html root relative",
				Sources: cli.NewValueSourceChain(yaml.YAML("rootRelative", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.IntFlag{
				Name:    "max-commits",
				Value:   0,
				Usage:   "maximum number of commits to generate",
				Sources: cli.NewValueSourceChain(yaml.YAML("maxCommits", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.BoolFlag{
				Name:    "hide-tree-last-commit",
				Value:   false,
				Usage:   "dont calculate last commit for each file in the tree",
				Sources: cli.NewValueSourceChain(yaml.YAML("hideTreeLastCommit", altsrc.NewStringPtrSourcer(&configFile))),
			},
			&cli.StringFlag{
				Name:  "config",
				Value: "pgit.yaml",
				Usage: "path to config file",
			},
		},

Action: func(ctx context.Context, cmd *cli.Command) error {
			configFile := cmd.String("config")
			argsProvided := false
			for _, flag := range cmd.Flags {
				if flag.IsSet() {
					argsProvided = true
					break
				}
			}
			if !argsProvided && !cmd.IsSet("config") {
				_, err := os.Stat(configFile)
				if os.IsNotExist(err) {
					return fmt.Errorf("no parameters provided and config file %s does not exist", configFile)
				}
			}

			config := &RepoConfig{
				Outdir:             cmd.String("out"),
				RepoPath:           cmd.String("repo"),
				Revs:               cmd.StringSlice("revs"),
				ThemeName:          cmd.String("theme"),
				Label:              cmd.String("label"),
				CloneURL:           cmd.String("clone-url"),
				HomeURL:            cmd.String("home-url"),
				Desc:               cmd.String("desc"),
				RootRelative:       cmd.String("root-relative"),
				MaxCommits:         int(cmd.Int("max-commits")),
				HideTreeLastCommit: cmd.Bool("hide-tree-last-commit"),
			}

			if config.Label == "" {
				config.Label = repoName(config.RepoPath)
			}
			config.RepoName = config.Label
			if len(config.Revs) == 0 {
				bail(fmt.Errorf("you must provide revs"))
			}
			config.Cache = make(map[string]bool)
			config.Logger = logger
			config.Theme = styles.Get(config.ThemeName)
			if config.Theme == nil {
				config.Theme = styles.Fallback
			}
			config.Formatter = formatter

			config.writeRepo()

			err := config.copyStatic("static")
			bail(err)

			stylesCss := style(*config.Theme)
			err = os.WriteFile(filepath.Join(config.Outdir, "vars.css"), []byte(stylesCss), 0644)
			bail(err)

			fp := filepath.Join(config.Outdir, "syntax.css")
			w, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			bail(err)
			err = formatter.WriteCSS(w, config.Theme)
			bail(err)

			url := filepath.Join("/", "index.html")
			config.Logger.Info("root url", "url", url)

			return nil
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		panic(err)
	}

	// TODO: Use logger for http.ListenAndServe(":"+"1313", nil) as well
	// TODO: Do not hardcode port
	if strings.HasPrefix(os.Args[0], filepath.Join(os.TempDir(), "go-build")) {
		if err := os.Chdir(app.String("out")); err != nil {
			panic(fmt.Sprintf("Failed to change directory to %q: %v", app.String("out"), err))
		}
		http.Handle("/", http.FileServer(http.Dir(".")))
		logger.Info("Serving %s on HTTP port: %s\n", app.String("out"), "1313")
		http.ListenAndServe(":"+"1313", nil)
	}
}
