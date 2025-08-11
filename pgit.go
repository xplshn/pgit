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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters/html"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/dustin/go-humanize"
	"github.com/gogs/git-module"
	"github.com/h2non/filetype"
	"github.com/urfave/cli/v3"
	"github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli-altsrc/v3/yaml"
	"github.com/xplshn/tracerr2"
)

//go:embed html/*.tmpl
var embedFS embed.FS

//go:embed static/*
var staticFS embed.FS

type RepoConfig struct {
	Outdir             string `yaml:"out"`
	RepoPath           string `yaml:"repo"`
	Revs               []string `yaml:"revs"`
	Desc               string `yaml:"desc"`
	MaxCommits         int `yaml:"max-commits"`
	Readme             string `yaml:"readme"`
	HideTreeLastCommit bool `yaml:"hide-tree-last-commit"`
	HomeURL            string `yaml:"home-url"`
	CloneURL           string `yaml:"clone-url"`
	RootRelative       string `yaml:"root-relative"`
	ThemeName          string `yaml:"theme"`
	Label              string `yaml:"label"`
	Cache              map[string]bool
	Mutex              sync.RWMutex
	RepoName           string
	Logger             *slog.Logger
	Theme              *chroma.Style
	Formatter          *html.Formatter
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
	ID      string       `json:"ID"`
	Refspec string       `json:"Refspec"`
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

func (c *RepoConfig) parseText(filename string, text string, blob *git.Blob) (string, string, error) {
	if blob != nil && blob.Size() > 800*1024 {
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
		return text, lang, tracerr.Errorf("%v", err)
	}
	var buf bytes.Buffer
	err = c.Formatter.Format(&buf, c.Theme, iterator)
	if err != nil {
		return text, lang, tracerr.Errorf("%v", err)
	}
	return buf.String(), lang, nil
}

func isText(s string) bool {
	const max = 1024
	if len(s) > max {
		s = s[0:max]
	}
	for i, c := range s {
		if i+utf8.UTFMax > len(s) {
			break
		}
		if c == 0xFFFD || c < ' ' && c != '\n' && c != '\t' && c != '\f' && c != '\r' {
			return false
		}
	}
	return true
}

func isTextFile(text string, blob *git.Blob) bool {
	if blob != nil && blob.Size() > 800*1024 {
		return false
	}

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

func (c *RepoConfig) writeHtml(writeData *WriteData) error {
	ts, err := template.ParseFS(
		embedFS,
		writeData.Template,
		"html/header.partial.tmpl",
		"html/footer.partial.tmpl",
		"html/base.layout.tmpl",
	)
	if err != nil {
		c.Logger.Error("failed to parse templates", "error", err)
		return tracerr.Errorf("%v", err)
	}

	dir := filepath.Join(c.Outdir, writeData.Subdir)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		c.Logger.Error("failed to create directory", "dir", dir, "error", err)
		return tracerr.Errorf("%v", err)
	}

	fp := filepath.Join(dir, writeData.Filename)
	c.Logger.Info("writing", "filepath", fp)

	w, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		c.Logger.Error("failed to open file for writing", "filepath", fp, "error", err)
		return tracerr.Errorf("%v", err)
	}
	defer w.Close()

	if err := ts.Execute(w, writeData.Data); err != nil {
		c.Logger.Error("failed to execute template", "filepath", fp, "error", err)
		return tracerr.Errorf("%v", err)
	}
	return nil
}

func (c *RepoConfig) copyStatic(dir string) error {
	entries, err := staticFS.ReadDir(dir)
	if err != nil {
		c.Logger.Error("failed to read static directory", "dir", dir, "error", err)
		return tracerr.Errorf("%v", err)
	}

	for _, e := range entries {
		infp := filepath.Join(dir, e.Name())
		if e.IsDir() {
			continue
		}

		w, err := staticFS.ReadFile(infp)
		if err != nil {
			c.Logger.Error("failed to read static file", "file", infp, "error", err)
			return tracerr.Errorf("%v", err)
		}
		fp := filepath.Join(c.Outdir, e.Name())
		c.Logger.Info("writing", "filepath", fp)
		if err := os.WriteFile(fp, w, 0644); err != nil {
			c.Logger.Error("failed to write static file", "file", fp, "error", err)
			return tracerr.Errorf("%v", err)
		}
	}

	return nil
}

func (c *RepoConfig) writeRootSummary(data *PageData, readme template.HTML) {
	c.Logger.Info("writing root html", "repoPath", c.RepoPath)
	if err := c.writeHtml(&WriteData{
		Filename: "index.html",
		Template: "html/summary.page.tmpl",
		Data: &SummaryPageData{
			PageData: data,
			Readme:   readme,
		},
	}); err != nil {
		c.Logger.Error("failed to write root summary", "error", err)
	}
}

func (c *RepoConfig) writeTree(data *PageData, tree *TreeRoot) {
	c.Logger.Info("writing tree", "treePath", tree.Path)
	if err := c.writeHtml(&WriteData{
		Filename: "index.html",
		Subdir:   tree.Path,
		Template: "html/tree.page.tmpl",
		Data: &TreePageData{
			PageData: data,
			Tree:     tree,
		},
	}); err != nil {
		c.Logger.Error("failed to write tree", "path", tree.Path, "error", err)
	}
}

func (c *RepoConfig) writeLog(data *PageData, logs []*CommitData) {
	c.Logger.Info("writing log file", "revision", data.RevData.Name())
	if err := c.writeHtml(&WriteData{
		Filename: "index.html",
		Subdir:   getLogBaseDir(data.RevData),
		Template: "html/log.page.tmpl",
		Data: &LogPageData{
			PageData:   data,
			NumCommits: len(logs),
			Logs:       logs,
		},
	}); err != nil {
		c.Logger.Error("failed to write log", "revision", data.RevData.Name(), "error", err)
	}
}

func (c *RepoConfig) writeRefs(data *PageData, refs []*RefInfo) {
	c.Logger.Info("writing refs", "repoPath", c.RepoPath)
	if err := c.writeHtml(&WriteData{
		Filename: "refs.html",
		Template: "html/refs.page.tmpl",
		Data: &RefPageData{
			PageData: data,
			Refs:     refs,
		},
	}); err != nil {
		c.Logger.Error("failed to write refs html", "error", err)
		return
	}

	jsonData, err := json.Marshal(refs)
	if err != nil {
		c.Logger.Error("failed to marshal refs to json", "error", err)
		return
	}
	fp := filepath.Join(c.Outdir, "refs.json")
	if err := os.WriteFile(fp, jsonData, 0644); err != nil {
		c.Logger.Error("failed to write refs.json", "error", err)
	}
}

func (c *RepoConfig) writeHTMLTreeFile(pageData *PageData, treeItem *TreeItem) (string, error) {
	readme := ""
	b, err := treeItem.Entry.Blob().Bytes()
	if err != nil {
		c.Logger.Error("failed to get blob bytes", "file", treeItem.Path, "error", err)
		return "", tracerr.Errorf("%v", err)
	}
	str := string(b)

	treeItem.IsTextFile = isTextFile(str, treeItem.Entry.Blob())

	contentsStr := "binary file, cannot display"
	lang := ""
	numLines := 0
	if treeItem.IsTextFile {
		numLines = len(strings.Split(str, "\n"))
		var parseErr error
		contentsStr, lang, parseErr = c.parseText(treeItem.Entry.Name(), str, treeItem.Entry.Blob())
		if parseErr != nil {
			c.Logger.Error("failed to parse text file", "file", treeItem.Entry.Name(), "error", parseErr)
			return "", tracerr.Errorf("%v", parseErr)
		}
	}
	treeItem.NumLines = numLines

	d := filepath.Dir(treeItem.Path)

	nameLower := strings.ToLower(treeItem.Entry.Name())
	summary := readmeFile(pageData.Repo)
	if d == "." && nameLower == summary {
		readme = contentsStr
	}

	if err := c.writeHtml(&WriteData{
		Filename: fmt.Sprintf("%s.html", treeItem.Entry.Name()),
		Template: "html/file.page.tmpl",
		Data: &FilePageData{
			PageData: pageData,
			Contents: template.HTML(contentsStr),
			Item:     treeItem,
			Language: lang,
		},
		Subdir: getFileDir(pageData.RevData, d),
	}); err != nil {
		c.Logger.Error("failed to write html tree file", "file", treeItem.Entry.Name(), "error", err)
		return "", tracerr.Errorf("%v", err)
	}
	return readme, nil
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
		finContent, _, parseErr := c.parseText("commit.diff", content, nil)
		if parseErr != nil {
			c.Logger.Error("failed to parse diff content", "commitID", getShortID(commitID), "error", parseErr)
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

	if err := c.writeHtml(&WriteData{
		Filename: fmt.Sprintf("%s.html", commitID),
		Template: "html/commit.page.tmpl",
		Subdir:   "commits",
		Data:     commitData,
	}); err != nil {
		c.Logger.Error("failed to write log diff", "commit", getShortID(commitID), "error", err)
	}
}

func (c *RepoConfig) getSummaryURL() template.URL {
	url := c.RootRelative + "index.html"
	return template.URL(url)
}

func (c *RepoConfig) getRefsURL() template.URL {
	url := c.RootRelative + "refs.html"
	return template.URL(url)
}

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
	if len(id) < 7 {
		return id
	}
	return id[:7]
}

func (c *RepoConfig) writeRepo() (*BranchOutput, error) {
	c.Logger.Info("writing repo", "repoPath", c.RepoPath)
	repo, err := git.Open(c.RepoPath)
	if err != nil {
		c.Logger.Error("failed to open git repository", "path", c.RepoPath, "error", err)
		return nil, tracerr.Errorf("%v", err)
	}

	refs, err := repo.ShowRef(git.ShowRefOptions{Heads: true, Tags: true})
	if err != nil {
		c.Logger.Error("failed to get refs", "error", err)
		return nil, tracerr.Errorf("%v", err)
	}

	var first *RevData
	revs := []*RevData{}
	for _, revStr := range c.Revs {
		fullRevID, err := repo.RevParse(revStr)
		if err != nil {
			c.Logger.Error("failed to parse revision", "rev", revStr, "error", err)
			return nil, tracerr.Errorf("%v", err)
		}

		revName := getShortID(fullRevID)
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
		err := tracerr.New("could not find a git reference that matches criteria")
		c.Logger.Error(err.Error())
		return nil, err
	}

	refInfoMap := map[string]*RefInfo{}
	for _, revData := range revs {
		refInfoMap[revData.Name()] = &RefInfo{
			ID:      revData.ID(),
			Refspec: revData.Name(),
			URL:     revData.TreeURL(),
		}
	}

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
			branchOutput, err := c.writeRevision(repo, data, refInfoList)
			if err != nil {
				c.Logger.Error("failed to write main revision", "rev", revData.Name(), "error", err)
				return nil, tracerr.Errorf("%v", err)
			}
			mainOutput = branchOutput
		} else {
			wg.Add(1)
			go func(d *PageData) {
				defer wg.Done()
				if _, err := c.writeRevision(repo, d, refInfoList); err != nil {
					c.Logger.Error("failed to write revision", "rev", d.RevData.Name(), "error", err)
				}
			}(data)
		}
	}
	wg.Wait()

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
	return mainOutput, nil
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
	errChan            chan error
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
	if icon == "" {
		return ""
	}

	return fmt.Sprintf("devicon-%s-original", icon)
}

func (tw *TreeWalker) NewTreeItem(entry *git.TreeEntry, curpath string, crumbs []*Breadcrumb) (*TreeItem, error) {
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

	if !tw.HideTreeLastCommit {
		id := tw.PageData.RevData.ID()
		lastCommits, err := tw.Repo.RevList([]string{id}, git.RevListOptions{
			Path:           item.Path,
			CommandOptions: git.CommandOptions{Args: []string{"-1"}},
		})
		if err != nil {
			tw.Config.Logger.Error("failed to get last commit for file", "path", item.Path, "error", err)
			return nil, tracerr.Errorf("%v", err)
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

	return item, nil
}

func (tw *TreeWalker) walk(tree *git.Tree, curpath string) {
	defer func() {
		if curpath == "" {
			close(tw.tree)
			close(tw.treeItem)
		}
	}()

	entries, err := tree.Entries()
	if err != nil {
		tw.errChan <- tracerr.Errorf("%v", err)
		return
	}

	crumbs := tw.calcBreadcrumbs(curpath)
	treeEntries := []*TreeItem{}
	for _, entry := range entries {
		typ := entry.Type()
		item, err := tw.NewTreeItem(entry, curpath, crumbs)
		if err != nil {
			tw.errChan <- err
			return
		}

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
	if curpath == "" {
		fpath = getTreeBaseDir(tw.PageData.RevData)
	}

	tw.tree <- &TreeRoot{
		Path:   fpath,
		Items:  treeEntries,
		Crumbs: crumbs,
	}
}

func (c *RepoConfig) writeRevision(repo *git.Repository, pageData *PageData, refs []*RefInfo) (*BranchOutput, error) {
	c.Logger.Info(
		"compiling revision",
		"repoName", c.RepoName,
		"revision", pageData.RevData.Name(),
	)

	output := &BranchOutput{}
	var wg sync.WaitGroup
	errChan := make(chan error, 10)

	wg.Add(1)
	go func() {
		defer wg.Done()

		pageSize := pageData.Repo.MaxCommits
		if pageSize == 0 {
			pageSize = 5000
		}
		commits, err := repo.CommitsByPage(pageData.RevData.ID(), 0, pageSize)
		if err != nil {
			c.Logger.Error("failed to get commits", "rev", pageData.RevData.ID(), "error", err)
			errChan <- tracerr.Errorf("%v", err)
			return
		}

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
	if err != nil {
		c.Logger.Error("failed to list tree", "rev", pageData.RevData.ID(), "error", err)
		return nil, tracerr.Errorf("%v", err)
	}

	readme := ""
	entries := make(chan *TreeItem)
	subtrees := make(chan *TreeRoot)
	tw := &TreeWalker{
		Config:   c,
		PageData: pageData,
		Repo:     repo,
		treeItem: entries,
		tree:     subtrees,
		errChan:  errChan,
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		tw.walk(tree, "")
	}()

	var readmeMutex sync.Mutex
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

				readmeStr, err := c.writeHTMLTreeFile(pageData, entry)
				if err != nil {
					errChan <- err
					return
				}
				if readmeStr != "" {
					readmeMutex.Lock()
					readme = readmeStr
					readmeMutex.Unlock()
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
		return nil, err
	}

	c.Logger.Info(
		"compilation complete",
		"repoName", c.RepoName,
		"revision", pageData.RevData.Name(),
	)

	output.Readme = readme
	return output, nil
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

func isPortAvailable(port string, logger *slog.Logger) bool {
	logger.Info("checking port availability", "port", port)
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		logger.Warn("port is not available", "port", port, "error", err)
		return false
	}
	_ = ln.Close()
	logger.Info("port is available", "port", port)
	return true
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
				Value:   "gruvbox-light",
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
			&cli.StringFlag{
				Name:  "port",
				Value: "1313",
				Usage: "port for the http server",
			},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			configFile := cmd.String("config")
			if cmd.NumFlags() == 0 {
				if _, err := os.Stat(configFile); os.IsNotExist(err) {
					return tracerr.Errorf("no parameters provided and config file %s does not exist", configFile)
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
				return tracerr.New("you must provide revs")
			}
			config.Cache = make(map[string]bool)
			config.Logger = logger
			config.Theme = styles.Get(config.ThemeName)
			if config.Theme == nil {
				config.Theme = styles.Fallback
			}
			config.Formatter = formatter

			if _, err := config.writeRepo(); err != nil {
				return tracerr.Errorf("%v", err)
			}

			if err := config.copyStatic("static"); err != nil {
				return tracerr.Errorf("%v", err)
			}

			stylesCss := style(*config.Theme)
			if err := os.WriteFile(filepath.Join(config.Outdir, "vars.css"), []byte(stylesCss), 0644); err != nil {
				logger.Error("failed to write vars.css", "error", err)
				return tracerr.Errorf("%v", err)
			}

			fp := filepath.Join(config.Outdir, "syntax.css")
			w, err := os.OpenFile(fp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				logger.Error("failed to open syntax.css for writing", "error", err)
				return tracerr.Errorf("%v", err)
			}
			defer w.Close()
			if err = formatter.WriteCSS(w, config.Theme); err != nil {
				logger.Error("failed to write syntax.css", "error", err)
				return tracerr.Errorf("%v", err)
			}

			url := filepath.Join("/", "index.html")
			config.Logger.Info("root url", "url", url)

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

	fmt.Println(strings.HasPrefix(os.Args[0], filepath.Join(os.TempDir(), "go-build")))

	if strings.HasPrefix(os.Args[0], filepath.Join(os.TempDir(), "go-build")) {
		outDir := app.String("out")
		port := app.String("port")

		if !isPortAvailable(port, logger) {
			err := tracerr.Errorf("port %s is already in use", port)
			err.Print()
			os.Exit(1)
		}

		if err := os.Chdir(outDir); err != nil {
			err := tracerr.Errorf("failed to change directory to %q: %v", outDir, err)
			err.Print()
			os.Exit(1)
		}

		server := &http.Server{
			Addr: ":" + port,
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				logger.Info("request received", "method", r.Method, "url", r.URL.String())
				http.FileServer(http.Dir(".")).ServeHTTP(w, r)
			}),
			ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
		}

		logger.Info("serving content", "directory", outDir, "port", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			err := tracerr.Errorf("http server failed: %v", err)
			err.Print()
			os.Exit(1)
		}
	}
}
