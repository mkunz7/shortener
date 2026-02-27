package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

const (
	defaultAddr   = ":8080"
	pageSize      = 5
	sessionName   = "shortener_session"
	adminUsername = "admin"
)

type App struct {
	db              *sql.DB
	tpl             *template.Template
	sc              *securecookie.SecureCookie
	baseURL         string
	basePath        string
	excludedDomains map[string]struct{}
}

type Link struct {
	ID        int64
	ShortCode string
	LongURL   string
	Clicks    int64
	CreatedAt time.Time
}

type LoginPageData struct {
	Error    string
	BasePath string
}

type AdminPageData struct {
	Username    string
	Links       []Link
	Search      string
	ResultCount int
	TotalLinks  int
	Page        int
	TotalPages  int
	HasPrev     bool
	HasNext     bool
	PrevPage    int
	NextPage    int
	Error       string
	Success     string
	BaseURL     string
	BasePath    string
}

func main() {
	defaultDBPath := "shortener.db"
	addr := flag.String("a", defaultAddr, "listen address")
	basePathFlag := flag.String("b", "/", "base path when served behind reverse proxy (example: /shortener)")
	dbPath := flag.String("d", defaultDBPath, "path to SQLite database")
	excludedDomainsFlag := flag.String("e", "", "comma separated domains to block as link targets (example: example.com,bad.com)")
	resetAdmin := flag.Bool("r", false, "resets the admin password and prints a new one to console")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintln(flag.CommandLine.Output(), "Options:")
		flag.PrintDefaults()
	}
	flag.Parse()

	baseURL := ""
	basePath, err := normalizeBasePath(*basePathFlag)
	if err != nil {
		log.Fatalf("invalid base path: %v", err)
	}
	excludedDomains := parseDomainList(*excludedDomainsFlag)

	db, err := sql.Open("sqlite", *dbPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer db.Close()

	if err := initDB(db); err != nil {
		log.Fatalf("init db: %v", err)
	}

	if err := ensureAdminUser(db); err != nil {
		log.Fatalf("ensure admin user: %v", err)
	}
	if *resetAdmin {
		if err := resetAdminPassword(db); err != nil {
			log.Fatalf("reset admin password: %v", err)
		}
	}
	dbAbsPath, err := filepath.Abs(*dbPath)
	if err != nil {
		log.Fatalf("resolve db path: %v", err)
	}
	userCount, err := countRows(db, "users")
	if err != nil {
		log.Fatalf("count users: %v", err)
	}
	linkCount, err := countRows(db, "links")
	if err != nil {
		log.Fatalf("count links: %v", err)
	}

	tpl, err := template.ParseFiles(
		"templates/login.html",
		"templates/admin.html",
	)
	if err != nil {
		log.Fatalf("parse templates: %v", err)
	}

	authKey := keyFromEnv("SESSION_AUTH_KEY", 32)
	encKey := keyFromEnv("SESSION_ENC_KEY", 32)
	app := &App{
		db:              db,
		tpl:             tpl,
		sc:              securecookie.New(authKey, encKey),
		baseURL:         baseURL,
		basePath:        basePath,
		excludedDomains: excludedDomains,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.rootHandler)

	log.Printf("database: %s | users: %d | links: %d", dbAbsPath, userCount, linkCount)
	log.Printf("listening on %s", *addr)
	if err := http.ListenAndServe(*addr, withLogging(mux)); err != nil {
		log.Fatal(err)
	}
}

func initDB(db *sql.DB) error {
	schema := `
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS links (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	short_code TEXT NOT NULL UNIQUE,
	long_url TEXT NOT NULL,
	clicks INTEGER NOT NULL DEFAULT 0,
	created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_links_short_code ON links(short_code);
`
	_, err := db.Exec(schema)
	return err
}

func ensureAdminUser(db *sql.DB) error {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, adminUsername).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	password, err := generatePassword(16)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if _, err := db.Exec(`INSERT INTO users(username, password_hash) VALUES(?, ?)`, adminUsername, string(hash)); err != nil {
		return err
	}

	fmt.Println("========================================")
	fmt.Println("First run detected. Admin user created:")
	fmt.Printf("username: %s\n", adminUsername)
	fmt.Printf("password: %s\n", password)
	fmt.Println("Please log in and change this password.")
	fmt.Println("========================================")
	return nil
}

func resetAdminPassword(db *sql.DB) error {
	password, err := generatePassword(16)
	if err != nil {
		return err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	res, err := db.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, string(hash), adminUsername)
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return fmt.Errorf("admin user %q not found", adminUsername)
	}

	fmt.Println("========================================")
	fmt.Println("Admin password reset complete:")
	fmt.Printf("username: %s\n", adminUsername)
	fmt.Printf("password: %s\n", password)
	fmt.Println("========================================")
	return nil
}

func (a *App) rootHandler(w http.ResponseWriter, r *http.Request) {
	path, ok := a.stripBasePath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}

	if path == "/" {
		if a.isAuthenticated(r) {
			http.Redirect(w, r, a.path("/admin"), http.StatusSeeOther)
			return
		}
		http.Redirect(w, r, a.path("/login"), http.StatusSeeOther)
		return
	}

	switch path {
	case "/login":
		a.loginHandler(w, r)
	case "/logout":
		a.logoutHandler(w, r)
	case "/admin":
		a.authMiddleware(a.adminHandler)(w, r)
	case "/admin/links/create":
		a.authMiddleware(a.createLinkHandler)(w, r)
	case "/admin/links/update":
		a.authMiddleware(a.updateLinkHandler)(w, r)
	case "/admin/links/delete":
		a.authMiddleware(a.deleteLinkHandler)(w, r)
	case "/admin/password":
		a.authMiddleware(a.changePasswordHandler)(w, r)
	default:
		a.redirectHandler(w, r, path)
	}
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		a.renderLogin(w, "")
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		a.renderLogin(w, "invalid form")
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	var hash string
	err := a.db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, username).Scan(&hash)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		a.renderLogin(w, "invalid credentials")
		return
	}

	if err := a.setSession(w, username); err != nil {
		http.Error(w, "failed to set session", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, a.path("/admin"), http.StatusSeeOther)
}

func (a *App) logoutHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionName,
		Value:    "",
		Path:     a.cookiePath(),
		HttpOnly: true,
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, a.path("/login"), http.StatusSeeOther)
}

func (a *App) adminHandler(w http.ResponseWriter, r *http.Request) {
	page := parsePage(r.URL.Query().Get("page"))
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	offset := (page - 1) * pageSize

	filter := "%"
	if search != "" {
		filter = "%" + search + "%"
	}
	rows, err := a.db.Query(`
		SELECT id, short_code, long_url, clicks, created_at
		FROM links
		WHERE short_code LIKE ? OR long_url LIKE ?
		ORDER BY id ASC
		LIMIT ? OFFSET ?
	`, filter, filter, pageSize, offset)
	if err != nil {
		http.Error(w, "failed to load links", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	links := make([]Link, 0, pageSize)
	for rows.Next() {
		var l Link
		if err := rows.Scan(&l.ID, &l.ShortCode, &l.LongURL, &l.Clicks, &l.CreatedAt); err != nil {
			http.Error(w, "failed to scan links", http.StatusInternalServerError)
			return
		}
		links = append(links, l)
	}

	var total int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM links WHERE short_code LIKE ? OR long_url LIKE ?`, filter, filter).Scan(&total); err != nil {
		http.Error(w, "failed to count links", http.StatusInternalServerError)
		return
	}
	var totalLinks int
	if err := a.db.QueryRow(`SELECT COUNT(*) FROM links`).Scan(&totalLinks); err != nil {
		http.Error(w, "failed to count total links", http.StatusInternalServerError)
		return
	}
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))
	if totalPages == 0 {
		totalPages = 1
	}

	if page > totalPages {
		qv := url.Values{}
		qv.Set("page", strconv.Itoa(totalPages))
		if search != "" {
			qv.Set("q", search)
		}
		http.Redirect(w, r, a.path("/admin")+"?"+qv.Encode(), http.StatusSeeOther)
		return
	}

	data := AdminPageData{
		Username:    adminUsername,
		Links:       links,
		Search:      search,
		ResultCount: total,
		TotalLinks:  totalLinks,
		Page:        page,
		TotalPages:  totalPages,
		HasPrev:     page > 1,
		HasNext:     page < totalPages,
		PrevPage:    page - 1,
		NextPage:    page + 1,
		Error:       r.URL.Query().Get("error"),
		Success:     r.URL.Query().Get("success"),
		BaseURL:     a.baseURL,
		BasePath:    a.basePath,
	}
	if err := a.tpl.ExecuteTemplate(w, "admin.html", data); err != nil {
		http.Error(w, "failed to render page", http.StatusInternalServerError)
	}
}

func (a *App) createLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.redirectWithMessage(w, r, "invalid form", "")
		return
	}

	longURL := strings.TrimSpace(r.FormValue("long_url"))
	code := strings.TrimSpace(r.FormValue("short_code"))
	if longURL == "" {
		a.redirectWithMessage(w, r, "long URL is required", "")
		return
	}
	if err := a.validateTargetURL(longURL); err != nil {
		a.redirectWithMessage(w, r, err.Error(), "")
		return
	}
	var existingCode string
	err := a.db.QueryRow(`SELECT short_code FROM links WHERE long_url = ? LIMIT 1`, longURL).Scan(&existingCode)
	if err == nil {
		a.redirectWithMessage(w, r, "", fmt.Sprintf("short code: %s", existingCode))
		return
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		a.redirectWithMessage(w, r, "failed to check existing link", "")
		return
	}

	if code == "" {
		nextCode, err := a.nextCode()
		if err != nil {
			a.redirectWithMessage(w, r, "failed to generate code", "")
			return
		}
		code = nextCode
	}

	if !isValidCode(code) {
		a.redirectWithMessage(w, r, "short code can only contain [0-9a-zA-Z_-]", "")
		return
	}
	if isReservedCode(code) {
		a.redirectWithMessage(w, r, "short code is reserved by the application", "")
		return
	}

	_, err = a.db.Exec(`INSERT INTO links(short_code, long_url) VALUES(?, ?)`, code, longURL)
	if err != nil {
		if isUniqueConstraintErr(err) {
			a.redirectWithMessage(w, r, "short code already exists", "")
			return
		}
		a.redirectWithMessage(w, r, "failed to create link", "")
		return
	}
	a.redirectWithMessage(w, r, "", fmt.Sprintf("link created: %s", code))
}

func (a *App) updateLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.redirectWithMessage(w, r, "invalid form", "")
		return
	}

	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		a.redirectWithMessage(w, r, "invalid link id", "")
		return
	}
	longURL := strings.TrimSpace(r.FormValue("long_url"))
	code := strings.TrimSpace(r.FormValue("short_code"))
	if longURL == "" || code == "" {
		a.redirectWithMessage(w, r, "short code and long URL are required", "")
		return
	}
	if err := a.validateTargetURL(longURL); err != nil {
		a.redirectWithMessage(w, r, err.Error(), "")
		return
	}
	if !isValidCode(code) {
		a.redirectWithMessage(w, r, "short code can only contain [0-9a-zA-Z_-]", "")
		return
	}
	if isReservedCode(code) {
		a.redirectWithMessage(w, r, "short code is reserved by the application", "")
		return
	}

	_, err = a.db.Exec(`UPDATE links SET short_code = ?, long_url = ? WHERE id = ?`, code, longURL, id)
	if err != nil {
		if isUniqueConstraintErr(err) {
			a.redirectWithMessage(w, r, "short code already exists", "")
			return
		}
		a.redirectWithMessage(w, r, "failed to update link", "")
		return
	}
	a.redirectWithMessage(w, r, "", "link updated")
}

func (a *App) deleteLinkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.redirectWithMessage(w, r, "invalid form", "")
		return
	}
	id, err := strconv.ParseInt(r.FormValue("id"), 10, 64)
	if err != nil {
		a.redirectWithMessage(w, r, "invalid link id", "")
		return
	}
	if _, err := a.db.Exec(`DELETE FROM links WHERE id = ?`, id); err != nil {
		a.redirectWithMessage(w, r, "failed to delete link", "")
		return
	}
	a.redirectWithMessage(w, r, "", "link deleted")
}

func (a *App) changePasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		a.redirectWithMessage(w, r, "invalid form", "")
		return
	}

	current := r.FormValue("current_password")
	newPw := r.FormValue("new_password")
	confirm := r.FormValue("confirm_password")

	if newPw == "" || newPw != confirm {
		a.redirectWithMessage(w, r, "new passwords do not match", "")
		return
	}

	var hash string
	if err := a.db.QueryRow(`SELECT password_hash FROM users WHERE username = ?`, adminUsername).Scan(&hash); err != nil {
		a.redirectWithMessage(w, r, "failed to load account", "")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(current)) != nil {
		a.redirectWithMessage(w, r, "current password is incorrect", "")
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPw), bcrypt.DefaultCost)
	if err != nil {
		a.redirectWithMessage(w, r, "failed to hash password", "")
		return
	}

	if _, err := a.db.Exec(`UPDATE users SET password_hash = ? WHERE username = ?`, string(newHash), adminUsername); err != nil {
		a.redirectWithMessage(w, r, "failed to update password", "")
		return
	}
	a.redirectWithMessage(w, r, "", "password changed")
}

func (a *App) redirectHandler(w http.ResponseWriter, r *http.Request, reqPath string) {
	if reqPath == "/" {
		http.NotFound(w, r)
		return
	}
	code := strings.TrimPrefix(reqPath, "/")
	if strings.Contains(code, "/") {
		http.NotFound(w, r)
		return
	}
	if code == "" {
		http.NotFound(w, r)
		return
	}

	var longURL string
	err := a.db.QueryRow(`SELECT long_url FROM links WHERE short_code = ?`, code).Scan(&longURL)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		http.Error(w, "failed to resolve link", http.StatusInternalServerError)
		return
	}

	if _, err := a.db.Exec(`UPDATE links SET clicks = clicks + 1 WHERE short_code = ?`, code); err != nil {
		log.Printf("failed to increment click counter for %s: %v", code, err)
	}

	http.Redirect(w, r, longURL, http.StatusFound)
}

func (a *App) authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.isAuthenticated(r) {
			http.Redirect(w, r, a.path("/login"), http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (a *App) isAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionName)
	if err != nil {
		return false
	}
	value := map[string]string{}
	if err := a.sc.Decode(sessionName, cookie.Value, &value); err != nil {
		return false
	}
	return value["username"] == adminUsername
}

func (a *App) setSession(w http.ResponseWriter, username string) error {
	encoded, err := a.sc.Encode(sessionName, map[string]string{"username": username})
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionName,
		Value:    encoded,
		Path:     a.cookiePath(),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   false,
		MaxAge:   86400,
	})
	return nil
}

func (a *App) renderLogin(w http.ResponseWriter, errMsg string) {
	if err := a.tpl.ExecuteTemplate(w, "login.html", LoginPageData{Error: errMsg, BasePath: a.basePath}); err != nil {
		http.Error(w, "failed to render login", http.StatusInternalServerError)
	}
}

func (a *App) redirectWithMessage(w http.ResponseWriter, r *http.Request, errMsg, success string) {
	q := url.Values{}
	if errMsg != "" {
		q.Set("error", errMsg)
	}
	if success != "" {
		q.Set("success", success)
	}
	page := parsePage(r.URL.Query().Get("page"))
	q.Set("page", strconv.Itoa(page))
	search := strings.TrimSpace(r.URL.Query().Get("q"))
	if search != "" {
		q.Set("q", search)
	}
	http.Redirect(w, r, a.path("/admin")+"?"+q.Encode(), http.StatusSeeOther)
}

func (a *App) nextCode() (string, error) {
	rows, err := a.db.Query(`SELECT short_code FROM links`)
	if err != nil {
		return "", err
	}
	defer rows.Close()

	used := map[string]struct{}{}
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			return "", err
		}
		used[strings.ToLower(code)] = struct{}{}
	}

	candidate := int64(0)
	for {
		c := strings.ToLower(strconv.FormatInt(candidate, 36))
		if !isReservedCode(c) {
			if _, exists := used[c]; !exists {
				return c, nil
			}
		}
		candidate++
	}
}

func isReservedCode(code string) bool {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "login", "logout", "admin":
		return true
	default:
		return false
	}
}

func isValidCode(s string) bool {
	if s == "" {
		return false
	}
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' {
			continue
		}
		return false
	}
	return true
}

func isUniqueConstraintErr(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique")
}

func (a *App) validateTargetURL(raw string) error {
	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return errors.New("long URL must be valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("long URL must start with http:// or https://")
	}
	if u.Host == "" {
		return errors.New("long URL must include a host")
	}
	host := strings.ToLower(u.Hostname())
	for d := range a.excludedDomains {
		if host == d || strings.HasSuffix(host, "."+d) {
			return fmt.Errorf("links to domain %q are blocked", d)
		}
	}
	return nil
}

func generatePassword(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf)[:length], nil
}

func keyFromEnv(name string, n int) []byte {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		key := securecookie.GenerateRandomKey(n)
		if key == nil {
			panic("failed to generate secure cookie key")
		}
		return key
	}
	sum := sha256.Sum256([]byte(v))
	return sum[:n]
}

func parsePage(p string) int {
	page, err := strconv.Atoi(p)
	if err != nil || page < 1 {
		return 1
	}
	return page
}

func normalizeBasePath(raw string) (string, error) {
	b := strings.TrimSpace(raw)
	if b == "" || b == "/" {
		return "", nil
	}
	if !strings.HasPrefix(b, "/") {
		b = "/" + b
	}
	b = "/" + strings.Trim(strings.TrimSpace(b), "/")
	if strings.Contains(b, "//") {
		return "", errors.New("base path cannot contain empty path segments")
	}
	return b, nil
}

func (a *App) stripBasePath(p string) (string, bool) {
	if a.basePath == "" {
		return p, true
	}
	if p == a.basePath || p == a.basePath+"/" {
		return "/", true
	}
	prefix := a.basePath + "/"
	if strings.HasPrefix(p, prefix) {
		return "/" + strings.TrimPrefix(p, prefix), true
	}
	return "", false
}

func (a *App) path(suffix string) string {
	if suffix == "" {
		suffix = "/"
	}
	if !strings.HasPrefix(suffix, "/") {
		suffix = "/" + suffix
	}
	if a.basePath == "" {
		return suffix
	}
	if suffix == "/" {
		return a.basePath + "/"
	}
	return a.basePath + suffix
}

func (a *App) cookiePath() string {
	if a.basePath == "" {
		return "/"
	}
	return a.basePath
}

func countRows(db *sql.DB, table string) (int, error) {
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count)
	return count, err
}

func parseDomainList(raw string) map[string]struct{} {
	out := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		d := strings.ToLower(strings.TrimSpace(part))
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.TrimPrefix(d, "www.")
		d = strings.Trim(d, "/")
		if d == "" {
			continue
		}
		out[d] = struct{}{}
	}
	return out
}

func withLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//start := time.Now()
		next.ServeHTTP(w, r)
		//log.Printf("%s %s (%s)", r.Method, r.URL.Path, time.Since(start))
	})
}
