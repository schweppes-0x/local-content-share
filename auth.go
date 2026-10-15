package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	sessionCookieName = "lcs_session"
	sessionMaxAge     = 30 * 24 * time.Hour
)

// Slows down password guessing; overridden in tests
var loginFailDelay = time.Second

// Paths needed to render the login page and install the PWA
var publicPaths = map[string]bool{
	"/login":         true,
	"/logout":        true,
	"/favicon.ico":   true,
	"/manifest.json": true,
	"/sw.js":         true,
	"/icon-192.png":  true,
	"/icon-512.png":  true,
	"/style.css":     true,
}

type loginPage struct {
	Next  string
	Error string
}

func templateFuncs(password string) template.FuncMap {
	return template.FuncMap{"authEnabled": func() bool { return password != "" }}
}

// Session tokens are "<expiry unix>.<hmac>" signed with a key derived from the password,
// so they survive restarts and are invalidated when the password changes
func signSession(password string, expiry time.Time) string {
	exp := strconv.FormatInt(expiry.Unix(), 10)
	return exp + "." + sessionMAC(password, exp)
}

func sessionMAC(password, exp string) string {
	key := sha256.Sum256([]byte("local-content-share-session:" + password))
	mac := hmac.New(sha256.New, key[:])
	mac.Write([]byte(exp))
	return hex.EncodeToString(mac.Sum(nil))
}

func validSession(password, token string) bool {
	exp, sig, ok := strings.Cut(token, ".")
	if !ok {
		return false
	}
	if !hmac.Equal([]byte(sig), []byte(sessionMAC(password, exp))) {
		return false
	}
	n, err := strconv.ParseInt(exp, 10, 64)
	return err == nil && time.Now().Unix() < n
}

func passwordMatches(password, attempt string) bool {
	// Hash both sides so the comparison doesn't leak the password length
	a := sha256.Sum256([]byte(attempt))
	b := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// Only allow redirects to local paths to avoid an open redirect via ?next=
func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	if u, err := url.Parse(next); err != nil || u.Host != "" {
		return "/"
	}
	return next
}

func isSecure(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   isSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
}

func handleLogin(password string, tmpl *template.Template, w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		tmpl.ExecuteTemplate(w, "login.html", loginPage{Next: safeNext(r.URL.Query().Get("next"))})
	case "POST":
		next := safeNext(r.FormValue("next"))
		if !passwordMatches(password, r.FormValue("password")) {
			log.Printf("Failed login attempt from %s\n", r.RemoteAddr)
			time.Sleep(loginFailDelay)
			w.WriteHeader(http.StatusUnauthorized)
			tmpl.ExecuteTemplate(w, "login.html", loginPage{Next: next, Error: "Incorrect password"})
			return
		}
		setSessionCookie(w, r, signSession(password, time.Now().Add(sessionMaxAge)), int(sessionMaxAge.Seconds()))
		http.Redirect(w, r, next, http.StatusSeeOther)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// requireAuth gates every route behind a password; with an empty password it is a no-op
func requireAuth(password string, tmpl *template.Template, next http.Handler) http.Handler {
	if password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			handleLogin(password, tmpl, w, r)
			return
		case "/logout":
			setSessionCookie(w, r, "", -1)
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		if publicPaths[r.URL.Path] || strings.HasPrefix(r.URL.Path, "/static/") {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(sessionCookieName); err == nil && validSession(password, c.Value) {
			next.ServeHTTP(w, r)
			return
		}
		// Browser navigations go to the login page; API calls, SSE and form posts get a 401
		if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") {
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
