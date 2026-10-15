package main

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testPassword = "hunter2"

// newTestServer wraps a stub handler that answers "ok" on every path with the auth layer
func newTestServer(t *testing.T, password string) http.Handler {
	t.Helper()
	loginFailDelay = 0
	tmpl := template.Must(template.New("").Funcs(templateFuncs(password)).ParseFS(content, "templates/*.html"))
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	return requireAuth(password, tmpl, next)
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func login(t *testing.T, h http.Handler, password, next string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"password": {password}, "next": {next}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return do(h, req)
}

func sessionCookie(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName {
			return c
		}
	}
	t.Fatalf("no %s cookie in response", sessionCookieName)
	return nil
}

func TestNoPasswordLeavesAppOpen(t *testing.T) {
	h := newTestServer(t, "")
	for _, path := range []string{"/", "/md", "/download/files/a.txt", "/api/updates"} {
		rec := do(h, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ok" {
			t.Errorf("%s: got %d %q, want 200 ok", path, rec.Code, rec.Body.String())
		}
	}
}

func TestBrowserPageRedirectsToLogin(t *testing.T) {
	h := newTestServer(t, testPassword)
	req := httptest.NewRequest("GET", "/md", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	rec := do(h, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("got %d, want 303", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login?next=%2Fmd" {
		t.Errorf("Location = %q, want /login?next=%%2Fmd", loc)
	}
}

func TestNonBrowserRequestGets401(t *testing.T) {
	h := newTestServer(t, testPassword)
	cases := []struct{ method, path, accept string }{
		{"GET", "/raw/text/a", "*/*"},
		{"GET", "/api/updates", "text/event-stream"},
		{"POST", "/submit", "text/html"},
		{"POST", "/delete/files/a.txt", ""},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Accept", c.accept)
		rec := do(h, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestPublicPathsSkipAuth(t *testing.T) {
	h := newTestServer(t, testPassword)
	for _, path := range []string{"/static/style.css", "/favicon.ico", "/manifest.json", "/sw.js", "/icon-192.png", "/icon-512.png", "/style.css"} {
		rec := do(h, httptest.NewRequest("GET", path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("%s: got %d, want 200", path, rec.Code)
		}
	}
}

func TestLoginPageRenders(t *testing.T) {
	h := newTestServer(t, testPassword)
	rec := do(h, httptest.NewRequest("GET", "/login?next=%2Fmd", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="password"`) || !strings.Contains(body, `value="/md"`) {
		t.Errorf("login page missing password field or next value:\n%s", body)
	}
}

func TestCorrectPasswordGrantsAccess(t *testing.T) {
	h := newTestServer(t, testPassword)
	rec := login(t, h, testPassword, "/md")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/md" {
		t.Fatalf("got %d Location=%q, want 303 to /md", rec.Code, rec.Header().Get("Location"))
	}
	c := sessionCookie(t, rec)
	if !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: HttpOnly=%v SameSite=%v", c.HttpOnly, c.SameSite)
	}
	req := httptest.NewRequest("GET", "/raw/text/a", nil)
	req.AddCookie(c)
	if rec := do(h, req); rec.Code != http.StatusOK || rec.Body.String() != "ok" {
		t.Errorf("authed request: got %d %q, want 200 ok", rec.Code, rec.Body.String())
	}
}

func TestWrongPasswordRejected(t *testing.T) {
	h := newTestServer(t, testPassword)
	rec := login(t, h, "wrong", "/")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("got %d, want 401", rec.Code)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			t.Errorf("wrong password set a session cookie")
		}
	}
	if !strings.Contains(rec.Body.String(), "Incorrect password") {
		t.Errorf("login page should show an error")
	}
}

func TestLoginIgnoresOffsiteNext(t *testing.T) {
	h := newTestServer(t, testPassword)
	for _, next := range []string{"https://evil.example", "//evil.example", "/\\evil.example", ""} {
		rec := login(t, h, testPassword, next)
		if loc := rec.Header().Get("Location"); loc != "/" {
			t.Errorf("next=%q: Location = %q, want /", next, loc)
		}
	}
}

func TestSecureCookieBehindHTTPSProxy(t *testing.T) {
	h := newTestServer(t, testPassword)
	form := url.Values{"password": {testPassword}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	if c := sessionCookie(t, do(h, req)); !c.Secure {
		t.Errorf("cookie should be Secure behind an HTTPS proxy")
	}
}

func TestInvalidCookiesRejected(t *testing.T) {
	h := newTestServer(t, testPassword)
	valid := sessionCookie(t, login(t, h, testPassword, "/")).Value
	expired := signSession(testPassword, time.Now().Add(-time.Minute))
	otherPassword := signSession("different", time.Now().Add(time.Hour))
	exp, _, _ := strings.Cut(valid, ".")
	n, _ := strconv.ParseInt(exp, 10, 64)
	extended := strconv.FormatInt(n+3600, 10) + valid[len(exp):]
	for name, value := range map[string]string{
		"expired":        expired,
		"other password": otherPassword,
		"tampered":       extended,
		"garbage":        "not-a-token",
		"empty":          "",
	} {
		req := httptest.NewRequest("GET", "/raw/text/a", nil)
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: value})
		if rec := do(h, req); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s cookie: got %d, want 401", name, rec.Code)
		}
	}
}

func TestLogoutClearsCookie(t *testing.T) {
	h := newTestServer(t, testPassword)
	rec := do(h, httptest.NewRequest("GET", "/logout", nil))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/login" {
		t.Fatalf("got %d Location=%q, want 303 to /login", rec.Code, rec.Header().Get("Location"))
	}
	if c := sessionCookie(t, rec); c.MaxAge >= 0 {
		t.Errorf("logout cookie MaxAge = %d, want negative", c.MaxAge)
	}
}

func TestIndexShowsLogoutOnlyWhenLocked(t *testing.T) {
	for _, tc := range []struct {
		password string
		want     bool
	}{{"", false}, {testPassword, true}} {
		tmpl := template.Must(template.New("").Funcs(templateFuncs(tc.password)).ParseFS(content, "templates/*.html"))
		var sb strings.Builder
		if err := tmpl.ExecuteTemplate(&sb, "index.html", []Entry{}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(sb.String(), `href="/logout"`); got != tc.want {
			t.Errorf("password=%q: logout link present=%v, want %v", tc.password, got, tc.want)
		}
	}
}
