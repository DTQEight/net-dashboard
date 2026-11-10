package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ============================================================
// 登录认证
//
// 配置（.env）：
//   AUTH_USER        用户名（默认 admin）
//   AUTH_PASS        明文密码（启动时 bcrypt 加密后只存在内存里）
//   AUTH_PASS_HASH   或直接给 bcrypt 哈希（优先于 AUTH_PASS）
//   AUTH_SECRET      cookie 签名密钥（不填则自动生成并持久化到 DATA_DIR/session.key）
//   AUTH_TTL_HOURS   登录有效期（默认 168 = 7 天）
//
// 两个都没配 → 不启用认证（并打印警告）
//
// 实现要点：
//   - cookie 是「用户名|过期时间|HMAC 签名」，无状态，重启不丢（密钥持久化）
//   - 用 subtle.ConstantTimeCompare 防时序攻击
//   - 登录失败按 IP 限流：5 次失败锁 5 分钟，并推送告警
// ============================================================

const authCookieName = "dsh_session"

type authConfig struct {
	enabled bool
	user    string
	passOK  func(string) bool
	secret  []byte
	ttl     time.Duration

	mu       sync.Mutex
	attempts map[string]*loginAttempt
}

type loginAttempt struct {
	fails     int
	firstFail time.Time
	lockUntil time.Time
}

var auth = &authConfig{attempts: map[string]*loginAttempt{}}

func initAuth(dataDir string) {
	user := env("AUTH_USER", "admin")
	plain := os.Getenv("AUTH_PASS")
	hash := os.Getenv("AUTH_PASS_HASH")

	if plain == "" && hash == "" {
		log.Printf("认证: 未配置 AUTH_PASS / AUTH_PASS_HASH → 面板无密码保护")
		log.Printf("认证: 建议在 .env 里加一行 AUTH_PASS=你的密码 然后重建")
		return
	}

	auth.user = user
	auth.ttl = time.Duration(envInt("AUTH_TTL_HOURS", 168)) * time.Hour

	// 校验密码用的闭包
	if hash != "" {
		h := []byte(strings.TrimSpace(hash))
		auth.passOK = func(p string) bool {
			return bcrypt.CompareHashAndPassword(h, []byte(p)) == nil
		}
		log.Printf("认证: 已启用（用户 %s，使用 AUTH_PASS_HASH）", user)
	} else {
		h, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
		if err != nil {
			log.Printf("认证: 密码加密失败（%v）→ 不启用认证", err)
			return
		}
		auth.passOK = func(p string) bool {
			return bcrypt.CompareHashAndPassword(h, []byte(p)) == nil
		}
		log.Printf("认证: 已启用（用户 %s，密码来自 AUTH_PASS）", user)
	}

	// cookie 签名密钥
	if s := os.Getenv("AUTH_SECRET"); s != "" {
		auth.secret = []byte(s)
	} else {
		auth.secret = loadOrCreateSecret(dataDir)
	}

	auth.enabled = true
	log.Printf("认证: 登录有效期 %d 小时", int(auth.ttl.Hours()))
}

func loadOrCreateSecret(dataDir string) []byte {
	path := filepath.Join(dataDir, "session.key")
	if b, err := os.ReadFile(path); err == nil && len(b) >= 16 {
		return b
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("认证: 生成密钥失败（%v）→ 用时间戳兜底", err)
		return []byte(fmt.Sprintf("fallback-%d", time.Now().UnixNano()))
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		log.Printf("认证: 密钥无法持久化（%v）→ 重启后所有登录失效", err)
	}
	return buf
}

// ---- token ----

func (a *authConfig) makeToken(user string, exp int64) string {
	payload := user + "|" + strconv.FormatInt(exp, 10)
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(
		[]byte(payload + "|" + hex.EncodeToString(mac.Sum(nil))))
}

func (a *authConfig) verifyToken(tok string) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 {
		return "", false
	}
	user, expStr, sig := parts[0], parts[1], parts[2]

	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}

	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(user + "|" + expStr))
	want := hex.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(sig), []byte(want)) != 1 {
		return "", false
	}
	// 用户改名后旧 token 失效
	if user != a.user {
		return "", false
	}
	return user, true
}

// ---- 失败限流 ----

const (
	maxFails   = 5
	failWindow = 10 * time.Minute
	lockTime   = 5 * time.Minute
)

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		return strings.TrimSpace(strings.Split(v, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (a *authConfig) locked(ip string) (time.Duration, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	at, ok := a.attempts[ip]
	if !ok {
		return 0, false
	}
	if time.Now().Before(at.lockUntil) {
		return time.Until(at.lockUntil), true
	}
	return 0, false
}

func (a *authConfig) recordFail(ip string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()
	at, ok := a.attempts[ip]
	if !ok || now.Sub(at.firstFail) > failWindow {
		at = &loginAttempt{firstFail: now}
		a.attempts[ip] = at
	}
	at.fails++
	if at.fails >= maxFails {
		at.lockUntil = now.Add(lockTime)
		at.fails = 0
		at.firstFail = now
		notifier.Send("warn", "面板登录被暴力尝试",
			"IP "+ip+" 连续 "+strconv.Itoa(maxFails)+" 次密码错误，已锁定 5 分钟",
			"login-brute-"+ip)
	}
}

func (a *authConfig) clearFail(ip string) {
	a.mu.Lock()
	delete(a.attempts, ip)
	a.mu.Unlock()
}

// ---- 处理器 ----

func handleLoginPage(w http.ResponseWriter, r *http.Request) {
	b, err := staticFS.ReadFile("static/login.html")
	if err != nil {
		http.Error(w, "login.html 缺失", 500)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

func (a *authConfig) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	ip := clientIP(r)

	if d, ok := a.locked(ip); ok {
		writeJSON(w, map[string]interface{}{
			"ok":    false,
			"error": fmt.Sprintf("尝试过于频繁，请 %d 分钟后再试", int(d.Minutes())+1),
		})
		return
	}

	var req struct {
		User string `json:"user"`
		Pass string `json:"pass"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "参数解析失败"})
		return
	}

	// 用户名和密码都要比对，避免"用户名对不对"被探测出来
	userOK := subtle.ConstantTimeCompare([]byte(req.User), []byte(a.user)) == 1
	passOK := a.passOK(req.Pass)

	if !userOK || !passOK {
		a.recordFail(ip)
		log.Printf("登录失败: user=%q ip=%s", req.User, ip)
		writeJSON(w, map[string]interface{}{"ok": false, "error": "用户名或密码错误"})
		return
	}

	a.clearFail(ip)
	exp := time.Now().Add(a.ttl)
	http.SetCookie(w, &http.Cookie{
		Name:     authCookieName,
		Value:    a.makeToken(req.User, exp.Unix()),
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	log.Printf("登录成功: user=%q ip=%s", req.User, ip)
	writeJSON(w, map[string]interface{}{"ok": true, "ttlHours": int(a.ttl.Hours())})
}

func (a *authConfig) handleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: authCookieName, Value: "", Path: "/",
		MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, map[string]interface{}{"ok": true})
}

func (a *authConfig) handleWhoami(w http.ResponseWriter, r *http.Request) {
	user := ""
	if c, err := r.Cookie(authCookieName); err == nil {
		if u, ok := a.verifyToken(c.Value); ok {
			user = u
		}
	}
	writeJSON(w, map[string]interface{}{
		"authEnabled": a.enabled,
		"user":        user,
		"loggedIn":    user != "",
	})
}

// ---- 中间件 ----

// 不需要登录就能访问的路径
func isPublicPath(p string) bool {
	switch p {
	case "/login", "/api/login", "/api/logout", "/api/whoami",
		"/healthz", "/favicon.ico", "/manifest.json",
		"/apple-touch-icon.png", "/icon-192.png", "/icon-512.png",
		"/icon-maskable-512.png":
		return true
	}
	return false
}

func (a *authConfig) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.enabled {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		if isPublicPath(p) {
			next.ServeHTTP(w, r)
			return
		}

		if c, err := r.Cookie(authCookieName); err == nil {
			if _, ok := a.verifyToken(c.Value); ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// 未登录：API 返回 401 让前端跳转，页面直接重定向
		if strings.HasPrefix(p, "/api/") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": "未登录", "needLogin": true,
			})
			return
		}
		http.Redirect(w, r, "/login", http.StatusFound)
	})
}
