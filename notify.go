package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ============================================================
// 通知推送
//
// 支持多种渠道，配置了哪个就用哪个（可同时配多个）：
//   NOTIFY_BARK         Bark key 或完整地址，如 https://api.day.app/xxxx
//   NOTIFY_TELEGRAM     bot_token:chat_id
//   NOTIFY_WECOM        企业微信【群机器人】webhook key
//   NOTIFY_WECOM_CORP   企业微信【自建应用】企业ID (corpid)
//   NOTIFY_WECOM_SECRET 企业微信【自建应用】应用Secret (corpsecret)
//   NOTIFY_WECOM_AGENT  企业微信【自建应用】AgentId
//   NOTIFY_WECOM_TOUSER 企业微信【自建应用】接收人（默认 @all）
//   NOTIFY_NTFY         ntfy 地址，如 https://ntfy.sh/mytopic
//   NOTIFY_WEBHOOK      通用 webhook（POST JSON {title, body}）
//   NOTIFY_MIN_LEVEL    最低级别 info|warn|error（默认 warn）
// ============================================================

type Notifier struct {
	bark     string
	telegram string
	wecom    string // 群机器人 key
	ntfy     string
	webhook  string
	minLevel string

	// 企业微信自建应用
	wecomCorp   string
	wecomSecret string
	wecomAgent  int
	wecomToUser string
	wecomBase   string // API 地址，默认官方；可指向自建代理（如 wxchat）绕过可信IP校验
	insecure    bool   // 跳过 TLS 证书校验（自建代理常用自签证书）

	mu     sync.Mutex
	recent map[string]time.Time // 去重：同样的标题+内容 N 分钟内只发一次

	// 应用 access_token 缓存
	tokenMu  sync.Mutex
	token    string
	tokenExp time.Time
}

var notifier = &Notifier{recent: map[string]time.Time{}}

func initNotifier() {
	notifier.bark = strings.TrimRight(os.Getenv("NOTIFY_BARK"), "/")
	notifier.telegram = os.Getenv("NOTIFY_TELEGRAM")
	notifier.wecom = os.Getenv("NOTIFY_WECOM")
	notifier.ntfy = strings.TrimRight(os.Getenv("NOTIFY_NTFY"), "/")
	notifier.webhook = os.Getenv("NOTIFY_WEBHOOK")
	notifier.minLevel = env("NOTIFY_MIN_LEVEL", "warn")

	notifier.wecomCorp = os.Getenv("NOTIFY_WECOM_CORP")
	notifier.wecomSecret = os.Getenv("NOTIFY_WECOM_SECRET")
	notifier.wecomAgent = envInt("NOTIFY_WECOM_AGENT", 0)
	notifier.wecomToUser = env("NOTIFY_WECOM_TOUSER", "@all")
	notifier.wecomBase = strings.TrimRight(
		env("NOTIFY_WECOM_BASE", "https://qyapi.weixin.qq.com"), "/")

	// 自建代理（Sakura Frp / 自签证书）常需要跳过证书校验
	ins := strings.ToLower(os.Getenv("NOTIFY_INSECURE"))
	notifier.insecure = ins == "1" || ins == "true" || ins == "yes"

	chans := []string{}
	if notifier.bark != "" {
		chans = append(chans, "Bark")
	}
	if notifier.telegram != "" {
		chans = append(chans, "Telegram")
	}
	if notifier.wecom != "" {
		chans = append(chans, "企业微信(群机器人)")
	}
	if notifier.wecomReady() {
		chans = append(chans, "企业微信(自建应用)")
	} else if notifier.wecomCorp != "" || notifier.wecomSecret != "" {
		chans = append(chans, "企业微信(自建应用)⚠️ 配置不完整")
	}
	if notifier.ntfy != "" {
		chans = append(chans, "ntfy")
	}
	if notifier.webhook != "" {
		chans = append(chans, "Webhook")
	}
	if len(chans) == 0 {
		log.Printf("通知: 未配置任何渠道（告警只记录在日志里）")
	} else {
		log.Printf("通知: 已启用 %s（最低级别 %s）", strings.Join(chans, " / "), notifier.minLevel)
	}
	if notifier.insecure {
		log.Printf("通知: ⚠️ 已开启 NOTIFY_INSECURE，跳过 TLS 证书校验（仅用于自建代理）")
	}
}

// 企业微信自建应用的三要素齐了吗
func (n *Notifier) wecomReady() bool {
	return n.wecomCorp != "" && n.wecomSecret != "" && n.wecomAgent != 0
}

func (n *Notifier) configured() bool {
	return n.bark != "" || n.telegram != "" || n.wecom != "" ||
		n.wecomReady() || n.ntfy != "" || n.webhook != ""
}

func levelRank(l string) int {
	switch l {
	case "info":
		return 0
	case "warn":
		return 1
	case "error":
		return 2
	}
	return 1
}

// Send 发送通知。level: info / warn / error
// dedupKey 非空时，同一 key 在 10 分钟内只发一次（避免刷屏）
func (n *Notifier) Send(level, title, body, dedupKey string) {
	if levelRank(level) < levelRank(n.minLevel) {
		return
	}

	if dedupKey != "" {
		n.mu.Lock()
		if t, ok := n.recent[dedupKey]; ok && time.Since(t) < 10*time.Minute {
			n.mu.Unlock()
			return
		}
		n.recent[dedupKey] = time.Now()
		// 顺手清理过期记录
		for k, v := range n.recent {
			if time.Since(v) > time.Hour {
				delete(n.recent, k)
			}
		}
		n.mu.Unlock()
	}

	text := title
	if body != "" {
		text = title + "\n" + body
	}
	log.Printf("[通知/%s] %s", level, strings.ReplaceAll(text, "\n", " | "))

	if !n.configured() {
		return
	}
	go func() {
		if n.bark != "" {
			if err := n.sendBark(title, body); err != nil {
				log.Printf("通知 Bark 失败: %v", err)
			}
		}
		if n.telegram != "" {
			if err := n.sendTelegram(title, body); err != nil {
				log.Printf("通知 Telegram 失败: %v", err)
			}
		}
		if n.wecom != "" {
			if err := n.sendWecom(text); err != nil {
				log.Printf("通知 企业微信(群机器人) 失败: %v", err)
			}
		}
		if n.wecomReady() {
			if err := n.sendWecomApp(text); err != nil {
				log.Printf("通知 企业微信(自建应用) 失败: %v", err)
			}
		}
		if n.ntfy != "" {
			if err := n.sendNtfy(title, body, level); err != nil {
				log.Printf("通知 ntfy 失败: %v", err)
			}
		}
		if n.webhook != "" {
			if err := n.sendWebhook(title, body, level); err != nil {
				log.Printf("通知 Webhook 失败: %v", err)
			}
		}
	}()
}

func notifyClient() *http.Client {
	if notifier.insecure {
		return insecureNotifyClient
	}
	return notifyClientDefault
}

var notifyClientDefault = &http.Client{Timeout: 10 * time.Second}

var insecureNotifyClient = &http.Client{
	Timeout: 10 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

// Bark: GET {base}/{title}/{body}
func (n *Notifier) sendBark(title, body string) error {
	u := n.bark
	if !strings.HasPrefix(u, "http") {
		u = "https://api.day.app/" + strings.Trim(u, "/")
	}
	full := fmt.Sprintf("%s/%s/%s", strings.TrimRight(u, "/"),
		url.PathEscape(title), url.PathEscape(body))
	resp, err := notifyClient().Get(full)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Telegram: POST /bot{token}/sendMessage
func (n *Notifier) sendTelegram(title, body string) error {
	parts := strings.SplitN(n.telegram, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("格式应为 bot_token:chat_id")
	}
	token, chatID := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
	payload, _ := json.Marshal(map[string]string{
		"chat_id": chatID,
		"text":    title + "\n" + body,
	})
	u := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)
	resp, err := notifyClient().Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// 企业微信群机器人
func (n *Notifier) sendWecom(text string) error {
	u := n.wecom
	if !strings.HasPrefix(u, "http") {
		u = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=" + strings.TrimSpace(u)
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
	})
	resp, err := notifyClient().Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// 企业微信【自建应用】—— 先换 access_token，再发应用消息
// 与群机器人的区别：群机器人只要一个 webhook key；
// 自建应用要 corpid + corpsecret + agentid，消息发给指定成员。
func (n *Notifier) wecomToken() (string, error) {
	n.tokenMu.Lock()
	defer n.tokenMu.Unlock()

	if n.token != "" && time.Now().Before(n.tokenExp) {
		return n.token, nil
	}

	u := fmt.Sprintf("%s/cgi-bin/gettoken?corpid=%s&corpsecret=%s",
		n.wecomBase, url.QueryEscape(n.wecomCorp), url.QueryEscape(n.wecomSecret))
	resp, err := notifyClient().Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
		Token   string `json:"access_token"`
		Expires int    `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return "", fmt.Errorf("解析失败: %v", err)
	}
	if r.ErrCode != 0 || r.Token == "" {
		return "", fmt.Errorf("errcode=%d %s（检查 CORP/SECRET 是否正确）", r.ErrCode, r.ErrMsg)
	}

	n.token = r.Token
	exp := r.Expires - 120 // 提前 2 分钟过期，避免边界失效
	if exp < 60 {
		exp = 60
	}
	n.tokenExp = time.Now().Add(time.Duration(exp) * time.Second)
	return n.token, nil
}

func (n *Notifier) sendWecomApp(text string) error {
	token, err := n.wecomToken()
	if err != nil {
		return fmt.Errorf("获取 access_token 失败: %w", err)
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"touser":  n.wecomToUser,
		"msgtype": "text",
		"agentid": n.wecomAgent, // 必须是数字，不能是字符串
		"text":    map[string]string{"content": text},
		"safe":    0,
	})

	u := n.wecomBase + "/cgi-bin/message/send?access_token=" + url.QueryEscape(token)
	resp, err := notifyClient().Post(u, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))

	var r struct {
		ErrCode int    `json:"errcode"`
		ErrMsg  string `json:"errmsg"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return fmt.Errorf("解析失败: %v", err)
	}
	if r.ErrCode != 0 {
		hint := ""
		switch r.ErrCode {
		case 60020:
			hint = "（发送者 IP 不在应用的可信 IP 列表里）"
		case 81013:
			hint = "（接收人不存在或不在应用可见范围内）"
		case 40056:
			hint = "（AgentId 无效）"
		case 40001:
			hint = "（Secret 无效）"
		}
		return fmt.Errorf("errcode=%d %s%s", r.ErrCode, r.ErrMsg, hint)
	}
	return nil
}

// ntfy: POST {base}  带 Title / Priority 头
func (n *Notifier) sendNtfy(title, body, level string) error {
	prio := map[string]string{"info": "2", "warn": "3", "error": "5"}[level]
	if prio == "" {
		prio = "3"
	}
	req, err := http.NewRequest("POST", n.ntfy, strings.NewReader(title+"\n"+body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", url.PathEscape(title))
	req.Header.Set("Priority", prio)
	req.Header.Set("Tags", "warning")
	resp, err := notifyClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// 通用 webhook
func (n *Notifier) sendWebhook(title, body, level string) error {
	payload, _ := json.Marshal(map[string]string{
		"title": title, "body": body, "level": level,
		"time": time.Now().Format(time.RFC3339),
	})
	resp, err := notifyClient().Post(n.webhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
