package main

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

//go:embed static
var staticFS embed.FS

// ============================================================
// 配置
// ============================================================

type Config struct {
	RouterIP     string
	MihomoPort   string
	MihomoSecret string
	AdgPort      string
	AdgUser      string
	AdgPass      string
	SpeedPort    string
	SSHUser      string
	SSHPass      string
	SSHKeyPath   string
	Listen       string

	// 历史与告警
	DataDir   string
	SampleSec int
	TempAlert float64
	MemAlert  float64

	// NAS 主机挂载点
	HostRoot string
	HostSys  string

	// 快捷入口
	Links []Link

	// 服务端口（用于生成快捷入口与探测）
	LuckyPort string
}

// 快捷入口
type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Icon string `json:"icon,omitempty"`
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envFloat(k string, def float64) float64 {
	if v := os.Getenv(k); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return f
		}
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// 快捷入口：LINK_n_NAME / LINK_n_URL，n 从 1 开始，最多 8 个
func loadLinks(routerIP, mihomoPort, adgPort, speedPort, luckyPort string) []Link {
	// 默认入口
	def := []Link{
		{Name: "AdGuard", URL: "http://" + routerIP + ":" + adgPort + "/", Icon: "shield"},
		{Name: "mihomo", URL: "http://" + routerIP + ":" + mihomoPort + "/ui/", Icon: "proxy"},
		{Name: "测速", URL: "http://" + routerIP + ":" + speedPort + "/", Icon: "speed"},
		{Name: "路由器", URL: "http://" + routerIP + "/", Icon: "router"},
	}
	if luckyPort != "" {
		def = append(def, Link{Name: "Lucky", URL: "http://" + routerIP + ":" + luckyPort + "/", Icon: "lucky"})
	}

	var out []Link
	for i := 1; i <= 8; i++ {
		name := os.Getenv(fmt.Sprintf("LINK_%d_NAME", i))
		u := os.Getenv(fmt.Sprintf("LINK_%d_URL", i))
		if name == "" || u == "" {
			continue
		}
		out = append(out, Link{Name: name, URL: u, Icon: os.Getenv(fmt.Sprintf("LINK_%d_ICON", i))})
	}
	if len(out) == 0 {
		return def
	}
	return out
}

var cfg Config

func loadConfig() {
	lucky := os.Getenv("LUCKY_PORT")
	cfg = Config{
		RouterIP:     env("ROUTER_IP", "192.168.31.1"),
		MihomoPort:   env("MIHOMO_PORT", "19090"),
		MihomoSecret: os.Getenv("MIHOMO_SECRET"),
		AdgPort:      env("ADGUARD_PORT", "3000"),
		AdgUser:      os.Getenv("ADGUARD_USER"),
		AdgPass:      os.Getenv("ADGUARD_PASS"),
		SpeedPort:    env("SPEEDTEST_PORT", "18081"),
		SSHUser:      env("ROUTER_SSH_USER", "root"),
		SSHPass:      os.Getenv("ROUTER_SSH_PASS"),
		SSHKeyPath:   os.Getenv("ROUTER_SSH_KEY"),
		Listen:       env("LISTEN", ":8080"),

		DataDir:   env("DATA_DIR", "/data"),
		SampleSec: envInt("SAMPLE_SEC", 60),
		TempAlert: envFloat("TEMP_ALERT", 80),
		MemAlert:  envFloat("MEM_ALERT", 92),

		HostRoot: env("HOST_ROOT", "/host/root"),
		HostSys:  env("HOST_SYS", "/host/sys"),

		LuckyPort: lucky,
	}
	cfg.Links = loadLinks(cfg.RouterIP, cfg.MihomoPort, cfg.AdgPort, cfg.SpeedPort, lucky)
}

// ============================================================
// 通用 HTTP 客户端
// ============================================================

var httpClient = &http.Client{Timeout: 8 * time.Second}

func httpGet(url string, headers map[string]string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return body, resp.StatusCode, err
}

func httpPostJSON(url string, payload []byte) ([]byte, int, http.Header, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		return nil, 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return body, resp.StatusCode, resp.Header, err
}

// ============================================================
// SSH：采集路由器数据
// ============================================================

const remoteScript = `
echo "@@LOADAVG"
cat /proc/loadavg 2>/dev/null
echo "@@UPTIME"
cat /proc/uptime 2>/dev/null
echo "@@MEM"
grep -E "^(MemTotal|MemFree|MemAvailable|Buffers|Cached):" /proc/meminfo 2>/dev/null
echo "@@TEMP"
cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null
echo "@@NETDEV"
cat /proc/net/dev 2>/dev/null
echo "@@WAN"
ifconfig pppoe-wan 2>/dev/null
echo "@@LEASES"
cat /tmp/dhcp.leases 2>/dev/null
echo "@@ARP"
cat /proc/net/arp 2>/dev/null
echo "@@WIFI"
for d in wl0 wl1 wl5 wl13; do
  echo "--DEV $d"
  iwinfo $d assoclist 2>/dev/null
done
echo "@@SVC"
ps w 2>/dev/null | grep -E "[m]ihomo|[A]dGuardHome|[d]nsmasq|[s]peedtest-backend" | grep -v grep
echo "@@END"
`

func sshClient() (*ssh.Client, error) {
	var auths []ssh.AuthMethod

	if cfg.SSHKeyPath != "" {
		if b, err := os.ReadFile(cfg.SSHKeyPath); err == nil {
			if signer, err := ssh.ParsePrivateKey(b); err == nil {
				auths = append(auths, ssh.PublicKeys(signer))
			} else {
				log.Printf("ssh: 解析私钥失败: %v", err)
			}
		}
	}
	if cfg.SSHPass != "" {
		auths = append(auths, ssh.Password(cfg.SSHPass))
	}
	if len(auths) == 0 {
		return nil, fmt.Errorf("未配置 SSH 认证方式")
	}

	conf := &ssh.ClientConfig{
		User:            cfg.SSHUser,
		Auth:            auths,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
		// 小米路由器跑的是 dropbear，主机密钥只提供 ssh-rsa(SHA-1)。
		// Go 新版本默认不再优先它，必须显式列出，否则报
		// "no matching host key type found. Their offer: ssh-rsa"
		HostKeyAlgorithms: []string{
			"ssh-rsa",
			"rsa-sha2-256",
			"rsa-sha2-512",
			"ssh-ed25519",
			"ecdsa-sha2-nistp256",
		},
		Config: ssh.Config{
			// 兼容老 dropbear 的算法集合
			KeyExchanges: []string{
				"curve25519-sha256@libssh.org",
				"curve25519-sha256",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group14-sha1",
			},
			Ciphers: []string{
				"aes128-ctr",
				"aes192-ctr",
				"aes256-ctr",
				"aes128-gcm@openssh.com",
				"aes256-gcm@openssh.com",
				"chacha20-poly1305@openssh.com",
			},
			MACs: []string{
				"hmac-sha2-256",
				"hmac-sha2-512",
				"hmac-sha1",
				"hmac-sha2-256-etm@openssh.com",
				"hmac-sha2-512-etm@openssh.com",
			},
		},
	}
	return ssh.Dial("tcp", net.JoinHostPort(cfg.RouterIP, "22"), conf)
}

func runRemote(script string) (string, error) {
	client, err := sshClient()
	if err != nil {
		return "", err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	var buf bytes.Buffer
	session.Stdout = &buf
	session.Stderr = &buf
	// 忽略 Run 的错误：部分命令（如 ifconfig 缺参数）非零退出但输出有效
	_ = session.Run(script)
	return buf.String(), nil
}

// 带 TTL 的缓存
type cacheBox struct {
	mu   sync.Mutex
	ts   time.Time
	data string
	err  error
}

func (c *cacheBox) fetch(ttl time.Duration, onFresh func(string)) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.data != "" && time.Since(c.ts) < ttl {
		return c.data, nil
	}
	d, err := runRemote(remoteScript)
	if err != nil {
		if c.data != "" {
			return c.data, nil // 返回旧数据总比空好
		}
		return "", err
	}
	c.data = d
	c.ts = time.Now()
	c.err = nil
	// 只有拿到「新」数据时才回调，避免用缓存数据重复计算速率（会把速率算成 0）
	if onFresh != nil {
		onFresh(d)
	}
	return d, nil
}

// 手动让缓存失效（服务启停后立刻刷新状态）
func (c *cacheBox) invalidate() {
	c.mu.Lock()
	c.ts = time.Time{}
	c.mu.Unlock()
}

// 拉取路由器数据；新数据到达时顺便更新流量速率
func fetchRouterSections(ttl time.Duration) (sections, error) {
	raw, err := routerCache.fetch(ttl, func(s string) {
		sec := splitSections(s)
		ifaces := parseNetDev(sec["NETDEV"])
		rates.update(ifaces)
	})
	if err != nil {
		return nil, err
	}
	return splitSections(raw), nil
}

var routerCache cacheBox

// ============================================================
// 解析 SSH 输出
// ============================================================

type sections map[string]string

func splitSections(raw string) sections {
	out := sections{}
	cur := ""
	var buf []string
	flush := func() {
		if cur != "" {
			out[cur] = strings.Join(buf, "\n")
		}
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "@@") {
			flush()
			cur = strings.TrimPrefix(strings.TrimSpace(line), "@@")
			buf = nil
			continue
		}
		buf = append(buf, line)
	}
	flush()
	return out
}

// ============================================================
// 流量速率（需要两次采样求差）
// ============================================================

type rateState struct {
	mu       sync.Mutex
	ts       time.Time
	wanRx    uint64
	wanTx    uint64
	lastRx   float64
	lastTx   float64
	hasData  bool
}

var rates rateState

func parseNetDev(block string) map[string][2]uint64 {
	res := map[string][2]uint64{}
	for _, line := range strings.Split(block, "\n") {
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		if name == "" {
			continue
		}
		fields := strings.Fields(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		rx, _ := strconv.ParseUint(fields[0], 10, 64)
		tx, _ := strconv.ParseUint(fields[8], 10, 64)
		res[name] = [2]uint64{rx, tx}
	}
	return res
}

func (r *rateState) update(ifaces map[string][2]uint64) (float64, float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	wan, ok := ifaces["pppoe-wan"]
	if !ok {
		return r.lastRx, r.lastTx
	}
	now := time.Now()
	if r.hasData {
		dt := now.Sub(r.ts).Seconds()
		if dt > 0.5 {
			dRx := float64(wan[0] - r.wanRx)
			dTx := float64(wan[1] - r.wanTx)
			// 计数器回绕保护
			if wan[0] >= r.wanRx && wan[1] >= r.wanTx {
				r.lastRx = dRx / dt
				r.lastTx = dTx / dt
			}
		}
	}
	r.wanRx = wan[0]
	r.wanTx = wan[1]
	r.ts = now
	r.hasData = true
	return r.lastRx, r.lastTx
}

// 读取上次算好的速率（不重新采样）
func (r *rateState) current() (float64, float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastRx, r.lastTx
}

// ============================================================
// mihomo API
// ============================================================

func mihomoGet(path string) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%s%s", cfg.RouterIP, cfg.MihomoPort, path)
	h := map[string]string{}
	if cfg.MihomoSecret != "" {
		h["Authorization"] = "Bearer " + cfg.MihomoSecret
	}
	body, code, err := httpGet(url, h)
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("mihomo HTTP %d", code)
	}
	return body, nil
}

type mihomoInfo struct {
	Alive         bool    `json:"alive"`
	Version       string  `json:"version"`
	Mode          string  `json:"mode"`
	Connections   int     `json:"connections"`
	DownloadTotal uint64  `json:"downloadTotal"`
	UploadTotal   uint64  `json:"uploadTotal"`
	RxRate        float64 `json:"rxRate"`
	TxRate        float64 `json:"txRate"`
	Error         string  `json:"error,omitempty"`
}

func getMihomoInfo() mihomoInfo {
	var out mihomoInfo

	// 版本
	if b, err := mihomoGet("/version"); err == nil {
		var v struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(b, &v) == nil {
			out.Version = v.Version
			out.Alive = true
		}
	}
	if !out.Alive {
		out.Error = "无法连接 mihomo API"
		return out
	}

	// 当前模式
	if b, err := mihomoGet("/configs"); err == nil {
		var c struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(b, &c) == nil {
			out.Mode = c.Mode
		}
	}

	// 连接与流量
	if b, err := mihomoGet("/connections"); err == nil {
		var c struct {
			DownloadTotal uint64 `json:"downloadTotal"`
			UploadTotal   uint64 `json:"uploadTotal"`
			Connections   []struct {
				ID string `json:"id"`
			} `json:"connections"`
		}
		if json.Unmarshal(b, &c) == nil {
			out.DownloadTotal = c.DownloadTotal
			out.UploadTotal = c.UploadTotal
			out.Connections = len(c.Connections)
			out.RxRate, out.TxRate = trafficRates.updateFromMihomo(c.DownloadTotal, c.UploadTotal)
		}
	}
	return out
}

// mihomo 侧的速率（用累计值求差）
type mihomoRate struct {
	mu      sync.Mutex
	ts      time.Time
	dl, ul  uint64
	rx, tx  float64
	hasData bool
}

func (m *mihomoRate) updateFromMihomo(dl, ul uint64) (float64, float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.hasData {
		dt := now.Sub(m.ts).Seconds()
		if dt > 0.5 && dl >= m.dl && ul >= m.ul {
			m.rx = float64(dl-m.dl) / dt
			m.tx = float64(ul-m.ul) / dt
		}
	}
	m.dl, m.ul, m.ts, m.hasData = dl, ul, now, true
	return m.rx, m.tx
}

var trafficRates mihomoRate

// 代理组与节点
type proxyNode struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Delay    int    `json:"delay"`
	Alive    bool   `json:"alive"`
	Provider string `json:"provider,omitempty"`
}

type proxyGroup struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Now   string   `json:"now"`
	Nodes []string `json:"nodes"`
}

func isGroupType(t string) bool {
	switch t {
	case "Selector", "URLTest", "Fallback", "LoadBalance", "Relay":
		return true
	}
	return false
}

func isBuiltinType(t string) bool {
	switch t {
	case "Direct", "Reject", "RejectDrop", "Compatible", "Pass", "PassRule", "Dns":
		return true
	}
	return false
}

type proxyHistory []struct {
	Delay int `json:"delay"`
}

func lastDelay(h proxyHistory) int {
	if len(h) == 0 {
		return 0
	}
	return h[len(h)-1].Delay
}

// 代理组来自 /proxies，节点来自 /providers/proxies（订阅节点不在 /proxies 里）
func getProxies() ([]proxyGroup, []proxyNode, error) {
	var groups []proxyGroup
	var nodes []proxyNode

	// ---------- 1. 代理组 ----------
	b, err := mihomoGet("/proxies")
	if err != nil {
		return nil, nil, err
	}
	var pr struct {
		Proxies map[string]struct {
			Type    string       `json:"type"`
			Now     string       `json:"now"`
			All     []string     `json:"all"`
			Alive   bool         `json:"alive"`
			History proxyHistory `json:"history"`
		} `json:"proxies"`
	}
	if err := json.Unmarshal(b, &pr); err != nil {
		return nil, nil, err
	}
	for name, p := range pr.Proxies {
		if !isGroupType(p.Type) {
			continue
		}
		groups = append(groups, proxyGroup{
			Name:  name,
			Type:  p.Type,
			Now:   p.Now,
			Nodes: p.All,
		})
	}

	// ---------- 2. 节点（provider） ----------
	if pb, err := mihomoGet("/providers/proxies"); err == nil {
		var pv struct {
			Providers map[string]struct {
				VehicleType string `json:"vehicleType"`
				Proxies     []struct {
					Name    string       `json:"name"`
					Type    string       `json:"type"`
					Alive   bool         `json:"alive"`
					History proxyHistory `json:"history"`
				} `json:"proxies"`
			} `json:"providers"`
		}
		if json.Unmarshal(pb, &pv) == nil {
			seen := map[string]bool{}
			for pname, prov := range pv.Providers {
				for _, p := range prov.Proxies {
					if p.Name == "" || isGroupType(p.Type) || isBuiltinType(p.Type) || seen[p.Name] {
						continue
					}
					seen[p.Name] = true
					nodes = append(nodes, proxyNode{
						Name:     p.Name,
						Type:     p.Type,
						Delay:    lastDelay(p.History),
						Alive:    p.Alive,
						Provider: pname,
					})
				}
			}
		}
	}

	sortGroups(groups)
	sortNodes(nodes)
	return groups, nodes, nil
}

// 找出「真正生效」的分组：由 MATCH 兜底规则决定
// 配置里 MATCH,节点选择 表示所有未匹配的流量都走这个分组
func getActiveGroup() string {
	b, err := mihomoGet("/rules")
	if err != nil {
		return ""
	}
	var r struct {
		Rules []struct {
			Type    string `json:"type"`
			Payload string `json:"payload"`
			Proxy   string `json:"proxy"`
		} `json:"rules"`
	}
	if json.Unmarshal(b, &r) != nil {
		return ""
	}
	// 从后往前找 Match 规则（兜底规则通常在最末）
	for i := len(r.Rules) - 1; i >= 0; i-- {
		if strings.EqualFold(r.Rules[i].Type, "Match") {
			return r.Rules[i].Proxy
		}
	}
	return ""
}

// 切换节点：PUT /proxies/<group>  body {"name":"节点名"}
func switchNode(group, node string) error {
	url := fmt.Sprintf("http://%s:%s/proxies/%s",
		cfg.RouterIP, cfg.MihomoPort, urlPathEscape(group))
	payload, _ := json.Marshal(map[string]string{"name": node})

	req, err := http.NewRequest("PUT", url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.MihomoSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.MihomoSecret)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// 只转义必要的字符，保留 emoji 与中文原样
func urlPathEscape(s string) string {
	return url.PathEscape(s)
}

// 触发整组延迟测试（mihomo 会并发测所有成员，约 5 秒）
var delayClient = &http.Client{Timeout: 120 * time.Second}

func testGroupDelay(group, testURL string) (map[string]int, float64, error) {
	if testURL == "" {
		testURL = "http://www.gstatic.com/generate_204"
	}
	u := fmt.Sprintf("http://%s:%s/group/%s/delay?url=%s&timeout=5000",
		cfg.RouterIP, cfg.MihomoPort,
		url.PathEscape(group),
		url.QueryEscape(testURL))

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, 0, err
	}
	if cfg.MihomoSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.MihomoSecret)
	}

	t0 := time.Now()
	resp, err := delayClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(t0).Seconds()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if resp.StatusCode != 200 {
		return nil, elapsed, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var m map[string]int
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, elapsed, fmt.Errorf("解析结果失败: %v", err)
	}
	return m, elapsed, nil
}

func sortGroups(g []proxyGroup) {
	for i := 1; i < len(g); i++ {
		for j := i; j > 0 && g[j].Name < g[j-1].Name; j-- {
			g[j], g[j-1] = g[j-1], g[j]
		}
	}
}

func sortNodes(n []proxyNode) {
	for i := 1; i < len(n); i++ {
		for j := i; j > 0 && n[j].Delay < n[j-1].Delay; j-- {
			n[j], n[j-1] = n[j-1], n[j]
		}
	}
}

// ============================================================
// AdGuard API（支持 basic auth 与 session 登录）
// ============================================================

type adgSession struct {
	mu     sync.Mutex
	cookie string
	exp    time.Time
	basic  bool // basic auth 是否可用
	probed bool
}

var adg adgSession

func adgLogin() (string, error) {
	payload, _ := json.Marshal(map[string]string{
		"name":     cfg.AdgUser,
		"password": cfg.AdgPass,
	})
	_, code, hdr, err := httpPostJSON(
		fmt.Sprintf("http://%s:%s/control/login", cfg.RouterIP, cfg.AdgPort), payload)
	if err != nil {
		return "", err
	}
	if code != 200 {
		return "", fmt.Errorf("登录失败 HTTP %d", code)
	}
	var cookie string
	for _, c := range hdr["Set-Cookie"] {
		if strings.HasPrefix(c, "agh_session=") {
			cookie = strings.SplitN(c, ";", 2)[0]
			break
		}
	}
	if cookie == "" {
		return "", fmt.Errorf("未拿到 session cookie")
	}
	return cookie, nil
}

func adgGet(path string) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%s%s", cfg.RouterIP, cfg.AdgPort, path)

	adg.mu.Lock()
	defer adg.mu.Unlock()

	// 优先用缓存的 cookie
	if !adg.basic && adg.cookie != "" && time.Now().Before(adg.exp) {
		if b, code, err := httpGet(url, map[string]string{"Cookie": adg.cookie}); err == nil && code == 200 {
			return b, nil
		}
	}

	// 第一次尝试 basic auth
	if !adg.probed {
		req, _ := http.NewRequest("GET", url, nil)
		req.SetBasicAuth(cfg.AdgUser, cfg.AdgPass)
		if resp, err := httpClient.Do(req); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			resp.Body.Close()
			adg.probed = true
			if resp.StatusCode == 200 {
				adg.basic = true
				return body, nil
			}
		}
		adg.probed = true
	}
	if adg.basic {
		req, _ := http.NewRequest("GET", url, nil)
		req.SetBasicAuth(cfg.AdgUser, cfg.AdgPass)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		if resp.StatusCode == 200 {
			return body, nil
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	// 回退到 session 登录
	cookie, err := adgLogin()
	if err != nil {
		return nil, err
	}
	adg.cookie = cookie
	adg.exp = time.Now().Add(20 * time.Minute)

	b, code, err := httpGet(url, map[string]string{"Cookie": cookie})
	if err != nil {
		return nil, err
	}
	if code != 200 {
		return nil, fmt.Errorf("HTTP %d", code)
	}
	return b, nil
}

// TOP 域名条目
type topItem struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// AdGuard 不同版本 /control/stats 的 top_blocked_domains 格式不同：
//   旧版: [{"domain.com": 123}, ...]
//   新版: ["domain.com", ...]
//   变体: [{"name":"domain.com","count":123}, ...]
// 这里三种都兼容。
func parseTopDomains(raw json.RawMessage) []topItem {
	if len(raw) == 0 {
		return nil
	}
	// 格式 1：[{"域名": 次数}]
	var m []map[string]int
	if json.Unmarshal(raw, &m) == nil && len(m) > 0 {
		var out []topItem
		for _, e := range m {
			for k, v := range e {
				out = append(out, topItem{Name: k, Count: v})
			}
		}
		sortTop(out)
		return out
	}
	// 格式 2：["域名", ...]
	var s []string
	if json.Unmarshal(raw, &s) == nil && len(s) > 0 {
		var out []topItem
		for _, e := range s {
			out = append(out, topItem{Name: e})
		}
		return out
	}
	// 格式 3：[{"name":..,"count":..}]
	var n []topItem
	if json.Unmarshal(raw, &n) == nil && len(n) > 0 {
		sortTop(n)
		return n
	}
	return nil
}

func sortTop(items []topItem) {
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && items[j].Count > items[j-1].Count; j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

type adguardInfo struct {
	Alive             bool      `json:"alive"`
	Queries           float64   `json:"queries"`
	Blocked           float64   `json:"blocked"`
	BlockedPercent    float64   `json:"blockedPercent"`
	AvgProcessingMs   float64   `json:"avgProcessingMs"`
	ProtectionEnabled bool      `json:"protectionEnabled"`
	TopBlocked        []topItem `json:"topBlocked"`
	Error             string    `json:"error,omitempty"`
}

func getAdguardInfo() adguardInfo {
	var out adguardInfo

	// 保护开关
	if b, err := adgGet("/control/status"); err == nil {
		var s struct {
			ProtectionEnabled bool `json:"protection_enabled"`
		}
		if json.Unmarshal(b, &s) == nil {
			out.ProtectionEnabled = s.ProtectionEnabled
			out.Alive = true
		}
	}

	// 统计
	if b, err := adgGet("/control/stats"); err == nil {
		var s struct {
			NumDNSQueries       float64         `json:"num_dns_queries"`
			NumBlockedFiltering float64         `json:"num_blocked_filtering"`
			AvgProcessingTime   float64         `json:"avg_processing_time"`
			TopBlockedDomains   json.RawMessage `json:"top_blocked_domains"`
		}
		if json.Unmarshal(b, &s) == nil {
			out.Alive = true
			out.Queries = s.NumDNSQueries
			out.Blocked = s.NumBlockedFiltering
			out.AvgProcessingMs = s.AvgProcessingTime * 1000
			if s.NumDNSQueries > 0 {
				out.BlockedPercent = s.NumBlockedFiltering / s.NumDNSQueries * 100
			}
			tops := parseTopDomains(s.TopBlockedDomains)
			if len(tops) > 8 {
				tops = tops[:8]
			}
			out.TopBlocked = tops
		}
	}

	if !out.Alive {
		out.Error = "无法连接 AdGuard API（检查 ADGUARD_USER / ADGUARD_PASS）"
	}
	return out
}

// ============================================================
// 服务探活
// ============================================================

type serviceState struct {
	Name  string `json:"name"`
	Key   string `json:"key,omitempty"` // 可远程控制的服务标识（空=只读）
	Alive bool   `json:"alive"`
	Port  string `json:"port"`
	Note  string `json:"note,omitempty"`
}

func checkPort(host, port string, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func getServices() []serviceState {
	return []serviceState{
		{Name: "mihomo 代理", Key: "mihomo", Port: cfg.MihomoPort,
			Alive: checkPort(cfg.RouterIP, cfg.MihomoPort, 3*time.Second)},
		{Name: "AdGuard Home", Key: "adguard", Port: cfg.AdgPort,
			Alive: checkPort(cfg.RouterIP, cfg.AdgPort, 3*time.Second)},
		{Name: "LibreSpeed 测速", Key: "speedtest", Port: cfg.SpeedPort,
			Alive: checkPort(cfg.RouterIP, cfg.SpeedPort, 2*time.Second), Note: "按需启动"},
		{Name: "SSH", Port: "22",
			Alive: checkPort(cfg.RouterIP, "22", 3*time.Second)},
	}
}

// ============================================================
// 公网 IP
// ============================================================

var publicIPCache cacheBox2

type cacheBox2 struct {
	mu   sync.Mutex
	ts   time.Time
	data string
}

func getPublicIP() string {
	publicIPCache.mu.Lock()
	defer publicIPCache.mu.Unlock()
	if publicIPCache.data != "" && time.Since(publicIPCache.ts) < 10*time.Minute {
		return publicIPCache.data
	}
	for _, u := range []string{"https://ip.3322.net", "http://members.3322.org/dyndns/getip", "https://api.ipify.org"} {
		if b, code, err := httpGet(u, nil); err == nil && code == 200 {
			ip := strings.TrimSpace(string(b))
			if net.ParseIP(ip) != nil {
				publicIPCache.data = ip
				publicIPCache.ts = time.Now()
				return ip
			}
		}
	}
	return publicIPCache.data
}

// ============================================================
// 组装路由器数据
// ============================================================

type routerData struct {
	Alive bool   `json:"alive"`
	Error string `json:"error,omitempty"`

	LoadAvg  string  `json:"loadavg"`
	UptimeS  float64 `json:"uptimeS"`
	MemTotal float64 `json:"memTotalKB"`
	MemAvail float64 `json:"memAvailKB"`
	MemUsed  float64 `json:"memUsedKB"`
	TempC    float64 `json:"tempC"`

	WanIP    string  `json:"wanIP"`
	WanIPv6  string  `json:"wanIPv6"`
	PublicIP string  `json:"publicIP"`
	RxRate   float64 `json:"rxRate"`
	TxRate   float64 `json:"txRate"`

	Services []serviceState `json:"services"`
}

func getRouterData() routerData {
	var out routerData

	raw, err := fetchRouterSections(6 * time.Second)
	if err != nil {
		out.Error = "SSH 采集失败: " + err.Error()
		out.Services = getServices()
		return out
	}
	out.Alive = true
	sec := raw

	// 负载
	out.LoadAvg = strings.TrimSpace(strings.SplitN(sec["LOADAVG"], "\n", 2)[0])

	// 运行时间
	if f := strings.Fields(strings.TrimSpace(sec["UPTIME"])); len(f) > 0 {
		out.UptimeS, _ = strconv.ParseFloat(f[0], 64)
	}

	// 内存
	for _, line := range strings.Split(sec["MEM"], "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseFloat(f[1], 64)
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			out.MemTotal = v
		case "MemAvailable":
			out.MemAvail = v
		}
	}
	if out.MemTotal > 0 {
		out.MemUsed = out.MemTotal - out.MemAvail
	}

	// 温度：可能是 60 或 60000
	if s := strings.TrimSpace(sec["TEMP"]); s != "" {
		if v, err := strconv.ParseFloat(s, 64); err == nil {
			if v > 1000 {
				v = v / 1000
			}
			out.TempC = v
		}
	}

	// 网络速率
	// 速率由 fetchRouterSections 在拿到新数据时计算，这里直接读取
	out.RxRate, out.TxRate = rates.current()

	// WAN 地址
	for _, line := range strings.Split(sec["WAN"], "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "inet addr:") {
			out.WanIP = strings.Fields(strings.TrimPrefix(t, "inet addr:"))[0]
		}
		if strings.HasPrefix(t, "inet6 addr:") {
			f := strings.Fields(strings.TrimPrefix(t, "inet6 addr:"))
			if len(f) > 0 && !strings.HasPrefix(f[0], "fe80") && out.WanIPv6 == "" {
				out.WanIPv6 = f[0]
			}
		}
	}

	out.PublicIP = getPublicIP()
	out.Services = getServices()
	return out
}

// ============================================================
// 设备列表
// ============================================================

type device struct {
	IP     string `json:"ip"`
	MAC    string `json:"mac"`
	Name   string `json:"name"`
	Online bool   `json:"online"`
}

var ipRe = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func getDevices() []device {
	raw, err := fetchRouterSections(6 * time.Second)
	if err != nil {
		return nil
	}
	sec := raw

	// DHCP 租约：时间戳 MAC IP 主机名 客户端ID
	nameByMAC := map[string]string{}
	ipByMAC := map[string]string{}
	for _, line := range strings.Split(sec["LEASES"], "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 3 {
			continue
		}
		mac := strings.ToUpper(f[1])
		ipByMAC[mac] = f[2]
		if len(f) >= 4 && f[3] != "*" {
			nameByMAC[mac] = f[3]
		}
	}

	// ARP 表：IP 类型 标志 MAC 掩码 设备
	online := map[string]bool{}
	macByIP := map[string]string{}
	for _, line := range strings.Split(sec["ARP"], "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) < 6 || !ipRe.MatchString(f[0]) {
			continue
		}
		mac := strings.ToUpper(f[3])
		if mac == "00:00:00:00:00:00" {
			continue
		}
		online[mac] = true
		macByIP[f[0]] = mac
	}

	// 合并
	seen := map[string]bool{}
	var out []device
	for mac, ip := range ipByMAC {
		out = append(out, device{
			IP:     ip,
			MAC:    mac,
			Name:   nameByMAC[mac],
			Online: online[mac],
		})
		seen[mac] = true
	}
	for ip, mac := range macByIP {
		if seen[mac] {
			continue
		}
		out = append(out, device{IP: ip, MAC: mac, Name: "", Online: true})
	}

	// 按 IP 末尾数字排序
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && ipLess(out[j].IP, out[j-1].IP); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func ipLess(a, b string) bool {
	pa := strings.Split(a, ".")
	pb := strings.Split(b, ".")
	for i := 0; i < 4 && i < len(pa) && i < len(pb); i++ {
		na, _ := strconv.Atoi(pa[i])
		nb, _ := strconv.Atoi(pb[i])
		if na != nb {
			return na < nb
		}
	}
	return a < b
}

// ============================================================
// 无线客户端
// ============================================================

type wifiClient struct {
	Band    string  `json:"band"`
	MAC     string  `json:"mac"`
	RSSI    float64 `json:"rssi"`
	SNR     float64 `json:"snr"`
	RxRate  string  `json:"rxRate"`
	TxRate  string  `json:"txRate"`
	PHY     string  `json:"phy"`
}

var bandName = map[string]string{
	"wl0":  "5G",
	"wl1":  "2.4G",
	"wl5":  "5G(mesh)",
	"wl13": "2.4G(guest)",
}

func getWifiClients() []wifiClient {
	raw, err := fetchRouterSections(6 * time.Second)
	if err != nil {
		return nil
	}
	sec := raw
	block := sec["WIFI"]

	var out []wifiClient
	var curBand, curDev string
	headerSeen := false

	for _, line := range strings.Split(block, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "--DEV ") {
			curDev = strings.TrimSpace(strings.TrimPrefix(t, "--DEV "))
			curBand = bandName[curDev]
			if curBand == "" {
				curBand = curDev
			}
			headerSeen = false
			continue
		}
		if strings.HasPrefix(t, "CLIENT_MAC") {
			headerSeen = true
			continue
		}
		if !headerSeen || t == "" {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 6 {
			continue
		}
		// CLIENT_MAC PHY SECU RSSI NOISE SNR RX_RATE ...
		rssi := parseDBM(f[3])
		snr, _ := strconv.ParseFloat(f[5], 64)
		rx, tx := "", ""
		if len(f) > 6 {
			rx = f[6]
		}
		if len(f) > 12 {
			tx = f[12]
		}
		out = append(out, wifiClient{
			Band:   curBand,
			MAC:    strings.ToUpper(f[0]),
			RSSI:   rssi,
			SNR:    snr,
			RxRate: rx,
			TxRate: tx,
			PHY:    f[1],
		})
	}
	return out
}

func parseDBM(s string) float64 {
	s = strings.TrimSpace(strings.ReplaceAll(s, "dBm", ""))
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// ============================================================
// 进程状态（从 SSH 输出里解析）
// ============================================================

type procState struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
	Alive bool   `json:"alive"`
}

func getProcesses() []procState {
	raw, err := fetchRouterSections(6 * time.Second)
	if err != nil {
		return nil
	}
	sec := raw
	block := sec["SVC"]

	counts := map[string]int{
		"mihomo": 0, "AdGuardHome": 0, "dnsmasq": 0, "speedtest-backend": 0,
	}
	for _, line := range strings.Split(block, "\n") {
		for k := range counts {
			if strings.Contains(line, k) {
				counts[k]++
			}
		}
	}
	var out []procState
	for _, name := range []string{"mihomo", "AdGuardHome", "dnsmasq", "speedtest-backend"} {
		out = append(out, procState{Name: name, Count: counts[name], Alive: counts[name] > 0})
	}
	return out
}

// ============================================================
// 服务控制（严格白名单）
// 只允许预设的「服务 + 动作」组合，前端无法传入任意命令，
// 避免这个接口变成远程命令执行漏洞。
// ============================================================

const usbBase = "/mnt/usb-6c7b7949"

var serviceActions = map[string]map[string]string{
	"speedtest": {
		"start":   "sh " + usbBase + "/speedtest/start.sh",
		"stop":    "sh " + usbBase + "/speedtest/stop.sh",
		"restart": "sh " + usbBase + "/speedtest/stop.sh >/dev/null 2>&1; sleep 1; sh " + usbBase + "/speedtest/start.sh",
	},
	"mihomo": {
		"start":   "sh " + usbBase + "/mihomo/start.sh",
		"restart": "killall mihomo >/dev/null 2>&1; sleep 2; sh " + usbBase + "/mihomo/start.sh",
	},
	"adguard": {
		"start":   "sh " + usbBase + "/AdGuardHome/start.sh",
		"restart": "killall AdGuardHome >/dev/null 2>&1; sleep 2; sh " + usbBase + "/AdGuardHome/start.sh",
	},
}

var serviceLabels = map[string]string{
	"speedtest": "LibreSpeed 测速",
	"mihomo":    "mihomo 代理",
	"adguard":   "AdGuard Home",
}

func handleControl(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	var req struct {
		Service string `json:"service"`
		Action  string `json:"action"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "参数解析失败"})
		return
	}

	acts, ok := serviceActions[req.Service]
	if !ok {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "不支持的服务: " + req.Service})
		return
	}
	cmd, ok := acts[req.Action]
	if !ok {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "不支持的动作: " + req.Action})
		return
	}

	t0 := time.Now()
	out, err := runRemote(cmd)
	elapsed := time.Since(t0).Seconds()

	// 状态缓存立刻失效，前端能马上看到变化
	routerCache.invalidate()

	if err != nil {
		writeJSON(w, map[string]interface{}{
			"ok": false, "error": err.Error(),
			"output": strings.TrimSpace(out), "elapsed": elapsed,
		})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"service": req.Service,
		"action":  req.Action,
		"label":   serviceLabels[req.Service],
		"output":  strings.TrimSpace(out),
		"elapsed": elapsed,
	})
}

// ============================================================
// AdGuard 保护开关
// 用 API 暂停过滤，而不是停进程 —— 停进程会让全屋 DNS 挂掉
// ============================================================

func adgPost(path string, payload []byte) ([]byte, error) {
	url := fmt.Sprintf("http://%s:%s%s", cfg.RouterIP, cfg.AdgPort, path)

	do := func() ([]byte, int, error) {
		req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Content-Type", "application/json")
		adg.mu.Lock()
		if adg.basic {
			req.SetBasicAuth(cfg.AdgUser, cfg.AdgPass)
		} else if adg.cookie != "" {
			req.Header.Set("Cookie", adg.cookie)
		}
		adg.mu.Unlock()
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return b, resp.StatusCode, nil
	}

	b, code, err := do()
	if err == nil && code >= 200 && code < 300 {
		return b, nil
	}

	// 认证可能过期 → 重新登录再试一次
	adg.mu.Lock()
	if c, lerr := adgLogin(); lerr == nil {
		adg.cookie = c
		adg.basic = false
		adg.probed = true
		adg.exp = time.Now().Add(20 * time.Minute)
	}
	adg.mu.Unlock()

	b, code, err = do()
	if err != nil {
		return nil, err
	}
	if code < 200 || code >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", code, strings.TrimSpace(string(b)))
	}
	return b, nil
}

func handleProtection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.Enabled == nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "需要 enabled 布尔值"})
		return
	}
	payload, _ := json.Marshal(map[string]bool{"enabled": *req.Enabled})
	if _, err := adgPost("/control/protection", payload); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"enabled": *req.Enabled,
		"msg":     map[bool]string{true: "广告过滤已恢复", false: "广告过滤已暂停"}[*req.Enabled],
	})
}

// ============================================================
// 新增接口：NAS / 历史 / 流量排行 / 订阅更新 / DNS 缓存
// ============================================================

func handleNAS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getNASInfo())
}

func handleContainers(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getContainers())
}

func handleHistory(w http.ResponseWriter, r *http.Request) {
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			hours = n
		}
	}
	if hours < 1 {
		hours = 1
	}
	if hours > 168 {
		hours = 168
	}
	from := time.Now().Add(-time.Duration(hours) * time.Hour)
	writeJSON(w, map[string]interface{}{
		"samples": hist.Range(from),
		"from":    from.Unix(),
		"now":     time.Now().Unix(),
	})
}

// 区间总流量：最近 1 天 / 1 周 / 1 月
func handleTrafficTotal(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	out := map[string]map[string]float64{}
	for k, d := range map[string]time.Duration{
		"day":   24 * time.Hour,
		"week":  7 * 24 * time.Hour,
		"month": 30 * 24 * time.Hour,
	} {
		rx, tx := hist.Totals(now.Add(-d))
		out[k] = map[string]float64{"rx": rx, "tx": tx}
	}
	writeJSON(w, out)
}

func handleTraffic(w http.ResponseWriter, r *http.Request) {
	list, note := getDeviceTraffic()
	// 给 IP 补上设备名
	names := map[string]string{}
	for _, d := range getDevices() {
		if d.Name != "" {
			names[d.IP] = d.Name
		}
	}
	writeJSON(w, map[string]interface{}{
		"list": list,
		"note": note,
		"names": names,
	})
}

// 机场订阅更新
func providerNames() []string {
	b, err := mihomoGet("/providers/proxies")
	if err != nil {
		return nil
	}
	var pv struct {
		Providers map[string]struct {
			Proxies []struct {
				Name string `json:"name"`
			} `json:"proxies"`
		} `json:"providers"`
	}
	if json.Unmarshal(b, &pv) != nil {
		return nil
	}
	var out []string
	for name, p := range pv.Providers {
		if name == "default" || len(p.Proxies) == 0 {
			continue
		}
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func updateProvider(name string) error {
	u := fmt.Sprintf("http://%s:%s/providers/proxies/%s",
		cfg.RouterIP, cfg.MihomoPort, url.PathEscape(name))
	req, err := http.NewRequest("PUT", u, nil)
	if err != nil {
		return err
	}
	if cfg.MihomoSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.MihomoSecret)
	}
	resp, err := delayClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

func handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	var req struct {
		Provider string `json:"provider"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 2048)).Decode(&req)

	names := providerNames()
	if len(names) == 0 {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "未发现订阅（proxy-providers）"})
		return
	}

	// 没指定就更新第一个
	target := req.Provider
	if target == "" {
		target = names[0]
	}
	// 严格校验：只能更新确实存在的 provider
	valid := false
	for _, n := range names {
		if n == target {
			valid = true
			break
		}
	}
	if !valid {
		writeJSON(w, map[string]interface{}{
			"ok": false, "error": "未知订阅: " + target, "providers": names,
		})
		return
	}

	t0 := time.Now()
	if err := updateProvider(target); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error(), "provider": target})
		return
	}
	elapsed := time.Since(t0).Seconds()

	// 取更新后的节点数
	_, nodes, _ := getProxies()
	writeJSON(w, map[string]interface{}{
		"ok": true, "provider": target, "nodes": len(nodes),
		"elapsed": elapsed, "providers": names,
	})
}

// 清 DNS 缓存（AdGuard + dnsmasq）
func handleDNSFlush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	var msgs []string
	if _, err := adgPost("/control/cache_clear", []byte("{}")); err != nil {
		msgs = append(msgs, "AdGuard: "+err.Error())
	} else {
		msgs = append(msgs, "AdGuard 缓存已清")
	}
	// dnsmasq 重载（SIGHUP 不会中断服务）
	if _, err := runRemote("killall -HUP dnsmasq 2>/dev/null; echo ok"); err == nil {
		msgs = append(msgs, "dnsmasq 已重载")
	}
	routerCache.invalidate()
	writeJSON(w, map[string]interface{}{"ok": true, "msg": strings.Join(msgs, "；")})
}

func handleLinks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"links":     cfg.Links,
		"providers": providerNames(),
	})
}

// 测试通知渠道
func handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	if !notifier.configured() {
		writeJSON(w, map[string]interface{}{
			"ok": false,
			"error": "未配置任何通知渠道（在 .env 里设置 NOTIFY_BARK / NOTIFY_TELEGRAM / NOTIFY_WECOM / NOTIFY_NTFY / NOTIFY_WEBHOOK）",
		})
		return
	}
	// 绕过级别过滤和去重，直接发
	notifier.minLevel = "info"
	notifier.Send("info", "网络仪表盘测试通知",
		"如果你收到这条消息，说明通知渠道配置正确。\n时间: "+time.Now().Format("2006-01-02 15:04:05"), "")
	writeJSON(w, map[string]interface{}{"ok": true, "msg": "测试通知已发送，请检查接收端"})
}

// ============================================================
// HTTP 路由
// ============================================================

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

func handleRouter(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getRouterData())
}

func handleMihomo(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getMihomoInfo())
}

func handleProxies(w http.ResponseWriter, r *http.Request) {
	groups, nodes, err := getProxies()
	if err != nil {
		writeJSON(w, map[string]interface{}{"error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{
		"groups":      groups,
		"nodes":       nodes,
		"activeGroup": getActiveGroup(), // 真正承载流量的分组（来自 MATCH 规则）
	})
}

// 切换节点
func handleSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "只支持 POST"})
		return
	}
	var req struct {
		Group string `json:"group"`
		Node  string `json:"node"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&req); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "参数解析失败"})
		return
	}
	if req.Group == "" || req.Node == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "group / node 不能为空"})
		return
	}
	if err := switchNode(req.Group, req.Node); err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	writeJSON(w, map[string]interface{}{"ok": true, "group": req.Group, "node": req.Node})
}

func handleAdguard(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, getAdguardInfo())
}

// 整组测速
func handleTest(w http.ResponseWriter, r *http.Request) {
	group := r.URL.Query().Get("group")
	if group == "" {
		writeJSON(w, map[string]interface{}{"ok": false, "error": "缺少 group 参数"})
		return
	}
	delays, elapsed, err := testGroupDelay(group, r.URL.Query().Get("url"))
	if err != nil {
		writeJSON(w, map[string]interface{}{"ok": false, "error": err.Error(), "elapsed": elapsed})
		return
	}
	// 统计
	best, worst, ok := 0, 0, 0
	for _, d := range delays {
		if d <= 0 {
			continue
		}
		ok++
		if best == 0 || d < best {
			best = d
		}
		if d > worst {
			worst = d
		}
	}
	writeJSON(w, map[string]interface{}{
		"ok":      true,
		"group":   group,
		"delays":  delays,
		"total":   len(delays),
		"usable":  ok,
		"best":    best,
		"worst":   worst,
		"elapsed": elapsed,
	})
}

func handleDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]interface{}{
		"devices": getDevices(),
		"wifi":    getWifiClients(),
		"procs":   getProcesses(),
	})
}

func handleAll(w http.ResponseWriter, r *http.Request) {
	type resp struct {
		Router  routerData   `json:"router"`
		Mihomo  mihomoInfo   `json:"mihomo"`
		Adguard adguardInfo  `json:"adguard"`
		Devices []device     `json:"devices"`
		Wifi    []wifiClient `json:"wifi"`
		Procs   []procState  `json:"procs"`
		Links   []Link       `json:"links"`
	}
	rd := getRouterData()
	writeJSON(w, resp{
		Router:  rd,
		Mihomo:  getMihomoInfo(),
		Adguard: getAdguardInfo(),
		Devices: getDevices(),
		Wifi:    getWifiClients(),
		Procs:   getProcesses(),
		Links:   cfg.Links,
	})
}

// ============================================================
// main
// ============================================================

func main() {
	loadConfig()
	log.Printf("路由器: %s  mihomo:%s  adguard:%s", cfg.RouterIP, cfg.MihomoPort, cfg.AdgPort)

	// 确保数据目录存在
	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Printf("警告: 无法创建数据目录 %s: %v", cfg.DataDir, err)
	}

	initNotifier()
	initDocker()
	initAuth(cfg.DataDir)
	initAlerts(cfg.DataDir)
	initHistory(cfg.DataDir, 31*24*3600/cfg.SampleSec) // 保留 31 天（月流量统计需要）
	log.Printf("采样间隔: %ds  保留: 31 天  NAS 挂载: %s", cfg.SampleSec, cfg.HostRoot)

	// 预热一次 SSH 缓存（不阻塞启动）
	go func() {
		if _, err := fetchRouterSections(6 * time.Second); err != nil {
			log.Printf("警告: SSH 采集失败 -> %v", err)
			log.Printf("提示: 检查 ROUTER_SSH_PASS 或 ROUTER_SSH_KEY 配置")
		} else {
			log.Printf("SSH 采集正常")
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/api/all", handleAll)
	mux.HandleFunc("/api/router", handleRouter)
	mux.HandleFunc("/api/mihomo", handleMihomo)
	mux.HandleFunc("/api/proxies", handleProxies)
	mux.HandleFunc("/api/switch", handleSwitch)
	mux.HandleFunc("/api/adguard", handleAdguard)
	mux.HandleFunc("/api/test", handleTest)
	mux.HandleFunc("/api/control", handleControl)
	mux.HandleFunc("/api/protection", handleProtection)
	mux.HandleFunc("/api/nas", handleNAS)
	mux.HandleFunc("/api/containers", handleContainers)
	mux.HandleFunc("/api/history", handleHistory)
	mux.HandleFunc("/api/traffic", handleTraffic)
	mux.HandleFunc("/api/traffic-total", handleTrafficTotal)
	mux.HandleFunc("/api/subscription", handleSubscription)
	mux.HandleFunc("/api/dns/flush", handleDNSFlush)
	mux.HandleFunc("/api/links", handleLinks)
	mux.HandleFunc("/api/notify/test", handleNotifyTest)
	mux.HandleFunc("/api/devices", handleDevices)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	// 登录相关
	mux.HandleFunc("/login", handleLoginPage)
	mux.HandleFunc("/api/login", auth.handleLogin)
	mux.HandleFunc("/api/logout", auth.handleLogout)
	mux.HandleFunc("/api/whoami", auth.handleWhoami)

	// 静态文件（manifest / 图标 / 页面）
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		b, err := staticFS.ReadFile("static/" + p)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		switch {
		case strings.HasSuffix(p, ".html"):
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
		case strings.HasSuffix(p, ".json"):
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		case strings.HasSuffix(p, ".png"):
			w.Header().Set("Content-Type", "image/png")
		case strings.HasSuffix(p, ".js"):
			w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		case strings.HasSuffix(p, ".webmanifest"):
			w.Header().Set("Content-Type", "application/manifest+json; charset=utf-8")
		}
		w.Write(b)
	})

	log.Printf("仪表盘已启动: http://0.0.0.0%s", cfg.Listen)
	// 用认证中间件包一层（未配置 AUTH_PASS 时中间件直接放行）
	if err := http.ListenAndServe(cfg.Listen, auth.middleware(mux)); err != nil {
		log.Fatal(err)
	}
}
