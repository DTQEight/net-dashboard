package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ============================================================
// Docker 容器清单
//
// 通过挂载的 /var/run/docker.sock 查询（只调用只读接口）。
//
// 安全说明：挂载 docker.sock 等于把宿主 Docker 的控制权交给这个容器。
// 本程序只调 GET 接口，但如果你在意，可以改用 socket-proxy：
//   https://github.com/11notes/docker-socket-proxy
// 只放行 /containers/json 等只读路径。
//
// 自定义显示名 / 图标：
//   1) 给容器打标签（需要重建容器）
//        dashboard.name=Alist 网盘
//        dashboard.url=http://192.168.31.52:5244
//        dashboard.icon=📁
//        dashboard.group=媒体
//   2) 或写配置文件 /data/containers.json（不用动容器）
//        { "alist": { "name": "Alist 网盘", "icon": "📁", "url": "..." } }
// ============================================================

var dockerSockClient *http.Client

func initDocker() {
	sock := env("DOCKER_SOCK", "/var/run/docker.sock")
	if _, err := os.Stat(sock); err != nil {
		log.Printf("Docker: 未找到 socket（%s）→ 容器清单卡片不可用", sock)
		return
	}
	dockerSockClient = &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	log.Printf("Docker: 已连接 %s", sock)
}

type containerPort struct {
	Private int    `json:"private"`
	Public  int    `json:"public"`
	Type    string `json:"type"`
	IP      string `json:"ip,omitempty"`
	Web     bool   `json:"web"`
	// published = 有端口映射（host:port 可直接访问）
	// host      = host 网络模式，端口直接开在宿主上，也可直接访问
	// internal  = 只声明了端口但没发布，容器外访问不到
	Mode string `json:"mode"`
}

type containerInfo struct {
	ID      string          `json:"id"`
	Name    string          `json:"name"`
	Title   string          `json:"title"`
	Image   string          `json:"image"`
	State   string          `json:"state"`
	Status  string          `json:"status"`
	Created int64           `json:"created"`
	Ports   []containerPort `json:"ports"`
	URLs    []string        `json:"urls"`
	Icon    string          `json:"icon,omitempty"`
	Group   string          `json:"group,omitempty"`
}

// 自己不用展示
var hiddenContainers = map[string]bool{
	"net-dashboard": true,
}

// 常见非 Web 端口（数据库、消息队列、P2P、流媒体信令、UPnP…）
var nonWebPorts = map[int]bool{
	// 数据库 / 中间件
	3306: true, 5432: true, 6379: true, 27017: true, 9200: true, 9300: true,
	5672: true, 15672: true, 11211: true, 9042: true, 2181: true, 9092: true,
	1883: true, 8883: true, 5060: true, 123: true, 161: true,
	// P2P / 下载
	6881: true, 6882: true, 6883: true, 6884: true, 6885: true,
	6886: true, 6887: true, 6888: true, 6889: true,
	16881: true, 51413: true, 42069: true,
	// 流媒体信令（RTSP / RTMP / WebRTC）
	8554: true, 8555: true, 1935: true, 1936: true, 554: true,
	// UPnP / DLNA / mDNS
	1900: true, 7359: true, 5353: true,
}

// 默认认为所有端口都可点（用户的诉求就是"点开看"），
// 只把明确知道的非 Web 端口标灰。这样 Lucky:16601、go2rtc:1984
// 这类不在常见 Web 端口段的界面不会被误判。
func looksLikeWeb(port int) bool {
	return !nonWebPorts[port]
}

type containerOverride struct {
	Name  string `json:"name"`
	Icon  string `json:"icon"`
	URL   string `json:"url"`
	Group string `json:"group"`
	Hide  bool   `json:"hide"`
}

func loadContainerOverrides(dataDir string) map[string]containerOverride {
	path := filepath.Join(dataDir, "containers.json")
	b, err := os.ReadFile(path)
	if err != nil {
		log.Printf("容器名配置: 读不到 %s（%v）", path, err)
		return nil
	}
	// 去掉可能存在的 UTF-8 BOM
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		b = b[3:]
	}

	// 先按 RawMessage 解，再逐条尝试解析成 containerOverride。
	// 这样文件里可以放 "//xxx": "说明文字" 这类注释键（值是字符串），
	// 不会因为一个说明项就让整份配置失效。
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		log.Printf("容器名配置解析失败（%s）: %v", path, err)
		return nil
	}

	m := make(map[string]containerOverride, len(raw))
	skipped := 0
	for k, v := range raw {
		var ov containerOverride
		if err := json.Unmarshal(v, &ov); err != nil {
			skipped++ // 注释 / 说明类的键，忽略
			continue
		}
		m[k] = ov
	}
	log.Printf("容器名配置: 已载入 %d 条（跳过 %d 个非配置项）", len(m), skipped)
	return m
}

type dockerAPIContainer struct {
	ID      string            `json:"Id"`
	Names   []string          `json:"Names"`
	Image   string            `json:"Image"`
	State   string            `json:"State"`
	Status  string            `json:"Status"`
	Created int64             `json:"Created"`
	Labels  map[string]string `json:"Labels"`
	Ports   []struct {
		IP          string `json:"IP"`
		PrivatePort int    `json:"PrivatePort"`
		PublicPort  int    `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
}

func dockerGet(path string) ([]byte, error) {
	if dockerSockClient == nil {
		return nil, fmt.Errorf("未连接 Docker")
	}
	resp, err := dockerSockClient.Get("http://docker" + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

type dockerInspect struct {
	Config struct {
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		NetworkMode string `json:"NetworkMode"`
	} `json:"HostConfig"`
}

// 没有端口映射的容器（多为 host 网络模式），从 inspect 里读出它声明的端口
func fillExposedPorts(ci *containerInfo, id string) {
	b, err := dockerGet("/containers/" + id + "/json")
	if err != nil {
		return
	}
	var insp dockerInspect
	if json.Unmarshal(b, &insp) != nil {
		return
	}

	hostMode := insp.HostConfig.NetworkMode == "host"

	// 收集已在列表里的公网端口，避免重复
	have := map[int]bool{}
	for _, p := range ci.Ports {
		have[p.Public] = true
	}

	for spec := range insp.Config.ExposedPorts {
		// 形如 "8096/tcp"
		parts := strings.SplitN(spec, "/", 2)
		if len(parts) != 2 || parts[1] != "tcp" {
			continue
		}
		n := 0
		for _, ch := range parts[0] {
			if ch < '0' || ch > '9' {
				n = -1
				break
			}
			n = n*10 + int(ch-'0')
		}
		if n <= 0 || n > 65535 || have[n] {
			continue
		}
		have[n] = true
		mode := "internal"
		if hostMode {
			mode = "host"
		}
		ci.Ports = append(ci.Ports, containerPort{
			Private: n,
			Public:  n,
			Type:    "tcp",
			Web:     looksLikeWeb(n),
			Mode:    mode,
		})
	}
	sort.Slice(ci.Ports, func(i, j int) bool { return ci.Ports[i].Public < ci.Ports[j].Public })
}

type containersResp struct {
	Available  bool            `json:"available"`
	Note       string          `json:"note,omitempty"`
	Total      int             `json:"total"`
	Running    int             `json:"running"`
	Containers []containerInfo `json:"containers"`
}

func getContainers() containersResp {
	var out containersResp

	if dockerSockClient == nil {
		out.Note = "未挂载 Docker socket。在 docker-compose.yml 的 volumes 里加一行：" +
			"- /var/run/docker.sock:/var/run/docker.sock:ro"
		return out
	}

	b, err := dockerGet("/containers/json?all=true")
	if err != nil {
		out.Note = "查询 Docker 失败: " + err.Error()
		return out
	}

	var raw []dockerAPIContainer
	if err := json.Unmarshal(b, &raw); err != nil {
		out.Note = "解析失败: " + err.Error()
		return out
	}

	overrides := loadContainerOverrides(cfg.DataDir)
	out.Available = true

	for _, c := range raw {
		if len(c.Names) == 0 {
			continue
		}
		name := strings.TrimPrefix(c.Names[0], "/")
		if hiddenContainers[name] {
			continue
		}

		ci := containerInfo{
			Name:    name,
			Title:   name,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Created: c.Created,
		}
		if len(c.ID) > 12 {
			ci.ID = c.ID[:12]
		} else {
			ci.ID = c.ID
		}

		// Docker 会为 IPv4/IPv6 各报一条同样的端口，按公网端口去重
		seenPort := map[int]bool{}
		for _, p := range c.Ports {
			if p.Type != "tcp" || p.PublicPort == 0 || seenPort[p.PublicPort] {
				continue
			}
			seenPort[p.PublicPort] = true
			ci.Ports = append(ci.Ports, containerPort{
				Private: p.PrivatePort,
				Public:  p.PublicPort,
				Type:    p.Type,
				IP:      p.IP,
				Web:     looksLikeWeb(p.PrivatePort),
				Mode:    "published",
			})
		}
		sort.Slice(ci.Ports, func(i, j int) bool { return ci.Ports[i].Public < ci.Ports[j].Public })

		// 没映射端口的（多半是 host 网络模式）→ 从 inspect 读它声明的端口
		if len(ci.Ports) == 0 && c.State == "running" {
			fillExposedPorts(&ci, c.ID)
		}

		if v := c.Labels["dashboard.name"]; v != "" {
			ci.Title = v
		}
		if v := c.Labels["dashboard.icon"]; v != "" {
			ci.Icon = v
		}
		if v := c.Labels["dashboard.group"]; v != "" {
			ci.Group = v
		}
		if v := c.Labels["dashboard.url"]; v != "" {
			ci.URLs = append(ci.URLs, v)
		}

		// 配置文件覆盖（优先级最高，且不用重建容器）
		if ov, ok := overrides[name]; ok {
			if ov.Hide {
				continue
			}
			if ov.Name != "" {
				ci.Title = ov.Name
			}
			if ov.Icon != "" {
				ci.Icon = ov.Icon
			}
			if ov.Group != "" {
				ci.Group = ov.Group
			}
			if ov.URL != "" {
				ci.URLs = []string{ov.URL}
			}
		}

		out.Total++
		if c.State == "running" {
			out.Running++
		}
		out.Containers = append(out.Containers, ci)
	}

	sort.Slice(out.Containers, func(i, j int) bool {
		a, b := out.Containers[i], out.Containers[j]
		if (a.State == "running") != (b.State == "running") {
			return a.State == "running"
		}
		return strings.ToLower(a.Title) < strings.ToLower(b.Title)
	})

	return out
}
