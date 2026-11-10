package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ============================================================
// 历史采样 + 告警检测
//
// 采样间隔默认 60 秒，保留 7 天（约 1 万个点，JSON 约 1MB）。
// 数据落在 DATA_DIR/history.json（容器里挂一个卷）。
// ============================================================

type Sample struct {
	T     int64   `json:"t"`     // unix 秒
	Rx    float64 `json:"rx"`    // 下行 B/s
	Tx    float64 `json:"tx"`    // 上行 B/s
	Load  float64 `json:"load"`  // 1 分钟负载
	MemP  float64 `json:"mem"`   // 内存使用率 %
	Temp  float64 `json:"temp"`  // 路由器温度 ℃
	Delay float64 `json:"delay"` // 当前节点延迟 ms（0=未知）
	Dns   float64 `json:"dns"`   // AdGuard 查询总数（累计）
	Blk   float64 `json:"blk"`   // AdGuard 拦截总数（累计）
}

type History struct {
	mu      sync.RWMutex
	samples []Sample
	max     int
	path    string
	dirty   bool
	stop    chan struct{}
}

var hist *History

func initHistory(dataDir string, maxPoints int) {
	hist = &History{
		max:  maxPoints,
		path: filepath.Join(dataDir, "history.json"),
		stop: make(chan struct{}),
	}
	hist.load()
	go hist.loop()
}

func (h *History) load() {
	b, err := os.ReadFile(h.path)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("历史数据读取失败: %v", err)
		}
		return
	}
	var s []Sample
	if err := json.Unmarshal(b, &s); err != nil {
		log.Printf("历史数据解析失败（忽略）: %v", err)
		return
	}
	h.mu.Lock()
	h.samples = s
	h.mu.Unlock()
	log.Printf("历史数据已载入: %d 个采样点", len(s))
}

func (h *History) save() {
	h.mu.RLock()
	b, err := json.Marshal(h.samples)
	h.mu.RUnlock()
	if err != nil {
		return
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		log.Printf("历史数据写入失败: %v", err)
		return
	}
	_ = os.Rename(tmp, h.path)
}

func (h *History) Add(s Sample) {
	h.mu.Lock()
	h.samples = append(h.samples, s)
	if len(h.samples) > h.max {
		h.samples = h.samples[len(h.samples)-h.max:]
	}
	h.dirty = true
	h.mu.Unlock()
}

// Range 返回 after 之后的采样点
func (h *History) Range(after time.Time) []Sample {
	h.mu.RLock()
	defer h.mu.RUnlock()
	cut := after.Unix()
	out := make([]Sample, 0, len(h.samples))
	for _, s := range h.samples {
		if s.T >= cut {
			out = append(out, s)
		}
	}
	return out
}

// Totals 统计 from 之后的总流量（字节），按采样间隔对速率积分。
// 两次采样间隔过大（服务重启/休眠）时跳过该段，避免把速率乘以一段空白时间。
func (h *History) Totals(from time.Time) (rx, tx float64) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	cut := from.Unix()
	gap := int64(cfg.SampleSec) * 3
	if gap < 180 {
		gap = 180
	}
	for i := 1; i < len(h.samples); i++ {
		s := h.samples[i]
		if s.T < cut {
			continue
		}
		dt := s.T - h.samples[i-1].T
		if dt <= 0 || dt > gap {
			continue
		}
		rx += s.Rx * float64(dt)
		tx += s.Tx * float64(dt)
	}
	return
}

func (h *History) Last() (Sample, bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.samples) == 0 {
		return Sample{}, false
	}
	return h.samples[len(h.samples)-1], true
}

func (h *History) loop() {
	tick := time.NewTicker(time.Duration(cfg.SampleSec) * time.Second)
	saveTick := time.NewTicker(2 * time.Minute)
	defer tick.Stop()
	defer saveTick.Stop()

	// 启动后先采一次
	time.Sleep(15 * time.Second)
	collectAndCheck()

	for {
		select {
		case <-h.stop:
			return
		case <-tick.C:
			collectAndCheck()
		case <-saveTick.C:
			h.mu.RLock()
			d := h.dirty
			h.mu.RUnlock()
			if d {
				h.save()
				h.mu.Lock()
				h.dirty = false
				h.mu.Unlock()
			}
		}
	}
}

func (h *History) Stop() {
	close(h.stop)
	h.save()
}

// ============================================================
// 采集一个点
// ============================================================

func collectSample() Sample {
	s := Sample{T: time.Now().Unix()}

	// 路由器：速率 / 负载 / 内存 / 温度
	rd := getRouterData()
	s.Rx, s.Tx = rd.RxRate, rd.TxRate
	s.Temp = rd.TempC
	if rd.MemTotal > 0 {
		s.MemP = rd.MemUsed / rd.MemTotal * 100
	}
	if f := strings.Fields(rd.LoadAvg); len(f) > 0 {
		s.Load, _ = strconv.ParseFloat(f[0], 64)
	}

	// mihomo：当前生效节点 + 它的延迟
	active := getActiveGroup()
	if groups, nodes, err := getProxies(); err == nil {
		for _, g := range groups {
			if g.Name != active {
				continue
			}
			for _, n := range nodes {
				if n.Name == g.Now {
					s.Delay = float64(n.Delay)
					break
				}
			}
			break
		}
	}

	// AdGuard：累计查询/拦截
	if ag := getAdguardInfo(); ag.Alive {
		s.Dns = ag.Queries
		s.Blk = ag.Blocked
	}

	return s
}

// ============================================================
// 告警检测
// ============================================================

type alertState struct {
	mu        sync.Mutex
	svcUp     map[string]bool
	knownMAC  map[string]int64 // MAC -> 首次见到的时间
	initializ bool             // 首次运行：只记录不报警
	devPath   string
}

var alerts = &alertState{
	svcUp:    map[string]bool{},
	knownMAC: map[string]int64{},
}

func initAlerts(dataDir string) {
	alerts.devPath = filepath.Join(dataDir, "devices.json")
	b, err := os.ReadFile(alerts.devPath)
	if err == nil {
		var m map[string]int64
		if json.Unmarshal(b, &m) == nil {
			alerts.knownMAC = m
			alerts.initializ = true
			log.Printf("已知设备记录已载入: %d 台", len(m))
		}
	}
	if !alerts.initializ {
		log.Printf("首次运行：先记录现有设备，之后新设备才会告警")
	}
}

func (a *alertState) saveDevices() {
	a.mu.Lock()
	b, _ := json.Marshal(a.knownMAC)
	a.mu.Unlock()
	tmp := a.devPath + ".tmp"
	if os.WriteFile(tmp, b, 0644) == nil {
		_ = os.Rename(tmp, a.devPath)
	}
}

func collectAndCheck() {
	s := collectSample()
	hist.Add(s)

	checkServices()
	checkDevices()
	checkThresholds(s)
}

// ---- 服务存活 ----
func checkServices() {
	svcs := getServices()
	alerts.mu.Lock()
	defer alerts.mu.Unlock()

	for _, s := range svcs {
		if s.Key == "" {
			continue // SSH 之类不告警
		}
		prev, seen := alerts.svcUp[s.Key]
		alerts.svcUp[s.Key] = s.Alive

		if !seen {
			continue // 第一次只记录基线
		}
		if prev && !s.Alive {
			notifier.Send("error", "服务掉线: "+s.Name,
				"端口 :"+s.Port+" 不可访问", "svc-down-"+s.Key)
		}
		if !prev && s.Alive {
			notifier.Send("info", "服务已恢复: "+s.Name,
				"端口 :"+s.Port+" 已恢复监听", "svc-up-"+s.Key)
		}
	}
}

// ---- 新设备上线 ----
func checkDevices() {
	devs := getDevices()
	alerts.mu.Lock()
	firstRun := !alerts.initializ
	var news []device
	for _, d := range devs {
		if d.MAC == "" || !d.Online {
			continue
		}
		if _, ok := alerts.knownMAC[d.MAC]; !ok {
			alerts.knownMAC[d.MAC] = time.Now().Unix()
			if !firstRun {
				news = append(news, d)
			}
		}
	}
	if firstRun {
		alerts.initializ = true
	}
	alerts.mu.Unlock()

	if firstRun {
		alerts.saveDevices()
		log.Printf("已记录 %d 台现有设备", len(devs))
		return
	}
	if len(news) > 0 {
		alerts.saveDevices()
		for _, d := range news {
			name := d.Name
			if name == "" {
				name = "未知设备"
			}
			notifier.Send("warn", "新设备接入: "+name,
				"IP "+d.IP+"\nMAC "+d.MAC, "newdev-"+d.MAC)
		}
	}
}

// ---- 阈值告警 ----
func checkThresholds(s Sample) {
	// 路由器温度
	if cfg.TempAlert > 0 && s.Temp >= cfg.TempAlert {
		notifier.Send("warn", "路由器温度偏高",
			"当前 "+strconv.FormatFloat(s.Temp, 'f', 0, 64)+"°C，阈值 "+
				strconv.FormatFloat(cfg.TempAlert, 'f', 0, 64)+"°C",
			"temp-high")
	}
	// 路由器内存
	if cfg.MemAlert > 0 && s.MemP >= cfg.MemAlert {
		notifier.Send("warn", "路由器内存吃紧",
			"已用 "+strconv.FormatFloat(s.MemP, 'f', 0, 64)+"%",
			"mem-high")
	}
}
