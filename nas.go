package main

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// ============================================================
// NAS 硬盘状态
//
// 容器里能看到什么：
//   /proc/diskstats      主机全局，无需挂载  → 磁盘 I/O
//   /sys/block/*/size    块设备不隔离，无需挂载 → 磁盘容量
//   /sys/class/hwmon/*   需要挂载 /sys       → 温度（视机器而定）
//   /host/root/proc/mounts + Statfs          → 文件系统占用
//
// 挂载情况不满足时优雅降级，不报错。
// ============================================================

type diskIO struct {
	Name   string  `json:"name"`
	Size   uint64  `json:"size"`   // 字节
	ReadB  uint64  `json:"readB"`  // 累计读字节
	WriteB uint64  `json:"writeB"` // 累计写字节
	ReadPS float64 `json:"readPS"` // 读 B/s
	WritePS float64 `json:"writePS"`
	Temp   float64 `json:"temp,omitempty"`
	Model  string  `json:"model,omitempty"`
	Rotate bool    `json:"rotate"`
}

type fsUsage struct {
	Device string  `json:"device"`
	Mount  string  `json:"mount"`
	FSType string  `json:"fstype"`
	Total  uint64  `json:"total"`
	Used   uint64  `json:"used"`
	Free   uint64  `json:"free"`
	Pct    float64 `json:"pct"`
}

type nasInfo struct {
	Available bool       `json:"available"`
	Note      string     `json:"note,omitempty"`
	Hostname  string     `json:"hostname,omitempty"`
	UptimeS   float64    `json:"uptimeS,omitempty"`
	LoadAvg   string     `json:"loadavg,omitempty"`
	MemTotal  uint64     `json:"memTotal,omitempty"`
	MemAvail  uint64     `json:"memAvail,omitempty"`
	CPUTemp   float64    `json:"cpuTemp,omitempty"`
	Disks     []diskIO   `json:"disks"`
	FS        []fsUsage  `json:"fs"`
	HostTemps []hostTemp `json:"hostTemps,omitempty"`
	SysBlock  []sysBlockDev `json:"sysBlock,omitempty"`
}

type hostTemp struct {
	Label string  `json:"label"`
	C     float64 `json:"c"`
}

// /sys/block 的原始内容（诊断用：看内核到底认到哪些块设备）
type sysBlockDev struct {
	Name  string `json:"name"`
	Size  uint64 `json:"size"`
	Model string `json:"model,omitempty"`
	Note  string `json:"note,omitempty"`
	Shown bool   `json:"shown"` // 是否会出现在磁盘列表里
}

func listSysBlock(sysRoot string) []sysBlockDev {
	base := filepath.Join(sysRoot, "block")
	if _, err := os.Stat(base); err != nil {
		base = "/sys/block"
	}
	ents, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []sysBlockDev
	for _, e := range ents {
		name := e.Name()
		d := sysBlockDev{Name: name}

		if b, err := os.ReadFile(filepath.Join(base, name, "size")); err == nil {
			if n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64); err == nil {
				d.Size = n * 512
				if n == 0 {
					d.Note = "size 为 0"
				}
			} else {
				d.Note = "size 解析失败"
			}
		} else {
			d.Note = "size 读不到"
		}
		if b, err := os.ReadFile(filepath.Join(base, name, "device", "model")); err == nil {
			d.Model = strings.TrimSpace(string(b))
		}
		d.Shown = !isVirtualDisk(name) && d.Size > 0
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// 磁盘 I/O 速率需要两次采样
type diskRateState struct {
	mu   sync.Mutex
	ts   time.Time
	prev map[string][2]uint64
}

var diskRates = &diskRateState{prev: map[string][2]uint64{}}

// 读 /proc/diskstats：主设备号 次设备号 名字 读完成 读合并 读扇区 读耗时 写完成 ...
func parseDiskstats(path string) map[string][2]uint64 {
	out := map[string][2]uint64{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		name := f[2]
		if isVirtualDisk(name) {
			continue
		}
		rdSectors, _ := strconv.ParseUint(f[5], 10, 64)
		wrSectors, _ := strconv.ParseUint(f[9], 10, 64)
		out[name] = [2]uint64{rdSectors * 512, wrSectors * 512}
	}
	return out
}

// 过滤掉虚拟/重复设备，避免列表被 dm-0..dm-7、zram0..3、md1..md7 之类淹没
// md* 是软 RAID 阵列，容量和物理盘一一对应，物理盘还带型号，所以只留物理盘
func isVirtualDisk(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "dm-", "sr", "fd", "md"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	// mmcblk0boot0 / mmcblk0boot1 / mmcblk0rpmb 只有几 MB
	if strings.Contains(name, "boot") || strings.Contains(name, "rpmb") {
		return true
	}
	return false
}

// 读 /sys/block/*/size（单位 512 字节扇区）
func diskSizes(sysRoot string) map[string]uint64 {
	out := map[string]uint64{}
	base := filepath.Join(sysRoot, "block")
	ents, err := os.ReadDir(base)
	if err != nil {
		// 回退到容器自己的 /sys
		base = "/sys/block"
		ents, err = os.ReadDir(base)
		if err != nil {
			return out
		}
	}
	for _, e := range ents {
		name := e.Name()
		if isVirtualDisk(name) {
			continue
		}
		b, err := os.ReadFile(filepath.Join(base, name, "size"))
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		if err != nil || n == 0 {
			continue
		}
		out[name] = n * 512
	}
	return out
}

func diskModels(sysRoot string) map[string]string {
	out := map[string]string{}
	base := filepath.Join(sysRoot, "block")
	if _, err := os.Stat(base); err != nil {
		base = "/sys/block"
	}
	for name := range diskSizes(sysRoot) {
		if b, err := os.ReadFile(filepath.Join(base, name, "device", "model")); err == nil {
			out[name] = strings.TrimSpace(string(b))
		}
	}
	return out
}

// 读 hwmon / thermal 温度
func readHostTemps(sysRoot string) (float64, []hostTemp) {
	base := filepath.Join(sysRoot, "class", "hwmon")
	if _, err := os.Stat(base); err != nil {
		base = "/sys/class/hwmon"
	}
	var temps []hostTemp
	cpu := 0.0

	ents, _ := os.ReadDir(base)
	for _, e := range ents {
		dir := filepath.Join(base, e.Name())
		label := ""
		if b, err := os.ReadFile(filepath.Join(dir, "name")); err == nil {
			label = strings.TrimSpace(string(b))
		}
		files, _ := os.ReadDir(dir)
		for _, f := range files {
			fn := f.Name()
			if !strings.HasSuffix(fn, "_input") || !strings.HasPrefix(fn, "temp") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, fn))
			if err != nil {
				continue
			}
			v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
			if err != nil || v == 0 {
				continue
			}
			c := v / 1000.0
			if c < -40 || c > 150 {
				continue
			}
			lbl := label
			if lbl == "" {
				lbl = e.Name()
			}
			lbl = lbl + "/" + strings.TrimSuffix(fn, "_input")
			temps = append(temps, hostTemp{Label: lbl, C: c})
			if cpu == 0 || c > cpu {
				cpu = c
			}
		}
	}

	// thermal_zone 兜底
	tbase := filepath.Join(sysRoot, "class", "thermal")
	if _, err := os.Stat(tbase); err != nil {
		tbase = "/sys/class/thermal"
	}
	tents, _ := os.ReadDir(tbase)
	for _, e := range tents {
		if !strings.HasPrefix(e.Name(), "thermal_zone") {
			continue
		}
		dir := filepath.Join(tbase, e.Name())
		b, err := os.ReadFile(filepath.Join(dir, "temp"))
		if err != nil {
			continue
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(string(b)), 64)
		if err != nil || v == 0 {
			continue
		}
		c := v
		if c > 1000 {
			c = c / 1000.0
		}
		if c < -40 || c > 150 {
			continue
		}
		t := ""
		if tb, err := os.ReadFile(filepath.Join(dir, "type")); err == nil {
			t = strings.TrimSpace(string(tb))
		}
		if t == "" {
			t = e.Name()
		}
		temps = append(temps, hostTemp{Label: t, C: c})
		if cpu == 0 || c > cpu {
			cpu = c
		}
	}

	// 按温度从高到低排，高的更值得关注
	sort.Slice(temps, func(i, j int) bool { return temps[i].C > temps[j].C })
	if len(temps) > 12 {
		temps = temps[:12]
	}
	return cpu, temps
}

// ---- 文件系统魔数（statfs 的 f_type）----
// 用来精确判断文件系统类型，比按挂载路径猜可靠
const (
	msExt4      = 0xEF53
	msXfs       = 0x58465342
	msBtrfs     = 0x9123683E
	msF2fs      = 0xF2F52010
	msNfs       = 0x6969
	msTmpfs     = 0x01021994
	msOverlay   = 0x794c7630
	msSquashfs  = 0x73717368
	msProc      = 0x9fa0
	msSysfs     = 0x62656572
	msCgroup    = 0x27e0eb
	msCgroup2   = 0x63677270
	msRamfs     = 0x858458f6
	msDevtmpfs  = 0x1373
	msDevpts    = 0x1cd1
	msDebugfs   = 0x64626720
	msTracefs   = 0x74726163
	msSecurity  = 0x73636673
	msMqueue    = 0x19800202
	msBinfmt    = 0x42494e4d
	msFusectl   = 0x65735543
	msConfigfs  = 0x62656570
	msPstore    = 0x6165676c
	msAutofs    = 0x0187
	msHugetlb   = 0x958458f6
	msNfsd      = 0x6e667364
	msBpf       = 0xcafe4a11
	msNsfs      = 0x6e736673
	msEfivar    = 0xde5e81e4
)

func fsTypeName(m int64) string {
	switch m {
	case msExt4:
		return "ext4"
	case msXfs:
		return "xfs"
	case msBtrfs:
		return "btrfs"
	case msF2fs:
		return "f2fs"
	case msNfs:
		return "nfs"
	case msTmpfs:
		return "tmpfs"
	case msOverlay:
		return "overlay"
	case msSquashfs:
		return "squashfs"
	case msProc:
		return "proc"
	case msSysfs:
		return "sysfs"
	case msCgroup, msCgroup2:
		return "cgroup"
	case msRamfs:
		return "ramfs"
	case msDevtmpfs:
		return "devtmpfs"
	case msDevpts:
		return "devpts"
	case msDebugfs:
		return "debugfs"
	case msTracefs:
		return "tracefs"
	case msSecurity:
		return "securityfs"
	case msMqueue:
		return "mqueue"
	case msBinfmt:
		return "binfmt_misc"
	case msFusectl:
		return "fusectl"
	case msConfigfs:
		return "configfs"
	case msPstore:
		return "pstore"
	case msAutofs:
		return "autofs"
	case msHugetlb:
		return "hugetlbfs"
	case msNfsd:
		return "nfsd"
	case msBpf:
		return "bpf"
	case msNsfs:
		return "nsfs"
	case msEfivar:
		return "efivarfs"
	}
	return ""
}

// 这些不是"存储"，不要出现在硬盘卡片里
func isPseudoFS(m int64) bool {
	switch m {
	case msTmpfs, msOverlay, msProc, msSysfs, msCgroup, msCgroup2,
		msRamfs, msDevtmpfs, msDevpts, msSquashfs, msDebugfs, msTracefs,
		msSecurity, msMqueue, msBinfmt, msFusectl, msConfigfs, msPstore,
		msAutofs, msHugetlb, msNfsd, msBpf, msNsfs, msEfivar:
		return true
	}
	return false
}

// 统计单个挂载点的占用。dev/fsType 为空时用魔数推断。
func statFS(hostRoot, mount, dev, fsType string) (fsUsage, bool) {
	p := filepath.Join(hostRoot, mount)
	fi, err := os.Stat(p)
	if err != nil || !fi.IsDir() {
		return fsUsage{}, false
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(p, &st); err != nil {
		return fsUsage{}, false
	}
	// 伪文件系统（tmpfs / overlay / proc...）直接跳过
	if isPseudoFS(st.Type) {
		return fsUsage{}, false
	}
	if fsType == "" || fsType == "未知" {
		if n := fsTypeName(st.Type); n != "" {
			fsType = n
		} else {
			fsType = "未知"
		}
	}
	bs := uint64(st.Bsize)
	if bs == 0 {
		bs = 4096
	}
	total := st.Blocks * bs
	free := st.Bavail * bs
	if total == 0 {
		return fsUsage{}, false
	}
	used := total - free
	return fsUsage{
		Device: dev, Mount: mount, FSType: fsType,
		Total: total, Used: used, Free: free,
		Pct: float64(used) / float64(total) * 100,
	}, true
}

// 方式一：读主机 /proc/mounts（能拿到文件系统类型）
func readMounts(hostRoot string) []fsUsage {
	b, err := os.ReadFile(filepath.Join(hostRoot, "proc", "mounts"))
	if err != nil {
		return nil
	}
	skipFS := map[string]bool{
		"proc": true, "sysfs": true, "tmpfs": true, "devtmpfs": true,
		"devpts": true, "cgroup": true, "cgroup2": true, "overlay": true,
		"securityfs": true, "debugfs": true, "tracefs": true, "pstore": true,
		"bpf": true, "autofs": true, "mqueue": true, "hugetlbfs": true,
		"fusectl": true, "configfs": true, "ramfs": true, "efivarfs": true,
		"binfmt_misc": true, "nsfs": true, "squashfs": true, "rpc_pipefs": true,
		"nfsd": true, "fuse.gvfsd-fuse": true, "fuse.portal": true,
	}
	skipPrefix := []string{"/etc/", "/dev/", "/run/", "/var/lib/docker/",
		"/var/lib/kubelet/", "/snap/", "/sys/", "/proc/"}

	var out []fsUsage
	seen := map[string]bool{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		dev, mount, fsType := f[0], f[1], f[2]
		if skipFS[fsType] || seen[mount] || !strings.HasPrefix(dev, "/dev/") {
			continue
		}
		skip := false
		for _, pre := range skipPrefix {
			if strings.HasPrefix(mount, pre) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}
		if u, ok := statFS(hostRoot, mount, dev, fsType); ok {
			seen[mount] = true
			out = append(out, u)
		}
	}
	return out
}

// 方式二：按设备号扫描（/proc/mounts 读不到时的兜底）
// 关键：子目录的设备号要跟【父目录】比，不同才是挂载点。
// （跟根目录比会把挂载点下面所有子目录都误判成挂载点）
func scanMounts(hostRoot string) []fsUsage {
	var out []fsUsage
	seen := map[string]bool{}

	// 这些目录不用往里翻
	skipDir := map[string]bool{
		"proc": true, "sys": true, "dev": true, "run": true,
		"snap": true, "overlay2": true, "containerd": true,
		"kubelet": true, "docker": true, "lost+found": true,
	}

	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		if depth > 3 || len(out) > 24 {
			return
		}
		var dirSt syscall.Stat_t
		if err := syscall.Stat(dir, &dirSt); err != nil {
			return
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range ents {
			if !e.IsDir() {
				continue
			}
			name := e.Name()
			if skipDir[name] || strings.HasPrefix(name, ".") {
				continue
			}
			full := filepath.Join(dir, name)
			var st syscall.Stat_t
			if err := syscall.Stat(full, &st); err != nil {
				continue
			}
			if st.Dev != dirSt.Dev {
				// 相对父目录换设备了 → 是挂载点
				rel := strings.TrimPrefix(full, hostRoot)
				if rel == "" {
					rel = "/"
				}
				if !seen[rel] {
					if u, ok := statFS(hostRoot, rel, "", "未知"); ok {
						seen[rel] = true
						out = append(out, u)
					}
				}
			}
			walk(full, depth+1)
		}
	}
	walk(hostRoot, 0)
	return out
}

// /volume1 ~ /volume99 这类数据卷路径
func isVolumeMount(m string) bool {
	if !strings.HasPrefix(m, "/volume") {
		return false
	}
	rest := strings.TrimPrefix(m, "/volume")
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// 合并两种方式的结果
func readHostFS(hostRoot string) []fsUsage {
	raw := readMounts(hostRoot)
	have := map[string]bool{}
	for _, f := range raw {
		have[f.Mount] = true
	}
	for _, f := range scanMounts(hostRoot) {
		if !have[f.Mount] {
			raw = append(raw, f)
			have[f.Mount] = true
		}
	}

	// 去重：同一个文件系统挂在多个路径时只留一个，优先 /volumeN
	// （比如 NAS 会把同一个 LVM 同时挂到 /volume5 和 /home）
	type fsKey struct{ total, free uint64 }
	seen := map[fsKey]int{}
	var uniq []fsUsage
	for _, f := range raw {
		if f.Total == 0 {
			continue
		}
		k := fsKey{f.Total, f.Free}
		if idx, ok := seen[k]; ok {
			if isVolumeMount(f.Mount) && !isVolumeMount(uniq[idx].Mount) {
				uniq[idx] = f
			}
			continue
		}
		seen[k] = len(uniq)
		uniq = append(uniq, f)
	}

	sort.Slice(uniq, func(i, j int) bool {
		// /volumeN 排前面，同类型按容量降序
		vi, vj := isVolumeMount(uniq[i].Mount), isVolumeMount(uniq[j].Mount)
		if vi != vj {
			return vi
		}
		if uniq[i].Total != uniq[j].Total {
			return uniq[i].Total > uniq[j].Total
		}
		return uniq[i].Mount < uniq[j].Mount
	})
	return uniq
}

func getNASInfo() nasInfo {
	var out nasInfo
	out.Available = true

	// 主机自身信息
	if b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "proc", "loadavg")); err == nil {
		out.LoadAvg = strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
	}
	if b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "proc", "uptime")); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			out.UptimeS, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	// 主机名：/proc/sys/kernel/hostname 受 UTS 隔离，容器里读到的是容器名，
	// 所以优先读主机的 /etc/hostname
	if b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "etc", "hostname")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(b)), "\n")
		if len(lines) > 0 {
			out.Hostname = strings.TrimSpace(lines[0])
		}
	}
	if out.Hostname == "" {
		if b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "proc", "sys", "kernel", "hostname")); err == nil {
			out.Hostname = strings.TrimSpace(string(b))
		}
	}
	if b, err := os.ReadFile(filepath.Join(cfg.HostRoot, "proc", "meminfo")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 2 {
				continue
			}
			v, _ := strconv.ParseUint(f[1], 10, 64)
			switch strings.TrimSuffix(f[0], ":") {
			case "MemTotal":
				out.MemTotal = v * 1024
			case "MemAvailable":
				out.MemAvail = v * 1024
			}
		}
	}

	// 温度
	out.CPUTemp, out.HostTemps = readHostTemps(cfg.HostSys)

	// 诊断：/sys/block 原始列表
	out.SysBlock = listSysBlock(cfg.HostSys)

	// 磁盘
	sizes := diskSizes(cfg.HostSys)
	models := diskModels(cfg.HostSys)
	io := parseDiskstats("/proc/diskstats")

	diskRates.mu.Lock()
	now := time.Now()
	dt := now.Sub(diskRates.ts).Seconds()
	var disks []diskIO
	for name, size := range sizes {
		d := diskIO{Name: name, Size: size, Model: models[name]}
		if v, ok := io[name]; ok {
			d.ReadB, d.WriteB = v[0], v[1]
			if dt > 0.5 {
				if p, ok := diskRates.prev[name]; ok && v[0] >= p[0] && v[1] >= p[1] {
					d.ReadPS = float64(v[0]-p[0]) / dt
					d.WritePS = float64(v[1]-p[1]) / dt
				}
			}
		}
		// 旋转盘判断
		if b, err := os.ReadFile(filepath.Join(cfg.HostSys, "block", name, "queue", "rotational")); err == nil {
			d.Rotate = strings.TrimSpace(string(b)) == "1"
		} else if b, err := os.ReadFile(filepath.Join("/sys/block", name, "queue", "rotational")); err == nil {
			d.Rotate = strings.TrimSpace(string(b)) == "1"
		}
		disks = append(disks, d)
	}
	// 保存本次采样
	newPrev := map[string][2]uint64{}
	for name, v := range io {
		newPrev[name] = v
	}
	diskRates.prev = newPrev
	diskRates.ts = now
	diskRates.mu.Unlock()

	sort.Slice(disks, func(i, j int) bool {
		// 容量大的排前面，同容量按名字
		if disks[i].Size != disks[j].Size {
			return disks[i].Size > disks[j].Size
		}
		return disks[i].Name < disks[j].Name
	})
	if len(disks) > 14 {
		disks = disks[:14]
	}
	out.Disks = disks

	// 文件系统
	out.FS = readHostFS(cfg.HostRoot)
	if len(out.FS) == 0 && len(disks) == 0 {
		out.Available = false
		out.Note = "未能读取主机磁盘信息（检查 docker-compose 里的 /:/host/root:ro 与 /sys:/host/sys:ro 挂载）"
	} else if len(out.FS) == 0 {
		out.Note = "磁盘列表可读，但文件系统占用读不到（需要挂载 /:/host/root:ro，或用 docker exec 检查 /host/root 是否可访问）"
	}
	return out
}

// ============================================================
// 设备流量排行（读路由器 conntrack）
// ============================================================

type devTraffic struct {
	IP    string `json:"ip"`
	Bytes uint64 `json:"bytes"`
	Conns int    `json:"conns"`
}

const conntrackScript = `
for f in /proc/net/nf_conntrack /proc/net/ip_conntrack; do
  [ -r "$f" ] && { cat "$f"; exit 0; }
done
command -v conntrack >/dev/null 2>&1 && conntrack -L 2>/dev/null
echo "@@END"
`

func getDeviceTraffic() ([]devTraffic, string) {
	raw, err := runRemote(conntrackScript)
	if err != nil {
		return nil, "SSH 读取失败: " + err.Error()
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "@@END") && len(strings.Split(raw, "\n")) < 2 {
		return nil, "路由器没有 conntrack 表（内核未启用 nf_conntrack，或未安装 conntrack 工具）"
	}

	type acc struct {
		bytes uint64
		conns int
	}
	m := map[string]*acc{}
	hasBytes := false

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "@@") {
			continue
		}
		// 只统计内网源地址
		var ip string
		var bytes uint64
		for _, f := range strings.Fields(line) {
			if strings.HasPrefix(f, "src=") && ip == "" {
				cand := strings.TrimPrefix(f, "src=")
				if isPrivateIP(cand) {
					ip = cand
				}
			}
			if strings.HasPrefix(f, "bytes=") {
				// 形如 bytes=1234（可能是双向中的一项）
				v, _ := strconv.ParseUint(strings.TrimPrefix(f, "bytes="), 10, 64)
				bytes += v
				hasBytes = true
			}
		}
		if ip == "" {
			continue
		}
		a := m[ip]
		if a == nil {
			a = &acc{}
			m[ip] = a
		}
		a.conns++
		a.bytes += bytes
	}

	var out []devTraffic
	for ip, a := range m {
		out = append(out, devTraffic{IP: ip, Bytes: a.bytes, Conns: a.conns})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 30 {
		out = out[:30]
	}

	if !hasBytes {
		return out, "conntrack 没有字节计数（内核未开 nf_conntrack_acct），只能看连接数"
	}
	return out, ""
}

func isPrivateIP(ip string) bool {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false
	}
	a, _ := strconv.Atoi(parts[0])
	b, _ := strconv.Atoi(parts[1])
	switch {
	case a == 10:
		return true
	case a == 172 && b >= 16 && b <= 31:
		return true
	case a == 192 && b == 168:
		return true
	}
	return false
}
