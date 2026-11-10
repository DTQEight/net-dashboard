# 网络仪表盘 (Net Dashboard)

把家里这几个服务整合到一个页面上：

- **登录认证** —— 账号密码登录（bcrypt 加密）、失败限流、暴力破解告警
- **路由器系统** —— CPU 负载、内存、温度、运行时间
- **网络** —— 公网 IP、WAN 地址、实时上下行速率
- **mihomo 代理** —— 版本、当前节点、连接数、累计流量
- **代理节点** —— 节点列表、延迟排序、**点击切换节点**、**一键整组测速**
- **AdGuard Home** —— DNS 查询数、拦截数、拦截率、拦截域名 TOP
- **服务/进程状态** —— mihomo、AdGuard、dnsmasq 是否在跑
- **服务控制** —— 一键启停/重启测速、mihomo、AdGuard（严格白名单）
- **AdGuard 开关** —— 一键暂停/恢复广告过滤（不停进程，DNS 不中断）
- **快捷入口** —— 顶部一键跳转 AdGuard / mihomo / 测速 / 路由器 / Lucky
- **订阅更新** —— 手动触发机场订阅更新
- **DNS 缓存清理** —— AdGuard + dnsmasq 一起清
- **趋势图** —— 流量 / 负载内存 / 温度 / 节点延迟 / DNS 拦截（5 个标签页，24 小时）
- **NAS 硬盘** —— 磁盘容量、占用率、读写速率、温度、内存负载
- **Docker 服务** —— 列出所有容器 + **可点的访问端口**（不用再记端口号）
- **设备流量排行** —— 读路由器 conntrack，看谁在跑流量
- **告警推送** —— 服务掉线、新设备接入、温度过高、内存吃紧
- **PWA** —— 手机可加到桌面，像 App 一样用
- **在线设备** —— DHCP 租约 + ARP 表
- **无线客户端** —— 频段、信号强度、协议

数据来源：
- mihomo / AdGuard 走 **HTTP API**
- 系统、网络、设备、无线走 **SSH** 采集路由器

> 已实测环境：小米 BE7000（aarch64）+ mihomo v1.19.32 + AdGuard Home v0.107.79

---

## 快速部署（NAS 上）

### 方式一：直接拉取镜像（推荐，不用编译）

GitHub Actions 已自动构建 `linux/amd64` + `linux/arm64` 双架构镜像：

```bash
docker pull ghcr.io/dtqeight/net-dashboard:latest
```

在放 `.env` 的目录里直接启动（目录结构、挂载与 compose 一致）：

```bash
docker run -d --name net-dashboard --restart unless-stopped \
  -p 18080:8080 \
  --env-file .env \
  -e TZ=Asia/Shanghai \
  -v "$(pwd)/data:/data" \
  -v /:/host/root:ro \
  -v /sys:/host/sys:ro \
  -v /var/run/docker.sock:/var/run/docker.sock:ro \
  ghcr.io/dtqeight/net-dashboard:latest
```

镜像更新：`docker compose pull && docker compose up -d`（或重新 `docker run`）。

> 也可以把 `docker-compose.yml` 里的 `build: .` 删掉、加一行
> `image: ghcr.io/dtqeight/net-dashboard:latest`，直接 `docker compose up -d`。

### 方式二：本地构建

#### 1. 上传文件

把整个 `dashboard` 目录放到 NAS 上，例如 `/volume1/docker/dashboard`（群晖）
或绿联 NAS 的某个数据卷里。

**重要**：确认目标目录所在分区有足够空间（构建镜像需要约 1GB 临时空间）。

#### 2. 创建配置文件

```bash
cd /volume1/docker/dashboard
cp .env.example .env
vi .env          # 填写密码
```

必须填的项：

| 变量 | 说明 |
|---|---|
| `MIHOMO_SECRET` | mihomo 面板密码 |
| `ADGUARD_USER` / `ADGUARD_PASS` | AdGuard 管理员账号密码 |
| `ROUTER_SSH_PASS` | 路由器 root 密码（SSH 用） |

#### 3. 构建并启动

```bash
docker compose up -d --build
```

首次构建会拉取 `golang:1.23-alpine`（约 300MB）并编译，**需要几分钟**。

#### 4. 访问

```
http://NAS的IP:18080
```

---

## 登录认证

**强烈建议配置** —— 不配的话面板在局域网里谁都能打开。

```ini
AUTH_USER=admin
AUTH_PASS=改成你的登录密码
```

重建后访问任何页面都会跳到登录页。

### 配置项

| 变量 | 说明 | 默认 |
|---|---|---|
| `AUTH_USER` | 用户名 | `admin` |
| `AUTH_PASS` | 明文密码（**启动时自动 bcrypt 加密，只存在内存里**） | — |
| `AUTH_PASS_HASH` | 或直接给 bcrypt 哈希（优先于 `AUTH_PASS`） | — |
| `AUTH_SECRET` | cookie 签名密钥（不填会**自动生成并持久化**到 `data/session.key`） | 自动 |
| `AUTH_TTL_HOURS` | 登录有效期 | `168`（7 天） |

> **两个密码配置都不填 = 不启用认证**，启动日志会打印警告。

### 生成 bcrypt 哈希（可选）

```bash
docker run --rm httpd:alpine htpasswd -nbB "" "你的密码" | cut -d: -f2
```

### 安全设计

| 措施 | 说明 |
|---|---|
| **bcrypt 加密** | 明文密码不落盘，只在启动时算一次哈希存内存 |
| **HMAC 签名 cookie** | 改不了内容；密钥持久化，重启不掉登录 |
| **时序攻击防护** | 用 `subtle.ConstantTimeCompare` 比对用户名和签名 |
| **用户名不泄露** | 用户名错和密码错返回**同样的**提示 |
| **失败限流** | **5 次**密码错误锁 **5 分钟**，锁定期间**正确密码也拒绝** |
| **暴力破解告警** | 触发锁定时通过已配置的通知渠道推送 |
| **HttpOnly + SameSite** | JS 读不到 cookie，降低 XSS 影响 |

### 不需要登录的路径

登录页本身和几个静态资源是公开的（否则登录页加载不出来）：

```
/login  /api/login  /api/logout  /api/whoami
/healthz  /favicon.ico  /manifest.json
/icon-192.png  /icon-512.png  /icon-maskable-512.png
/apple-touch-icon.png
```

**其余全部需要登录**，包括所有 `/api/*`。

### 接口

| 接口 | 说明 |
|---|---|
| `POST /api/login` | body `{"user":"...","pass":"..."}`，成功后种 cookie |
| `POST /api/logout` | 清除 cookie |
| `GET /api/whoami` | 返回 `{authEnabled, loggedIn, user}` |

未登录访问 `/api/*` 返回 **401 + `{"needLogin":true}`**，前端会自动跳登录页。

### 退出登录

页面右上角有**「退出」**按钮（配置了认证才显示）。

---

## 常见问题

### 构建时拉不到 golang 镜像

国内网络问题。配置 Docker 镜像加速，或在能上网的机器上构建后导出：

```bash
# 在有网的机器上（x86_64）
docker build -t net-dashboard:latest .
docker save net-dashboard:latest | gzip > net-dashboard.tar.gz

# 传到 NAS 后
gunzip -c net-dashboard.tar.gz | docker load
docker compose up -d
```

### 卡在 `go mod tidy`

需要拉取 `golang.org/x/crypto`。如果 NAS 网络受限，用上面的"本地构建 + 导出"方式。

### 页面显示"SSH 采集失败"

检查：

```bash
# 在 NAS 上（容器外）测试 SSH 连通性
ssh root@192.168.31.1 "echo ok"

# 看容器日志
docker compose logs -f
```

常见原因：
- `ROUTER_SSH_PASS` 填错
- 路由器的 SSH 被关闭了（重启后需要重新开）
- NAS 和路由器不在同一网段

### 页面能开但数据都是横线

```bash
# 看容器能否访问路由器端口
docker compose exec dashboard wget -qO- http://192.168.31.1:19090/version
```

如果容器访问不到路由器，检查 NAS 的防火墙是否放行容器出站。

### 端口 18080 被占用

改 `docker-compose.yml` 里 `ports` 左边的数字，例如 `"18081:8080"`。

---

## API 说明

后端提供的接口（前端用 `/api/all` 一次性拉全部）：

| 接口 | 内容 |
|---|---|
| `GET /api/all` | 全部数据（推荐） |
| `GET /api/router` | 路由器系统 + 网络 + 服务状态 |
| `GET /api/mihomo` | mihomo 概览 |
| `GET /api/proxies` | 代理组 + 节点列表（含延迟） |
| `GET /api/test?group=<组名>` | **整组测速**，返回 `{节点: 延迟ms}` |
| `POST /api/switch` | **切换节点**，body `{"group":"节点选择","node":"节点名"}` |
| `GET /api/adguard` | AdGuard 统计 |
| `POST /api/protection` | **暂停/恢复广告过滤**，body `{"enabled":true}` |
| `POST /api/control` | **服务启停**，body `{"service":"speedtest","action":"start"}` |
| `POST /api/subscription` | **更新机场订阅**，body `{}` 或 `{"provider":"机场"}` |
| `POST /api/dns/flush` | **清 DNS 缓存**（AdGuard + dnsmasq） |
| `GET /api/history?hours=24` | **历史采样点**（流量/负载/温度/延迟/DNS） |
| `GET /api/nas` | **NAS 主机**：磁盘、文件系统、温度、内存 |
| `GET /api/traffic` | **设备流量排行**（读路由器 conntrack） |
| `GET /api/links` | 快捷入口 + 订阅列表 |
| `POST /api/notify/test` | **发一条测试通知**，验证渠道配置 |
| `GET /api/devices` | 设备 + 无线 + 进程 |
| `GET /healthz` | 健康检查 |

### 服务控制白名单

`/api/control` **只接受预设组合**，前端无法传入任意命令（避免变成 RCE 漏洞）：

| service | 可用 action |
|---|---|
| `speedtest` | `start` / `stop` / `restart` |
| `mihomo` | `start` / `restart` |
| `adguard` | `start` / `restart` |

> ⚠️ **故意不提供 `adguard: stop`** —— 停掉 AdGuard 会让全屋 DNS 中断。
> 要关过滤请用 `/api/protection`（AdGuard 自己的保护开关）。

已验证的拒绝行为：

```
evil + start           -> 不支持的服务: evil
speedtest + rm -rf /   -> 不支持的动作: rm -rf /
mihomo + stop          -> 不支持的动作: stop     （未开放）
GET /api/control       -> 只支持 POST
```

---

## 安装路由器端脚本

服务控制依赖路由器上的启停脚本。测速的脚本在 `router-scripts/`，**需要手动装到路由器**：

```bash
# 在路由器上执行（SSH 进去）
cd /mnt/usb-6c7b7949/speedtest

cat > start.sh << 'SCRIPT_EOF'
#!/bin/sh
PORT_HEX=":46A1 "
DIR=/mnt/usb-6c7b7949/speedtest
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "已在运行"; exit 0
fi
i=0
while [ ! -x "$DIR/speedtest-backend" ] && [ "$i" -lt 30 ]; do sleep 1; i=$((i+1)); done
if [ ! -x "$DIR/speedtest-backend" ]; then echo "二进制不存在"; exit 1; fi
cd "$DIR" || exit 1
( "$DIR/speedtest-backend" -c "$DIR/settings.toml" >> "$DIR/speedtest.log" 2>&1 < /dev/null & )
sleep 2
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "已启动: http://192.168.31.1:18081/"; exit 0
fi
echo "启动失败"; tail -20 "$DIR/speedtest.log"; exit 1
SCRIPT_EOF

cat > stop.sh << 'SCRIPT_EOF'
#!/bin/sh
PORT_HEX=":46A1 "
if ! grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "未在运行"; exit 0
fi
killall speedtest-backend 2>/dev/null
sleep 1
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  killall -9 speedtest-backend 2>/dev/null; sleep 1
fi
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "停止失败"; exit 1
fi
echo "已停止"; exit 0
SCRIPT_EOF

chmod +x start.sh stop.sh

# 原地验证
sh start.sh
sh stop.sh
sh start.sh
```

**为什么要重写 `run.sh`**：原来的脚本用 `ps w | grep -q "[s]peedtest-backend"` 做存活检测，
在脚本环境里不可靠（我们已经在 AdGuard 上踩过这个坑）。新脚本改用**端口检测**。

> 旧的 `run.sh` 可以留着，也可以删掉。

`mihomo` 和 `AdGuardHome` 的 `start.sh` 之前已经装好了，无需改动。

---

## 通知推送

支持 6 种渠道，**配置了哪个用哪个**（可同时配多个）。配好后点仪表盘右上角
**「测试通知」**验证。

| 渠道 | 环境变量 | 填什么 |
|---|---|---|
| **企业微信 群机器人** ⭐推荐 | `NOTIFY_WECOM` | 群机器人 webhook 的 key |
| **企业微信 自建应用** | `NOTIFY_WECOM_CORP`<br>`NOTIFY_WECOM_SECRET`<br>`NOTIFY_WECOM_AGENT`<br>`NOTIFY_WECOM_TOUSER`<br>`NOTIFY_WECOM_BASE` | 企业ID / 应用Secret / AgentId / 接收人 / **API地址（可用自建代理）** |
| **Bark**（iOS） | `NOTIFY_BARK` | key，或完整地址 `https://api.day.app/xxx` |
| **Telegram** | `NOTIFY_TELEGRAM` | `bot_token:chat_id` |
| **ntfy** | `NOTIFY_NTFY` | `https://ntfy.sh/你的topic` |
| **通用 Webhook** | `NOTIFY_WEBHOOK` | 你的地址，会 POST `{title,body,level,time}` |

### 企业微信：三种方式怎么选

| | 群机器人 ⭐ | 自建应用（直连） | 自建应用（走代理） |
|---|---|---|---|
| **配置** | 复制一个 key | corpid + secret + agentid | 同左 + 代理地址 |
| **IP 白名单** | ❌ 不需要 | ✅ 必须配「企业可信IP」 | ❌ 代理的 IP 已配好 |
| **公网 IP 变了** | 不受影响 | **失效，要重配** | 不受影响 |
| **适合** | **告警推送** | 临时用 | **已有代理的用户** |

#### 用自建代理（wxchat 等）

如果你已经在跑 [wxchat-Docker](https://github.com/DDSRem-Dev/wxchat-Docker)
这类「企业微信 API 转发代理」（跑在有固定公网 IP 的服务器上），把 API 地址指过去即可：

```ini
NOTIFY_WECOM_BASE=http://你的代理地址:端口
```

**代理需要能转发这两个路径**：

```
GET  {BASE}/cgi-bin/gettoken
POST {BASE}/cgi-bin/message/send
```

**先验证代理是否支持**：

```bash
curl -s --max-time 10 \
  "http://你的代理地址:端口/cgi-bin/gettoken?corpid=你的corpid&corpsecret=你的Secret"
```

| 返回 | 含义 |
|---|---|
| `{"errcode":0,"access_token":"...","expires_in":7200}` | ✅ **可用** |
| `{"errcode":40013,"errmsg":"invalid corpid..."}` | ✅ **可用**（只是参数不对） |
| HTML / nginx 404 / 连接失败 | ❌ 不是 API 代理 |

> 自建应用报错的常见原因（代码里已翻译成人话）：
>
> | errcode | 含义 |
> |---|---|
> | `40013` | corpid 无效 |
> | `40001` | secret 无效 |
> | `40056` | agentid 无效 |
> | `60020` | **调用方 IP 不在「企业可信IP」列表里** |
> | `81013` | 接收人不存在或不在应用可见范围 |

**最低级别** `NOTIFY_MIN_LEVEL`：

| 值 | 会推送什么 |
|---|---|
| `info` | 全部（含"服务已恢复"） |
| `warn`（默认） | 服务掉线、新设备、温度过高、内存吃紧 |
| `error` | 只有服务掉线这类严重问题 |

**触发条件**：

- 服务掉线 / 恢复（mihomo、AdGuard、测速）
- **新设备接入网络**（陌生 MAC）
- 路由器温度 ≥ `TEMP_ALERT`
- 路由器内存 ≥ `MEM_ALERT`

> 同一告警 10 分钟内只推一次，避免刷屏。
> 首次运行会先把**现有设备**记录为已知，**之后新接入的**才会告警。

---

## 趋势图与历史数据

后台每 `SAMPLE_SEC` 秒（默认 60）采一个点，保留 **7 天**，数据落在
`./data/history.json`（约 1MB）。

> ⚠️ **必须挂载 `./data:/data`**，否则容器重建后历史全丢。

页面「趋势」卡片有 5 个标签页：

| 标签 | 内容 |
|---|---|
| **流量** | 下行 / 上行 B/s |
| **负载/内存** | CPU 1 分钟负载、内存占用 % |
| **温度** | 路由器温度 ℃ |
| **节点延迟** | 当前生效节点的延迟 ms |
| **DNS 拦截** | 每分钟查询数、每分钟拦截数 |

刚部署时图是空的——**等几分钟**才有曲线。

---

## NAS 硬盘

容器需要**只读挂载**主机目录才能读到 NAS 的硬盘信息：

```yaml
volumes:
  - /:/host/root:ro
  - /sys:/host/sys:ro
```

| 数据 | 来源 | 需要挂载吗 |
|---|---|---|
| 磁盘列表、容量 | `/sys/block/*/size` | 不需要（块设备不隔离） |
| 磁盘读写速率 | `/proc/diskstats` | 不需要 |
| 分区占用率 | `/host/root/proc/mounts` + Statfs | **需要** `/:ro` |
| 温度 | `/host/sys/class/hwmon` | 需要 `/sys:ro`，且看机器 |

**不挂载也能跑**，只是「NAS 硬盘」卡片会提示不可用，其他功能不受影响。

> 温度取决于机器有没有暴露传感器。NAS 的**硬盘温度**通常要 `smartctl`
> 才能读到（需要额外权限），本项目**不读取硬盘 SMART**，只显示能拿到的传感器。

---

## Docker 服务清单

「Docker 服务」卡片列出 NAS 上所有容器，**每个映射端口都是一个可点链接** —— 不用再记端口号。

需要挂载 Docker socket：

```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock:ro
```

> ⚠️ **安全说明**：挂载 `docker.sock` 等于把宿主 Docker 的控制权交给这个容器。
> 本程序**只调用只读接口**（`GET /containers/json`），但如果你在意，可以改用
> [docker-socket-proxy](https://github.com/11notes/docker-socket-proxy)：
>
> ```yaml
> services:
>   socket-proxy:
>     image: 11notes/socket-proxy:stable
>     environment:
>       - ALLOW_GET=1
>     volumes:
>       - /var/run/docker.sock:/run/docker.sock:ro
>
>   dashboard:
>     environment:
>       - DOCKER_SOCK=/run/docker-proxy.sock   # 指向代理
>     volumes:
>       - socket-proxy:/run                       # 共享代理的 socket
> ```
>
> **不挂载也能跑**，只是这张卡片会显示不可用。

### 端口显示规则

| 外观 | 含义 | 能不能点 |
|---|---|---|
| **蓝色实线** `:8096` | 有端口映射（`-p`）**或** host 网络模式，**端口直接开在 NAS 上** | ✅ 点开 `http://NAS的IP:8096` |
| **灰色实线** `:3306` | 同上，但看着像数据库/消息队列（3306、6379、5432…） | ✅ 也能点，只是提示多半不是网页 |
| **虚线灰框** `:3306` | 只在 Dockerfile 里 `EXPOSE` 了，**没发布到宿主**，容器外访问不到 | ❌ 不可点（鼠标悬停有说明） |

### host 网络模式的容器自动识别

很多容器用 `network_mode: host`（Jellyfin、qBittorrent、Lucky、MoviePilot…），
这类容器**没有端口映射**，`docker ps` 里看不到端口。

仪表盘会额外调一次 `/containers/{id}/json`，读取它声明的端口
（`Config.ExposedPorts`）并判断网络模式：

- `HostConfig.NetworkMode == "host"` → 端口开在宿主上 → **显示成可点的蓝色**
- 否则（bridge 且未发布）→ **显示成虚线，不可点**

> 为了减少调用，只在「运行中 **且** 没有已发布端口」时才去 inspect。

### 自定义名称 / 图标

容器名经常看不懂（`a1b2c3d4`、`qinglong`…）。有两种方式改：

#### 方式一：配置文件（推荐，不用动容器）

编辑 `./data/containers.json`：

```json
{
  "alist":     { "name": "Alist 网盘",   "icon": "📁" },
  "qinglong":  { "name": "青龙面板",     "icon": "🐉" },
  "qbittorrent": { "name": "qBittorrent", "icon": "⬇️",
                   "url": "http://192.168.31.52:8080" },
  "mysql":     { "hide": true }
}
```

**只对实际存在的容器生效** —— 表里写 100 个、你只装了 3 个，其余 97 个
静静地躺着，不报错、不显示。所以可以放一张**大表**：现在用的 + 以后可能装的，
**装了哪个就自动有名字**。

`containers.example.json` 已经预置了 **76 条**常见容器（Alist、青龙、MoviePilot、
Jellyfin、qBittorrent、Emby、Portainer、Home Assistant…），直接拷来用：

```bash
cp containers.example.json data/containers.json
```

**可以在文件里写注释**：任何解析不出配置的键都会被跳过（比如
`"//": "这是说明文字"`），不会连累有效条目。启动日志会打印：

```
容器名配置: 已载入 74 条（跳过 2 个非配置项）
```

| 字段 | 说明 |
|---|---|
| `name` | 显示名 |
| `icon` | 图标（emoji） |
| `url` | 指定地址（不填则用映射端口自动拼）。**可以写 http 或 https** |
| `group` | 分组名（暂只用于排序） |
| `hide` | 隐藏这个容器 |

> **自签名 HTTPS 的情况**：像 Sakura Frp 启动器的 WebUI 跑在
> `https://NAS的IP:7102`（自签证书），浏览器第一次打开会警告 —— 点「继续访问」即可。
> 地址写成 `https://...` 就行。
>
> 例：
> ```json
> "natfrp-service": {
>   "name": "Sakura Frp", "icon": "🚇",
>   "url": "https://192.168.31.52:7102"
> }
> ```

改完 **点卡片右上角「刷新」** 即可生效，**不用重启容器**。

#### 方式二：容器标签（需要重建容器）

```yaml
labels:
  - dashboard.name=Alist 网盘
  - dashboard.icon=📁
  - dashboard.url=http://192.168.31.52:5244
```

### 端口颜色

| 颜色 | 含义 |
|---|---|
| **蓝色** | 像是 Web 界面（3000-9999、80、443 等） |
| **灰色** | 像是数据库/消息队列等非 Web 服务（3306、6379、5432…） |

灰色端口也能点，只是提示你它多半不是网页。

---

## 设备流量排行

读路由器 conntrack 表统计每个内网 IP 的流量：

```sh
/proc/net/nf_conntrack      # 首选
/proc/net/ip_conntrack      # 备选
conntrack -L                # 最后兜底
```

**两个前提**：

1. 路由器内核启用了 `nf_conntrack`
2. 开启了字节计数 `nf_conntrack_acct`（否则只能显示**连接数**）

**自检命令**（路由器上跑）：

```bash
# conntrack 表在不在
ls -l /proc/net/nf_conntrack /proc/net/ip_conntrack 2>/dev/null

# 有没有 bytes= 计数
grep -c "bytes=" /proc/net/nf_conntrack 2>/dev/null

# 计数开关
cat /proc/sys/net/netfilter/nf_conntrack_acct 2>/dev/null
```

- 有 `bytes=` → 显示流量
- 没有 → 卡片会提示"只能看连接数"，仍可用

---

## 手机加到桌面（PWA）

用手机浏览器打开仪表盘 → 菜单 → **「添加到主屏幕」**。

会装成一个独立 App：有自己的图标、全屏无地址栏、深色状态栏。

| 平台 | 操作 |
|---|---|
| **iOS Safari** | 分享 → 添加到主屏幕 |
| **Android Chrome** | 菜单 → 添加到主屏幕 / 安装应用 |

---

## 快捷入口

默认显示 AdGuard / mihomo / 测速 / 路由器。要改成自己的（比如加 TP-Link、NAS）：

```ini
LINK_1_NAME=TP-Link
LINK_1_URL=http://192.168.31.7/
LINK_1_ICON=router

LINK_2_NAME=NAS
LINK_2_URL=http://192.168.31.52:9999/
LINK_2_ICON=nas
```

**填了任意 `LINK_n_*` 就完全替换默认列表**（最多 8 个）。

可用图标：`router` `nas` `shield` `proxy` `speed` `lucky` `link`

---

## 技术细节（踩过的坑）

### 1. 订阅节点不在 `/proxies` 里

如果 mihomo 用 `proxy-providers` 加载订阅，**节点不会出现在 `/proxies`**，只
有内置项（DIRECT / REJECT / 各分组）。

节点要通过 **`/providers/proxies`** 的 `providers.<名字>.proxies` 获取：

```json
{
  "providers": {
    "default": { "proxies": [ DIRECT, REJECT, 分组... ] },
    "机场":     { "proxies": [ 46 个订阅节点 ], "updatedAt": "..." }
  }
}
```

### 2. 节点延迟会丢

订阅重载后，节点的 `history`（延迟历史）会被清空。要主动触发测速：

```
GET /group/<组名>/delay?url=http://www.gstatic.com/generate_204&timeout=5000
```

mihomo 会并发测试整组，约 5 秒返回 `{节点名: 延迟}`。前端「测速」按钮就是调这个。

> 节点名含 emoji（如 `🇭🇰 香港Y01`），URL 路径要用 `url.PathEscape` 编码。

### 3. 路由器 SSH 只支持 ssh-rsa（重要！）

小米路由器跑的是 **dropbear**，主机密钥**只提供 `ssh-rsa`（SHA-1）**。而新版
OpenSSH / Go 默认不再优先这个算法，会直接报：

```
no matching host key type found. Their offer: ssh-rsa
```

**代码里已显式声明算法**（`main.go` 的 `sshClient()`）：

```go
HostKeyAlgorithms: []string{"ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", ...},
Config: ssh.Config{
    KeyExchanges: []string{"curve25519-sha256@libssh.org", ...},
    Ciphers:      []string{"aes128-ctr", "aes256-ctr", ...},
    MACs:         []string{"hmac-sha2-256", "hmac-sha1", ...},
},
```

如果你的设备连不上又报算法错误，把 `sshClient()` 里的列表调宽即可。

**手动验证命令**：

```bash
ssh -o HostKeyAlgorithms=+ssh-rsa root@192.168.31.1 "echo ok"
```

### 4. Docker Hub 在国内不可达

`Dockerfile` 默认用 **DaoCloud 镜像源** + **goproxy.cn**。如果你的网络能直连
Docker Hub，可以覆盖：

```bash
docker compose build \
  --build-arg GO_IMAGE=golang:1.23-alpine \
  --build-arg RUNTIME_IMAGE=alpine:3.20
```

---

## 刷新频率与缓存

- 前端每 **5 秒** 刷新一次（可点「暂停刷新」）
- SSH 采集有 **6 秒** 缓存，避免频繁连路由器
- 公网 IP 查询有 **10 分钟** 缓存

---

## 修改界面

前端是单文件：`static/index.html`（内嵌 CSS/JS）。

改完需要重新构建：

```bash
docker compose up -d --build
```

因为 HTML 是**编译进二进制**的（Go embed），所以改完必须重建。

---

## 安全提示

- `.env` 含密码，**不要提交到 git**、不要外传
- 仪表盘**没有登录验证**，只适合在局域网内用
- 如果要外网访问，建议配合 Lucky 反向代理 + 访问密码

---

## 目录结构

```
dashboard/
├── main.go              Go 后端（HTTP API + SSH 采集 + 内嵌前端）
├── static/index.html    前端单页
├── go.mod               Go 依赖声明
├── Dockerfile           多阶段构建
├── docker-compose.yml   部署配置
├── .env.example         配置模板
└── README.md            本文件
```
