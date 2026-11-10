#!/bin/sh
# ============================================================
#  LibreSpeed 测速 - 启动脚本（幂等）
#
#  要点：
#   1. 用端口检测（/proc/net/tcp）判断是否在跑，不用 ps|grep
#      —— ps|grep 在脚本里会误匹配自身，之前踩过这个坑
#   2. ( cmd & ) 双 fork 脱离，SSH 断开后进程也不会被杀
#   3. 先等 U 盘挂载，避免开机时 U 盘还没就绪
#
#  18081 = 0x46A1（/proc/net/tcp 里端口是十六进制）
# ============================================================

PORT_HEX=":46A1 "
DIR=/mnt/usb-6c7b7949/speedtest

# 已在运行 → 直接成功返回
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "已在运行"
  exit 0
fi

# 等 U 盘挂载 + 二进制可执行（最多 30 秒）
i=0
while [ ! -x "$DIR/speedtest-backend" ] && [ "$i" -lt 30 ]; do
  sleep 1
  i=$((i + 1))
done
if [ ! -x "$DIR/speedtest-backend" ]; then
  echo "二进制不存在或不可执行: $DIR/speedtest-backend"
  exit 1
fi

cd "$DIR" || exit 1

# 双 fork 脱离终端
( "$DIR/speedtest-backend" -c "$DIR/settings.toml" >> "$DIR/speedtest.log" 2>&1 < /dev/null & )

sleep 2

if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "已启动: http://192.168.31.1:18081/"
  exit 0
fi

echo "启动失败，最后 20 行日志："
tail -20 "$DIR/speedtest.log" 2>/dev/null
exit 1
