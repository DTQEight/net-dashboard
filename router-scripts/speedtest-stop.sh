#!/bin/sh
# ============================================================
#  LibreSpeed 测速 - 停止脚本
#  18081 = 0x46A1
# ============================================================

PORT_HEX=":46A1 "

if ! grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "未在运行"
  exit 0
fi

# 先温和终止
killall speedtest-backend 2>/dev/null
sleep 1

# 还活着就强杀
if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  killall -9 speedtest-backend 2>/dev/null
  sleep 1
fi

if grep -q "$PORT_HEX" /proc/net/tcp /proc/net/tcp6 2>/dev/null; then
  echo "停止失败"
  exit 1
fi

echo "已停止"
exit 0
