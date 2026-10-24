#!/bin/sh
# Собирает конфиг sing-box из ссылок в настройках дополнения и запускает прокси.
# Ссылки содержат ключи, поэтому в лог выводятся только протокол и сервер.
set -eu

OPTIONS=/data/options.json
CONFIG=/tmp/sing-box.json

jq -f /parse.jq "$OPTIONS" > "$CONFIG"

jq -r '.outbounds[] | select(.server) | "[sing-box proxy] \(.tag): \(.type) \(.server):\(.server_port)"' "$CONFIG"

sing-box check -c "$CONFIG"
exec sing-box run -c "$CONFIG"
