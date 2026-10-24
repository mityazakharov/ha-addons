# Собирает конфиг sing-box из /data/options.json.
# Поддерживаются ссылки vless:// (Reality, TLS, без шифрования; tcp, ws, grpc, httpupgrade, http)
# и ss:// (SIP002 и старый формат base64). Сообщения об ошибках не содержат саму ссылку — в ней ключи.

def trim: gsub("^\\s+|\\s+$"; "");

def urldecode:
  gsub("%(?<h>[0-9A-Fa-f]{2})";
    .h | ascii_downcase | explode
       | map(if . >= 97 then . - 87 else . - 48 end)
       | [.[0] * 16 + .[1]] | implode);

# base64 и base64url, с паддингом и без
def b64decode:
  gsub("-"; "+") | gsub("_"; "/") | gsub("\\s"; "")
  | ((4 - (length % 4)) % 4) as $pad
  | (if $pad > 0 then . + ("=" * $pad) else . end)
  | @base64d;

def nonempty($v): ($v // "") != "";

def parse_url:
  (capture("^(?<scheme>[a-zA-Z0-9]+)://(?<userinfo>.+)@(?<host>\\[[^\\]]+\\]|[^:/?#\\[]+):(?<port>[0-9]+)/?(?:\\?(?<query>[^#]*))?(?:#.*)?$")
    // error("не удалось разобрать ссылку: ожидается формат протокол://данные@сервер:порт"))
  | .host |= (ltrimstr("[") | rtrimstr("]"))
  | .port |= tonumber
  | .params = ((.query // "") | split("&")
      | map(select(length > 0) | split("=") | {key: .[0], value: (.[1:] | join("=") | urldecode)})
      | from_entries);

def vless($tag):
  parse_url as $u | $u.params as $p
  | ($p.security // "none") as $sec
  | ($p.type // "tcp") as $net
  | {type: "vless", tag: $tag, server: $u.host, server_port: $u.port,
     uuid: ($u.userinfo | urldecode), packet_encoding: "xudp"}
  + (if nonempty($p.flow) then {flow: $p.flow} else {} end)
  + (if $sec == "reality" then
       {tls: {enabled: true,
              server_name: (if nonempty($p.sni) then $p.sni else error("\($tag): в ссылке VLESS Reality нет параметра sni") end),
              utls: {enabled: true, fingerprint: (if nonempty($p.fp) then $p.fp else "chrome" end)},
              reality: {enabled: true,
                        public_key: (if nonempty($p.pbk) then $p.pbk else error("\($tag): в ссылке VLESS Reality нет параметра pbk") end),
                        short_id: ($p.sid // "")}}}
     elif $sec == "tls" then
       {tls: ({enabled: true,
               server_name: (if nonempty($p.sni) then $p.sni elif nonempty($p.host) then $p.host else $u.host end)}
              + (if nonempty($p.fp) then {utls: {enabled: true, fingerprint: $p.fp}} else {} end)
              + (if nonempty($p.alpn) then {alpn: ($p.alpn | split(","))} else {} end)
              + (if ($p.allowInsecure // $p.insecure // "0") == "1" then {insecure: true} else {} end))}
     elif $sec == "none" then {}
     else error("\($tag): VLESS security=\($sec) не поддерживается") end)
  + (if $net == "tcp" or $net == "raw" then {}
     elif $net == "ws" then
       {transport: ({type: "ws", path: ($p.path // "/")}
                    + (if nonempty($p.host) then {headers: {Host: $p.host}} else {} end))}
     elif $net == "grpc" then
       {transport: {type: "grpc", service_name: ($p.serviceName // "")}}
     elif $net == "httpupgrade" then
       {transport: ({type: "httpupgrade", path: ($p.path // "/")}
                    + (if nonempty($p.host) then {host: $p.host} else {} end))}
     elif $net == "http" or $net == "h2" then
       {transport: ({type: "http", path: ($p.path // "/")}
                    + (if nonempty($p.host) then {host: ($p.host | split(","))} else {} end))}
     else error("\($tag): транспорт VLESS type=\($net) не поддерживается sing-box") end);

def ss($tag):
  # Старый формат: ss://base64(method:password@host:port)#name
  (if test("@") then . else "ss://" + (ltrimstr("ss://") | sub("#.*$"; "") | b64decode) end)
  | parse_url as $u
  | (if nonempty($u.params.plugin) then error("\($tag): плагины Shadowsocks (plugin=) не поддерживаются") else . end)
  | ($u.userinfo | urldecode) as $ui
  # SIP002: userinfo — base64(method:password) или, для Shadowsocks-2022, method:password как есть
  | (if ($ui | test(":")) then $ui else ($ui | b64decode) end) as $cred
  | ($cred | index(":")) as $i
  | if $i == null then error("\($tag): в ссылке Shadowsocks не найдены метод и пароль") else . end
  | {type: "shadowsocks", tag: $tag, server: $u.host, server_port: $u.port,
     method: $cred[:$i], password: $cred[$i + 1:]};

def outbound($tag):
  if startswith("vless://") then vless($tag)
  elif startswith("ss://") then ss($tag)
  else error("\($tag): поддерживаются только ссылки vless:// и ss://") end;

((.primary_link // "") | trim) as $primary
| ((.backup_link // "") | trim) as $backup
| if $primary == "" then error("не задана основная ссылка (primary_link)") else . end
| ([$primary | outbound("primary")]
   + (if $backup != "" then [$backup | outbound("backup")] else [] end)) as $servers
| ($servers | length > 1) as $failover
| {
    log: {level: .log_level, timestamp: true},
    dns: {servers: [{type: "local", tag: "local"}]},
    inbounds: [{type: "mixed", tag: "proxy-in", listen: "0.0.0.0", listen_port: 1080}],
    outbounds: ($servers
      + (if $failover then
           [{type: "urltest", tag: "auto", outbounds: ($servers | map(.tag)),
             url: .test_url, interval: "1m", tolerance: 300}]
         else [] end)),
    route: {
      final: (if $failover then "auto" else "primary" end),
      default_domain_resolver: "local"
    }
  }
