"""
Многопоточный тестер прокси-конфигов (VLESS + VMESS + Trojan + Shadowsocks)
Читает серверы из файла servers.txt
"""

import subprocess
import json
import time
import tempfile
import os
import sys
import re
import random
import socket
import threading
import base64
import asyncio
import aiohttp
from datetime import datetime
from urllib.parse import unquote, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Tuple, Any

# ─── Настройки ──────────────────────────────────────────────────────────────
SERVERS_FILE   = "servers.txt"
MAX_WORKERS    = 100
PING_WORKERS   = 100
CONNECT_TIMEOUT = 3
PROXY_TIMEOUT   = 6
XRAY_START_WAIT = 1.5
RETRY_COUNT     = 2
PORT_RANGE      = (20000, 59999)
SKIP_UNREACHABLE = True
TCP_PING_FIRST  = True
TCP_PING_TRIES  = 2
# ────────────────────────────────────────────────────────────────────────────

print_lock = threading.Lock()

def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)


# ══════════════════════════════════════════════════════════════════
#  Парсинг URL
# ══════════════════════════════════════════════════════════════════

def parse_ss_url(raw_url: str) -> dict | None:
    """
    Парсит ссылки вида:
      ss://BASE64(method:password)@host:port#Name
      ss://BASE64(method:password@host:port)#Name
    """
    url = raw_url.strip()
    if not url.startswith("ss://"):
        return None

    body = url[5:]

    name = ""
    if "#" in body:
        body, fragment = body.rsplit("#", 1)
        name = unquote(fragment)

    if "@" in body:
        userinfo_b64, host_port = body.split("@", 1)
    else:
        try:
            decoded = base64.urlsafe_b64decode(body + "===").decode("utf-8")
        except Exception:
            return None
        if "@" not in decoded:
            return None
        parts = decoded.split("@", 1)
        method_pass = parts[0]
        host_port = parts[1]
        userinfo_b64 = base64.urlsafe_b64encode(method_pass.encode()).decode().rstrip("=")

    try:
        decoded_userinfo = base64.urlsafe_b64decode(userinfo_b64 + "===").decode("utf-8")
    except Exception:
        return None

    if ":" not in decoded_userinfo:
        return None
    method, password = decoded_userinfo.split(":", 1)

    query_str = ""
    if "?" in host_port:
        host_port, query_str = host_port.split("?", 1)

    host_port = host_port.rstrip("/")
    if host_port.startswith("["):
        bracket_end = host_port.index("]")
        host = host_port[1:bracket_end]
        port_part = host_port[bracket_end + 1:].lstrip(":").rstrip("/")
        port = int(port_part) if port_part else 8388
    elif ":" in host_port:
        h, p = host_port.rsplit(":", 1)
        host = h
        port = int(p.rstrip("/"))
    else:
        host = host_port
        port = 8388

    params = {}
    if query_str:
        for kv in query_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = unquote(v)

    return {
        "protocol": "shadowsocks",
        "method":   method,
        "password": password,
        "host":     host,
        "port":     port,
        "params":   params,
        "name":     name or f"ss://{host}:{port}",
        "raw":      raw_url,
        "userinfo": f"{method}:{password}",
    }


def parse_vmess_url(raw_url: str) -> dict | None:
    """
    Парсит VMESS ссылки вида:
      vmess://base64(JSON)
    JSON содержит поля: add, port, id, aid, net, type, host, path,
                        tls, sni, alpn, fp, ps (name)
    """
    url = raw_url.strip()
    if not url.startswith("vmess://"):
        return None

    b64 = url[8:]

    name = ""
    if "#" in b64:
        b64, fragment = b64.rsplit("#", 1)
        name = unquote(fragment)

    try:
        padding = 4 - len(b64) % 4
        if padding != 4:
            b64 += "=" * padding
        decoded = base64.b64decode(b64).decode("utf-8")
        cfg = json.loads(decoded)
    except Exception:
        return None

    host = cfg.get("add", "")
    port = int(cfg.get("port", 443))
    uid  = cfg.get("id", "")
    aid  = int(cfg.get("aid", 0))
    net  = cfg.get("net", "tcp")
    type_ = cfg.get("type", "none")
    tls  = cfg.get("tls", "")
    host_header = cfg.get("host", "")
    path = cfg.get("path", "/")
    sni  = cfg.get("sni", host_header or host)
    alpn = cfg.get("alpn", "")
    fp   = cfg.get("fp", "")
    ps   = cfg.get("ps", "")

    if not name:
        name = ps or f"vmess://{host}:{port}"

    params = {
        "type": net,
        "security": "tls" if tls == "tls" else "none",
        "host": host_header,
        "path": path,
        "sni": sni,
    }
    if alpn:
        params["alpn"] = alpn
    if fp:
        params["fp"] = fp

    return {
        "protocol": "vmess",
        "userinfo": uid,
        "host":     host,
        "port":     port,
        "aid":      aid,
        "params":   params,
        "name":     name,
        "raw":      raw_url,
    }


def parse_proxy_url(raw_url: str) -> dict | None:
    url = raw_url.strip()
    if not url:
        return None

    if url.startswith("ss://"):
        return parse_ss_url(url)

    if url.startswith("vmess://"):
        return parse_vmess_url(url)

    if url.startswith("vless://"):
        proto = "vless"
        body  = url[8:]
    elif url.startswith("trojan://"):
        proto = "trojan"
        body  = url[9:]
    else:
        return None

    name = ""
    if "#" in body:
        body, fragment = body.rsplit("#", 1)
        name = unquote(fragment)

    if "@" not in body:
        return None

    userinfo, rest = body.split("@", 1)

    query_str = ""
    if "?" in rest:
        host_port, query_str = rest.split("?", 1)
    else:
        host_port = rest

    host_port = host_port.rstrip('/')
    
    if host_port.startswith("["):
        bracket_end = host_port.index("]")
        host = host_port[1:bracket_end]
        port_part = host_port[bracket_end + 1:]
        port_part = port_part.lstrip(":").rstrip("/")
        port = int(port_part) if port_part else 443
    elif ":" in host_port:
        h, p = host_port.rsplit(":", 1)
        p = p.rstrip('/')
        host = h
        port = int(p)
    else:
        host = host_port
        port = 443

    params: dict[str, str] = {}
    if query_str:
        for kv in query_str.split("&"):
            if "=" in kv:
                k, v = kv.split("=", 1)
                params[k] = unquote(v)

    return {
        "protocol": proto,
        "userinfo": userinfo,
        "host":     host,
        "port":     port,
        "params":   params,
        "name":     name or f"{proto}://{host}:{port}",
        "raw":      raw_url,
    }

# ══════════════════════════════════════════════════════════════════
#  Генерация конфига Xray
# ══════════════════════════════════════════════════════════════════

def _stream_settings(params: dict, host: str) -> dict:
    network  = params.get("type", "tcp")
    security = params.get("security", params.get("tls", "none"))
    sni      = params.get("sni", params.get("host", host))
    ws_host  = params.get("host", host)
    path     = params.get("path", "/")
    insecure = params.get("allowInsecure", params.get("insecure", "0")) == "1"
    alpn     = [a for a in params.get("alpn", "").split(",") if a]

    ss: dict = {"network": network, "security": security}

    if security == "tls":
        tls: dict = {"serverName": sni, "allowInsecure": insecure}
        if alpn:
            tls["alpn"] = alpn
        fp = params.get("fp", "")
        if fp:
            tls["fingerprint"] = fp
        ss["tlsSettings"] = tls

    if security == "reality":
        ss["realitySettings"] = {
            "serverName": sni,
            "publicKey":  params.get("pbk", ""),
            "shortId":    params.get("sid", ""),
            "spiderX":    params.get("spx", ""),
            "fingerprint": params.get("fp", "chrome"),
        }

    if network == "ws":
        ss["wsSettings"] = {
            "path": path,
            "headers": {"Host": ws_host},
        }
    elif network == "grpc":
        ss["grpcSettings"] = {
            "serviceName": params.get("serviceName", path.lstrip("/")),
        }
    elif network == "http" or network == "h2":
        ss["httpSettings"] = {
            "path": path,
            "host": [ws_host],
        }

    return ss


def build_xray_config(parsed: dict, socks_port: int, http_port: int) -> dict | None:
    proto  = parsed["protocol"]
    params = parsed["params"]
    host   = parsed["host"]
    port   = parsed["port"]

    if proto == "vless":
        uid = parsed["userinfo"]
        outbound = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port":    port,
                    "users": [{
                        "id":         uid,
                        "encryption": params.get("encryption", "none"),
                        "flow":       params.get("flow", ""),
                    }],
                }]
            },
            "streamSettings": _stream_settings(params, host),
            "tag": "proxy",
        }

    elif proto == "vmess":
        uid = parsed["userinfo"]
        aid = parsed.get("aid", 0)
        outbound = {
            "protocol": "vmess",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port":    port,
                    "users": [{
                        "id":       uid,
                        "alterId":  aid,
                        "security": params.get("encryption", "auto"),
                    }],
                }]
            },
            "streamSettings": _stream_settings(params, host),
            "tag": "proxy",
        }

    elif proto == "trojan":
        uid = parsed["userinfo"]
        outbound = {
            "protocol": "trojan",
            "settings": {
                "servers": [{
                    "address":  host,
                    "port":     port,
                    "password": uid,
                }]
            },
            "streamSettings": _stream_settings(params, host),
            "tag": "proxy",
        }

    elif proto == "shadowsocks":
        method   = parsed.get("method", "aes-256-gcm")
        password = parsed.get("password", "")
        outbound = {
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{
                    "address":  host,
                    "port":     port,
                    "method":   method,
                    "password": password,
                }]
            },
            "tag": "proxy",
        }

    else:
        return None

    return {
        "log": {"loglevel": "none"},
        "inbounds": [
            {
                "listen":   "127.0.0.1",
                "port":     socks_port,
                "protocol": "socks",
                "settings": {"udp": False, "auth": "noauth"},
            },
            {
                "listen":   "127.0.0.1",
                "port":     http_port,
                "protocol": "http",
                "settings": {},
            },
        ],
        "outbounds": [outbound],
    }


# ══════════════════════════════════════════════════════════════════
#  Утилиты
# ══════════════════════════════════════════════════════════════════

def find_xray() -> str | None:
    candidates = [
        os.path.expanduser(r"~\scoop\apps\xray\current\xray.exe"),
        "/usr/local/bin/xray",
        "/usr/bin/xray",
        "xray",
    ]
    scoop_dir = os.path.expanduser(r"~\scoop\apps\xray")
    if os.path.isdir(scoop_dir):
        for ver in sorted(os.listdir(scoop_dir), reverse=True):
            p = os.path.join(scoop_dir, ver, "xray.exe")
            if os.path.isfile(p):
                candidates.insert(0, p)

    for path in candidates:
        try:
            # Убрал shell=True
            r = subprocess.run(
                [path, "-version"],
                capture_output=True, text=True, timeout=3
            )
            if r.returncode == 0 or "Xray" in r.stdout:
                return path
        except Exception:
            continue
    return None


# ══════════════════════════════════════════════════════════════════
#  Асинхронный TCP-пинг с использованием asyncio
# ══════════════════════════════════════════════════════════════════

async def async_tcp_ping(host: str, port: int, timeout: float = CONNECT_TIMEOUT, tries: int = 1) -> Optional[float]:
    """
    Асинхронный TCP-пинг. Возвращает время в миллисекундах или None.
    """
    best_time = None
    
    for attempt in range(tries):
        try:
            start = time.perf_counter()
            # Используем asyncio.open_connection для асинхронного соединения
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            elapsed = (time.perf_counter() - start) * 1000
            writer.close()
            await writer.wait_closed()
            
            if best_time is None or elapsed < best_time:
                best_time = elapsed
                
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            continue
        except Exception:
            continue
    
    return best_time


async def batch_async_tcp_ping(servers_data: List[dict]) -> Dict[int, float]:
    """
    Асинхронный параллельный TCP-пинг всех серверов.
    """
    ping_results = {}
    
    async def ping_one(server_data):
        idx = server_data["index"]
        host = server_data.get("host")
        port = server_data.get("port")
        
        if not host or not port:
            return idx, None
        
        ping_ms = await async_tcp_ping(host, port, timeout=CONNECT_TIMEOUT, tries=TCP_PING_TRIES)
        return idx, ping_ms
    
    safe_print(f"\n  🏓 TCP-пинг {len(servers_data)} серверов (асинхронно)...")
    t0 = time.time()
    
    # Создаем задачи для всех серверов
    tasks = [ping_one(sd) for sd in servers_data]
    results = await asyncio.gather(*tasks)
    
    # Собираем результаты
    for idx, ping_ms in results:
        if ping_ms is not None:
            ping_results[idx] = ping_ms
    
    elapsed = time.time() - t0
    reachable = len(ping_results)
    safe_print(f"  ✅ TCP-пинг завершён за {elapsed:.1f}с. Доступно: {reachable}/{len(servers_data)} "
               f"({reachable/len(servers_data)*100:.1f}%)")
    
    # Показываем статистику по пингу
    if ping_results:
        pings = list(ping_results.values())
        avg_ping = sum(pings) / len(pings)
        min_ping = min(pings)
        max_ping = max(pings)
        safe_print(f"     📊 Пинг: средний={avg_ping:.0f}ms, мин={min_ping:.0f}ms, макс={max_ping:.0f}ms")
    
    return ping_results


# Функция-обертка для синхронного вызова
def batch_tcp_ping(servers_data: list[dict]) -> dict[int, float]:
    """Синхронная обертка для асинхронного TCP-пинга"""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    
    if loop and loop.is_running():
        # Если уже есть running loop, создаем новый в другом потоке
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(asyncio.run, batch_async_tcp_ping(servers_data))
            return future.result()
    else:
        # Запускаем новую event loop
        return asyncio.run(batch_async_tcp_ping(servers_data))


def check_via_socks5(socks_port: int) -> dict | None:
    """Проверка через SOCKS5 прокси (с таймаутом)"""
    try:
        import socks as _socks
        s = _socks.socksocket()
        s.set_proxy(_socks.SOCKS5, "127.0.0.1", socks_port)
        s.settimeout(PROXY_TIMEOUT)
        s.connect(("ip-api.com", 80))
        s.sendall(b"GET /json/?fields=66846719 HTTP/1.1\r\nHost: ip-api.com\r\nConnection: close\r\n\r\n")

        buf = b""
        deadline = time.time() + PROXY_TIMEOUT
        while time.time() < deadline:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            except socket.timeout:
                break
        s.close()

        body = buf.split(b"\r\n\r\n", 1)[-1]
        data = json.loads(body.decode("utf-8", errors="replace"))
        if data.get("status") == "success":
            return {
                "ip":          data.get("query", ""),
                "country":     data.get("country", ""),
                "countryCode": data.get("countryCode", ""),
                "city":        data.get("city", ""),
                "isp":         data.get("isp", ""),
                "as":          data.get("as", ""),
            }
    except Exception:
        pass
    return None


def unique_ports() -> tuple[int, int]:
    a = random.randint(*PORT_RANGE)
    b = a + 1 if a < PORT_RANGE[1] else a - 1
    return a, b


# ══════════════════════════════════════════════════════════════════
#  Tester
# ══════════════════════════════════════════════════════════════════

class ProxyTester:
    def __init__(self, xray_path: str):
        self.xray_path    = xray_path
        self._tmp_files   = []
        self._processes   = []  # Список запущенных процессов для graceful shutdown
        self._lock        = threading.Lock()

    def _start_xray(self, config: dict) -> subprocess.Popen | None:
        """Запуск Xray с временным конфигом (без shell=True)"""
        cfg_path = None
        try:
            # Создаем временный файл с delete=False для ручного управления
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, encoding="utf-8"
            ) as f:
                json.dump(config, f)
                cfg_path = f.name
            
            with self._lock:
                self._tmp_files.append(cfg_path)

            kwargs = dict(
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
            else:
                kwargs["start_new_session"] = True

            proc = subprocess.Popen(
                [self.xray_path, "run", "-config", cfg_path], **kwargs
            )
            
            with self._lock:
                self._processes.append(proc)
            
            # Ждем запуска
            time.sleep(XRAY_START_WAIT)
            
            # Проверяем, не завершился ли процесс
            if proc.poll() is not None:
                with self._lock:
                    self._processes.remove(proc)
                return None
                
            return proc
        except Exception as e:
            # Чистим конфиг в случае ошибки
            if cfg_path and os.path.exists(cfg_path):
                try:
                    os.unlink(cfg_path)
                    with self._lock:
                        if cfg_path in self._tmp_files:
                            self._tmp_files.remove(cfg_path)
                except Exception:
                    pass
            return None

    @staticmethod
    def _stop(proc: subprocess.Popen):
        """Остановка процесса с таймаутом"""
        if proc and proc.poll() is None:
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

    def cleanup(self):
        """Очистка временных файлов и процессов"""
        # Останавливаем все процессы
        with self._lock:
            for proc in self._processes:
                self._stop(proc)
            self._processes.clear()
            
            # Удаляем временные файлы
            for path in self._tmp_files:
                try:
                    if os.path.exists(path):
                        os.unlink(path)
                except Exception:
                    pass
            self._tmp_files.clear()

    def test(self, raw_url: str, index: int, tcp_ping_ms: float | None = None) -> dict:
        parsed = parse_proxy_url(raw_url)
        name   = parsed["name"] if parsed else raw_url[:80]

        result = {
            "index":    index,
            "name":     name,
            "protocol": parsed["protocol"] if parsed else "unknown",
            "server":   parsed["host"]     if parsed else None,
            "port":     parsed["port"]     if parsed else None,
            "url":      raw_url[:300],
            "ts":       datetime.now().isoformat(),
            "connected":     False,
            "exit_ip":       None,
            "exit_country":  None,
            "exit_country_code": None,
            "exit_city":     None,
            "isp":           None,
            "ping_ms":       tcp_ping_ms,
            "error":         None,
        }

        if not parsed:
            result["error"] = "Неизвестный протокол"
            safe_print(f"  [{index}] ⚠️  Пропуск — {result['error']}: {raw_url[:60]}")
            return result

        # Если есть TCP-пинг и он None — сервер недоступен
        if SKIP_UNREACHABLE and tcp_ping_ms is None:
            result["error"] = "Недоступен (TCP-пинг не прошёл)"
            safe_print(f"  [{index}] ⏭️  Пропуск — {parsed['host']}:{parsed['port']} недоступен")
            return result

        safe_print(f"  [{index}] 🔍 {parsed['protocol'].upper()} | {parsed['host']}:{parsed['port']} | {name[:50]}")

        socks_port, http_port = unique_ports()
        config = build_xray_config(parsed, socks_port, http_port)
        if not config:
            result["error"] = "Не удалось построить конфиг"
            return result

        proc = self._start_xray(config)
        if not proc:
            result["error"] = "Xray не запустился"
            safe_print(f"  [{index}] ❌ {result['error']}")
            return result

        try:
            geo = None
            for attempt in range(RETRY_COUNT):
                geo = check_via_socks5(socks_port)
                if geo:
                    break
                if attempt < RETRY_COUNT - 1:
                    time.sleep(1.5)

            if geo:
                result.update({
                    "connected":         True,
                    "exit_ip":           geo["ip"],
                    "exit_country":      geo["country"],
                    "exit_country_code": geo["countryCode"],
                    "exit_city":         geo["city"],
                    "isp":               geo["isp"],
                })
                ping_str = f"  ping={result['ping_ms']:.0f}ms" if result["ping_ms"] else ""
                safe_print(
                    f"  [{index}] ✅ {geo['country']} / {geo['city']} | "
                    f"{geo['ip']} | {geo['isp'][:35]}{ping_str}"
                )
            else:
                result["error"] = "Не удалось получить IP через прокси"
                safe_print(f"  [{index}] ❌ {result['error']}")

        finally:
            self._stop(proc)
            with self._lock:
                if proc in self._processes:
                    self._processes.remove(proc)

        return result


# ══════════════════════════════════════════════════════════════════
#  Загрузка серверов
# ══════════════════════════════════════════════════════════════════

def load_servers(filename: str) -> list[str]:
    servers = []
    if not os.path.isfile(filename):
        print(f"⚠️  Файл '{filename}' не найден — создаём пример...")
        _create_example_file(filename)
        print(f"✅ Создан '{filename}'. Добавьте свои серверы и перезапустите.\n")
        return []

    with open(filename, encoding="utf-8") as f:
        for raw_line in f:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(("vless://", "trojan://", "ss://", "vmess://")):
                servers.append(line)
            else:
                print(f"  ⚠️  Пропускаем строку (неизвестный формат): {line[:60]}")

    return servers


def _create_example_file(filename: str):
    content = """\
# СПИСОК СЕРВЕРОВ ДЛЯ ПРОВЕРКИ
# Поддерживаются: vless://, vmess://, trojan://, ss://
# Строки с # — комментарии

# --- VLESS примеры ---
# vless://UUID@host:port?encryption=none&security=tls&sni=...&type=ws&host=...&path=%2F#Name

# --- VMESS примеры ---
# vmess://eyJhZGQiOiJ...

# --- Trojan примеры ---
# trojan://PASSWORD@host:port?security=tls&sni=...&type=ws&host=...&path=%2F#Name

# --- Shadowsocks примеры ---
# ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpQQVNTV09SRA@host:port#Name

# Вставьте свои серверы ниже:
"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)


# ══════════════════════════════════════════════════════════════════
#  Консольный отчёт
# ══════════════════════════════════════════════════════════════════

def print_report(results: list[dict], elapsed: float):
    working = [r for r in results if r["connected"]]
    failed  = [r for r in results if not r["connected"]]

    print("\n" + "═" * 72)
    print("  📊  ИТОГОВЫЙ ОТЧЁТ")
    print("═" * 72)
    print(f"  ⏱  Время: {elapsed:.1f}с   "
          f"✅ Рабочих: {len(working)}   "
          f"❌ Нерабочих: {len(failed)}   "
          f"📦 Всего: {len(results)}")

    if working:
        print("\n  ─── РАБОЧИЕ ─────────────────────────────────────────────────────")
        sorted_working = sorted(working, key=lambda x: (x.get("ping_ms") or 9999, x["index"]))
        for r in sorted_working:
            ping = f" | {r['ping_ms']:.0f}ms" if r.get("ping_ms") else ""
            print(f"  [{r['index']:>3}] ✅  {r['protocol'].upper():<6} "
                  f"{r['exit_country']:<18} {r['exit_ip']:<16}{ping}")
            print(f"       └─ {r['name'][:65]}")

    if failed:
        print("\n  ─── НЕ РАБОЧИЕ ──────────────────────────────────────────────────")
        for r in sorted(failed, key=lambda x: x["index"]):
            err = r.get("error", "неизвестно")
            print(f"  [{r['index']:>3}] ❌  {r['protocol'].upper():<6} "
                  f"{r.get('server','?'):<30} {err}")

    print("═" * 72)


# ══════════════════════════════════════════════════════════════════
#  HTML-отчёт
# ══════════════════════════════════════════════════════════════════

def _flag_emoji(country_code: str) -> str:
    """ISO 3166-1 alpha-2 → emoji flag"""
    if not country_code or len(country_code) != 2:
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


# Заменяем только функцию save_html_report и всё, что с ней связано

def save_html_report(results: list[dict], elapsed: float):
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    html_file = f"report_{ts}.html"

    working = [r for r in results if r["connected"]]
    failed  = [r for r in results if not r["connected"]]
    total   = len(results)

    countries = sorted({
        r["exit_country"] for r in working if r.get("exit_country")
    })

    def ping_bar(ms):
        if ms is None:
            return '<span class="ping-na">—</span>'
        color = "#4ade80" if ms < 100 else "#facc15" if ms < 300 else "#f87171"
        return f'<span class="ping-val" style="color:{color}">{ms:.0f}<span class="ping-unit">ms</span></span>'

    def escape_html(text):
        """Экранирование HTML и JS"""
        if not text:
            return ""
        return (text
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
                .replace("'", "&#39;"))

    def build_rows():
        rows = []
        for r in results:
            cc   = r.get("exit_country_code") or ""
            flag = _flag_emoji(cc)
            ok   = r["connected"]
            country_attr = r.get("exit_country", "") or ""
            proto_badge = f'<span class="badge badge-{r["protocol"]}">{r["protocol"].upper()}</span>'
            
            # Числовое значение пинга для сортировки
            ping_value = r.get("ping_ms") if r.get("ping_ms") is not None else 9999
            
            # Статус для сортировки (1 = работает, 0 = не работает)
            status_value = 1 if ok else 0
            
            safe_url = escape_html(r["url"])
            full_url = r.get("url", "")
            
            # Кнопка копирования
            copy_btn = f'''<button class="copy-btn" onclick="copyToClipboard(this)" data-url="{escape_html(full_url)}" title="Copy link">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
            </button>'''

            if ok:
                rows.append(f'''
  <tr class="row-ok" data-country="{country_attr}" data-ping="{ping_value:.0f}" data-status="1">
    <td class="td-idx">{r["index"]}</td>
    <td>{proto_badge}</td>
    <td class="td-name" title="{safe_url}">{r["name"][:60]}</td>
    <td class="td-status"><span class="status-dot ok"></span></td>
    <td class="td-country">{flag} {country_attr}</td>
    <td class="td-city">{r.get("exit_city") or "—"}</td>
    <td class="td-ip mono">{r.get("exit_ip") or "—"}</td>
    <td class="td-isp">{(r.get("isp") or "—")[:40]}</td>
    <td class="td-ping">{ping_bar(r.get("ping_ms"))}</td>
    <td class="td-link">{copy_btn}</td>
  </tr>''')
            else:
                # Для нерабочих серверов добавляем пустые колонки вместо colspan
                error_msg = r.get("error") or "—"
                rows.append(f'''
  <tr class="row-fail" data-country="" data-ping="{ping_value:.0f}" data-status="0">
    <td class="td-idx">{r["index"]}</td>
    <td>{proto_badge}</td>
    <td class="td-name" title="{safe_url}">{r["name"][:60]}</td>
    <td class="td-status"><span class="status-dot fail"></span></td>
    <td class="td-country">—</td>
    <td class="td-city">—</td>
    <td class="td-ip mono">—</td>
    <td class="td-isp td-error">{error_msg}</td>
    <td class="td-ping">{ping_bar(r.get("ping_ms"))}</td>
    <td class="td-link">{copy_btn}</td>
  </tr>''')
        return "\n".join(rows)

    country_buttons_fixed = ""
    for c in countries:
        cc_val = ""
        for r in results:
            if r.get("exit_country") == c and r.get("exit_country_code"):
                cc_val = r["exit_country_code"]
                break
        country_buttons_fixed += f'<button class="filter-btn" data-country="{c}">{_flag_emoji(cc_val)} {c}</button>\n'

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Proxy Report — {generated_at}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Manrope:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg:        #0d0f14;
    --bg2:       #13161d;
    --bg3:       #1a1e28;
    --border:    #252a38;
    --border2:   #2e3447;
    --accent:    #6c63ff;
    --accent2:   #4f46e5;
    --green:     #4ade80;
    --red:       #f87171;
    --yellow:    #facc15;
    --text:      #e2e8f0;
    --text2:     #94a3b8;
    --text3:     #64748b;
    --radius:    10px;
    --radius-sm: 6px;
  }}

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  body {{
    font-family: 'Manrope', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 0 0 60px;
  }}

  .header {{
    background: linear-gradient(135deg, #0d0f14 0%, #13161d 50%, #0f1119 100%);
    border-bottom: 1px solid var(--border);
    padding: 28px 40px 24px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse 60% 80% at 80% 50%, rgba(108,99,255,.08) 0%, transparent 70%);
    pointer-events: none;
  }}
  .header-row {{
    display: flex;
    align-items: center;
    gap: 16px;
    margin-bottom: 20px;
  }}
  .logo {{
    width: 42px; height: 42px;
    background: linear-gradient(135deg, var(--accent), #a78bfa);
    border-radius: 10px;
    display: flex; align-items: center; justify-content: center;
    font-size: 20px;
    box-shadow: 0 0 20px rgba(108,99,255,.35);
    flex-shrink: 0;
  }}
  .header-title {{
    font-size: 22px;
    font-weight: 800;
    letter-spacing: -.5px;
  }}
  .header-title span {{ color: var(--accent); }}
  .header-sub {{
    font-size: 12px;
    color: var(--text3);
    font-family: 'JetBrains Mono', monospace;
    margin-top: 2px;
  }}

  .stats {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }}
  .stat-card {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 14px 20px;
    min-width: 120px;
    position: relative;
    overflow: hidden;
    transition: border-color .2s;
  }}
  .stat-card::after {{
    content: '';
    position: absolute;
    bottom: 0; left: 0; right: 0;
    height: 2px;
    border-radius: 0 0 var(--radius) var(--radius);
  }}
  .stat-card.green::after  {{ background: var(--green); }}
  .stat-card.red::after    {{ background: var(--red); }}
  .stat-card.accent::after {{ background: var(--accent); }}
  .stat-card.yellow::after {{ background: var(--yellow); }}
  .stat-num {{
    font-size: 28px;
    font-weight: 800;
    line-height: 1;
    font-family: 'JetBrains Mono', monospace;
  }}
  .stat-card.green  .stat-num {{ color: var(--green); }}
  .stat-card.red    .stat-num {{ color: var(--red); }}
  .stat-card.accent .stat-num {{ color: var(--accent); }}
  .stat-card.yellow .stat-num {{ color: var(--yellow); }}
  .stat-label {{
    font-size: 11px;
    color: var(--text3);
    margin-top: 4px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .5px;
  }}

  .content {{ padding: 28px 40px 0; }}

  .filters {{
    display: flex;
    align-items: center;
    gap: 10px;
    flex-wrap: wrap;
    margin-bottom: 20px;
  }}
  .filter-label {{
    font-size: 12px;
    color: var(--text3);
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .5px;
    margin-right: 4px;
  }}
  .filter-btn {{
    background: var(--bg3);
    border: 1px solid var(--border);
    color: var(--text2);
    border-radius: 20px;
    padding: 5px 14px;
    font-size: 12px;
    font-family: 'Manrope', sans-serif;
    font-weight: 600;
    cursor: pointer;
    transition: all .15s;
    white-space: nowrap;
  }}
  .filter-btn:hover {{ border-color: var(--accent); color: var(--text); }}
  .filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
    box-shadow: 0 0 12px rgba(108,99,255,.4);
  }}
  .filter-sep {{
    width: 1px;
    height: 24px;
    background: var(--border);
    margin: 0 4px;
  }}

  .search-wrap {{ margin-left: auto; }}
  .search-input {{
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    padding: 6px 14px;
    outline: none;
    width: 220px;
    transition: border-color .15s;
  }}
  .search-input:focus {{ border-color: var(--accent); }}
  .search-input::placeholder {{ color: var(--text3); }}

  .table-wrap {{
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
    overflow-x: auto;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    min-width: 1000px;
  }}
  thead tr {{
    background: var(--bg3);
    border-bottom: 1px solid var(--border2);
  }}
  th {{
    padding: 11px 14px;
    text-align: left;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .6px;
    color: var(--text3);
    white-space: nowrap;
    cursor: pointer;
    user-select: none;
    transition: color .15s;
  }}
  th:hover {{ color: var(--text2); }}
  th.sort-asc::after  {{ content: ' ↑'; color: var(--accent); }}
  th.sort-desc::after {{ content: ' ↓'; color: var(--accent); }}

  tbody tr {{
    border-bottom: 1px solid var(--border);
    transition: background .12s;
  }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: var(--bg3); }}
  tbody tr.hidden {{ display: none; }}

  td {{
    padding: 10px 14px;
    font-size: 13px;
    color: var(--text2);
    vertical-align: middle;
  }}

  .td-idx     {{ color: var(--text3); font-family: 'JetBrains Mono', monospace; font-size: 11px; width: 40px; }}
  .td-name    {{ color: var(--text); font-weight: 500; max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .td-city    {{ color: var(--text3); }}
  .td-status  {{ text-align: center; width: 60px; }}
  .mono       {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
  .td-isp     {{ max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .td-error   {{ color: var(--red); font-size: 12px; opacity: .8; }}
  .td-country {{ white-space: nowrap; }}
  .td-ping    {{ text-align: center; width: 80px; }}
  .td-link    {{ text-align: center; width: 50px; }}

  .status-dot {{
    width: 8px; height: 8px;
    border-radius: 50%;
    display: inline-block;
  }}
  .status-dot.ok   {{ background: var(--green);  box-shadow: 0 0 6px var(--green); }}
  .status-dot.fail {{ background: var(--red);    box-shadow: 0 0 6px var(--red); }}

  .badge {{
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: .5px;
    font-family: 'JetBrains Mono', monospace;
  }}
  .badge-vless   {{ background: rgba(108,99,255,.18); color: #a78bfa; border: 1px solid rgba(108,99,255,.3); }}
  .badge-vmess   {{ background: rgba(59, 130, 246, .12); color: #60a5fa; border: 1px solid rgba(59, 130, 246, .3); }}
  .badge-trojan  {{ background: rgba(250,204,21,.12);  color: #facc15; border: 1px solid rgba(250,204,21,.3); }}
  .badge-ss      {{ background: rgba(74,222,128,.12);  color: #4ade80; border: 1px solid rgba(74,222,128,.3); }}
  .badge-unknown {{ background: rgba(148,163,184,.1);  color: var(--text3); border: 1px solid var(--border); }}

  .ping-val  {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; font-weight: 600; }}
  .ping-unit {{ font-size: 10px; opacity: .7; margin-left: 1px; }}
  .ping-na   {{ color: var(--text3); }}

  /* Copy button */
  .copy-btn {{
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text3);
    border-radius: 4px;
    padding: 4px 8px;
    cursor: pointer;
    transition: all .15s;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }}
  .copy-btn:hover {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }}
  .copy-btn.copied {{
    background: var(--green);
    border-color: var(--green);
    color: #fff;
  }}

  /* Toast notification */
  .toast {{
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--accent);
    color: #fff;
    padding: 10px 20px;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 600;
    opacity: 0;
    transform: translateY(10px);
    transition: all .3s;
    pointer-events: none;
    z-index: 1000;
  }}
  .toast.show {{
    opacity: 1;
    transform: translateY(0);
  }}

  .empty-state {{
    text-align: center;
    padding: 48px 20px;
    color: var(--text3);
    font-size: 14px;
    display: none;
  }}
  .empty-state.visible {{ display: block; }}

  .footer {{
    margin-top: 24px;
    font-size: 11px;
    color: var(--text3);
    font-family: 'JetBrains Mono', monospace;
    text-align: center;
  }}

  ::-webkit-scrollbar {{ width: 6px; height: 6px; }}
  ::-webkit-scrollbar-track {{ background: var(--bg); }}
  ::-webkit-scrollbar-thumb {{ background: var(--border2); border-radius: 3px; }}
  ::-webkit-scrollbar-thumb:hover {{ background: var(--text3); }}

  @media (max-width: 700px) {{
    .header, .content {{ padding-left: 16px; padding-right: 16px; }}
    .stats {{ gap: 8px; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-row">
    <div class="logo">🛡</div>
    <div>
      <div class="header-title">Proxy<span>Tester</span> Report</div>
      <div class="header-sub">Generated {generated_at} · {elapsed:.1f}s · {MAX_WORKERS} threads</div>
    </div>
  </div>
  <div class="stats">
    <div class="stat-card accent">
      <div class="stat-num">{total}</div>
      <div class="stat-label">Total</div>
    </div>
    <div class="stat-card green">
      <div class="stat-num">{len(working)}</div>
      <div class="stat-label">Working</div>
    </div>
    <div class="stat-card red">
      <div class="stat-num">{len(failed)}</div>
      <div class="stat-label">Failed</div>
    </div>
    <div class="stat-card yellow">
      <div class="stat-num">{len(countries)}</div>
      <div class="stat-label">Countries</div>
    </div>
    <div class="stat-card green">
      <div class="stat-num">{round(len(working)/total*100) if total else 0}%</div>
      <div class="stat-label">Success rate</div>
    </div>
  </div>
</div>

<div class="content">
  <div class="filters">
    <span class="filter-label">Filter</span>
    <button class="filter-btn active" data-filter="all">🌐 All</button>
    <button class="filter-btn" data-filter="ok">✅ Working</button>
    <button class="filter-btn" data-filter="fail">❌ Failed</button>
    <div class="filter-sep"></div>
    {country_buttons_fixed}
    <div class="search-wrap">
      <input class="search-input" type="text" placeholder="Search name / IP / ISP…" id="searchInput">
    </div>
  </div>

  <div class="table-wrap">
    <table id="proxyTable">
      <thead>
        <tr>
          <th data-col="index">#</th>
          <th data-col="proto">Proto</th>
          <th data-col="name">Name</th>
          <th data-col="status">Status</th>
          <th data-col="country">Country</th>
          <th data-col="city">City</th>
          <th data-col="ip">Exit IP</th>
          <th data-col="isp">ISP</th>
          <th data-col="ping">Ping</th>
          <th data-col="link">Link</th>
        </tr>
      </thead>
      <tbody id="tableBody">
        {build_rows()}
      </tbody>
    </table>
    <div class="empty-state" id="emptyState">No results match the filter</div>
  </div>

  <div class="footer">proxy-tester · vless + vmess + trojan + shadowsocks · xray-core</div>
</div>

<div class="toast" id="toast">Copied!</div>

<script>
  const rows     = Array.from(document.querySelectorAll('#tableBody tr'));
  const empty    = document.getElementById('emptyState');
  const search   = document.getElementById('searchInput');
  const filterBtns = document.querySelectorAll('.filter-btn');
  const toast    = document.getElementById('toast');

  let activeStatus  = 'all';
  let activeCountry = '';
  let searchQuery   = '';
  let sortCol       = null;
  let sortDir       = 1;

  function applyFilters() {{
    let visible = 0;
    rows.forEach(row => {{
      const isOk      = row.classList.contains('row-ok');
      const country   = row.dataset.country || '';
      const text      = row.textContent.toLowerCase();

      const statusOk  = activeStatus === 'all'
                      || (activeStatus === 'ok'   && isOk)
                      || (activeStatus === 'fail' && !isOk);
      const countryOk = !activeCountry || country === activeCountry;
      const searchOk  = !searchQuery   || text.includes(searchQuery);

      if (statusOk && countryOk && searchOk) {{
        row.classList.remove('hidden');
        visible++;
      }} else {{
        row.classList.add('hidden');
      }}
    }});
    empty.classList.toggle('visible', visible === 0);
  }}

  // Copy to clipboard
  window.copyToClipboard = function(btn) {{
    const url = btn.dataset.url;
    if (!url) return;
    
    navigator.clipboard.writeText(url).then(() => {{
      btn.classList.add('copied');
      setTimeout(() => btn.classList.remove('copied'), 1500);
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2000);
    }}).catch(err => {{
      // Fallback
      const textarea = document.createElement('textarea');
      textarea.value = url;
      textarea.style.position = 'fixed';
      textarea.style.opacity = '0';
      document.body.appendChild(textarea);
      textarea.select();
      try {{
        document.execCommand('copy');
        btn.classList.add('copied');
        setTimeout(() => btn.classList.remove('copied'), 1500);
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 2000);
      }} catch (e) {{
        alert('Failed to copy');
      }}
      document.body.removeChild(textarea);
    }});
  }};

  // Filter buttons
  filterBtns.forEach(btn => {{
    btn.addEventListener('click', () => {{
      const f = btn.dataset.filter;
      const c = btn.dataset.country;

      if (f) {{
        filterBtns.forEach(b => {{ if (b.dataset.filter) b.classList.remove('active'); }});
        btn.classList.add('active');
        activeStatus  = f;
        activeCountry = '';
        filterBtns.forEach(b => {{ if (b.dataset.country) b.classList.remove('active'); }});
      }} else if (c !== undefined) {{
        const alreadyActive = btn.classList.contains('active');
        filterBtns.forEach(b => {{ if (b.dataset.country !== undefined) b.classList.remove('active'); }});
        if (!alreadyActive) {{
          btn.classList.add('active');
          activeCountry = c;
        }} else {{
          activeCountry = '';
        }}
      }}
      applyFilters();
    }});
  }});

  // Search
  search.addEventListener('input', () => {{
    searchQuery = search.value.toLowerCase().trim();
    applyFilters();
  }});

  // Sort function that uses data attributes for special columns
  function getSortValue(row, col) {{
    switch(col) {{
      case 'ping':
        return parseFloat(row.dataset.ping) || 9999;
      case 'status':
        return parseInt(row.dataset.status) || 0;
      case 'index':
        return parseInt(row.querySelector('.td-idx')?.textContent) || 0;
      default:
        // Для обычных колонок берём текст из ячейки
        const headers = Array.from(document.querySelectorAll('th[data-col]'));
        const colIndex = headers.findIndex(h => h.dataset.col === col);
        return (row.cells[colIndex]?.textContent || '').trim();
    }}
  }}

  // Sort
  document.querySelectorAll('th[data-col]').forEach(th => {{
    th.addEventListener('click', () => {{
      const col = th.dataset.col;
      
      // Toggle sort direction
      if (sortCol === col) {{
        sortDir *= -1;
      }} else {{
        sortCol = col;
        sortDir = 1;
      }}

      // Update header indicators
      document.querySelectorAll('th').forEach(t => t.classList.remove('sort-asc','sort-desc'));
      th.classList.add(sortDir === 1 ? 'sort-asc' : 'sort-desc');

      const tbody = document.getElementById('tableBody');
      const allRows = Array.from(tbody.querySelectorAll('tr'));
      
      const sorted = allRows.sort((a, b) => {{
        const av = getSortValue(a, col);
        const bv = getSortValue(b, col);
        
        // Числовое сравнение
        if (typeof av === 'number' && typeof bv === 'number') {{
          return (av - bv) * sortDir;
        }}
        
        // Строковое сравнение
        return String(av).localeCompare(String(bv)) * sortDir;
      }});
      
      sorted.forEach(r => tbody.appendChild(r));
    }});
  }});
</script>
</body>
</html>"""

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  💾 HTML-отчёт: {html_file}")
    return html_file


# ══════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════

def ensure_pysocks():
    try:
        import socks  # noqa: F401
    except ImportError:
        print("📦 Устанавливаем PySocks...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pysocks", "-q"],
            check=False,
        )
        import socks  # noqa: F401


def main():
    print("═" * 72)
    print("  🛡️   PROXY TESTER (Оптимизированная версия)")
    print("═" * 72)

    ensure_pysocks()

    xray = find_xray()
    if not xray:
        print("\n❌ Xray-core не найден!")
        print("   Windows: scoop install xray")
        print("   Linux:   https://github.com/XTLS/Xray-core/releases")
        sys.exit(1)
    print(f"  ✅ Xray: {xray}")

    servers = load_servers(SERVERS_FILE)
    if not servers:
        print(f"\n  ⚠️  Нет серверов в '{SERVERS_FILE}'. Добавьте URL и перезапустите.")
        sys.exit(0)

    print(f"  📋 Серверов: {len(servers)}  │  Потоков: {MAX_WORKERS}\n")
    
    # Парсинг URL
    safe_print("  📝 Парсинг URL...")
    servers_data = []
    for i, url in enumerate(servers, 1):
        parsed = parse_proxy_url(url)
        if parsed:
            servers_data.append({
                "index": i,
                "host": parsed["host"],
                "port": parsed["port"],
                "url": url,
                "parsed": parsed,
            })
        else:
            servers_data.append({
                "index": i,
                "host": None,
                "port": None,
                "url": url,
                "parsed": None,
            })
    safe_print(f"  ✅ Распознано: {len([s for s in servers_data if s['parsed']])} из {len(servers)}")
    
    # TCP-пинг (асинхронный)
    ping_results = {}
    if TCP_PING_FIRST:
        ping_results = batch_tcp_ping(servers_data)
    
    # Тестирование прокси
    print("\n" + "─" * 72)
    safe_print(f"  🔬 Тестирование прокси ({MAX_WORKERS} потоков)...")
    
    if SKIP_UNREACHABLE and ping_results:
        reachable = [s for s in servers_data if s["index"] in ping_results]
        unreachable = [s for s in servers_data if s["index"] not in ping_results]
        
        safe_print(f"     Доступных для проверки: {len(reachable)}")
        safe_print(f"     Пропускаем (нет TCP-пинга): {len(unreachable)}")
        
        test_queue = reachable
    else:
        test_queue = servers_data
    
    tester = ProxyTester(xray)
    results = []
    t0 = time.time()

    try:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = {}
            for sd in test_queue:
                idx = sd["index"]
                url = sd["url"]
                ping_ms = ping_results.get(idx)
                fut = ex.submit(tester.test, url, idx, ping_ms)
                futures[fut] = idx
            
            # Добавляем результаты для пропущенных серверов
            if SKIP_UNREACHABLE and ping_results:
                skipped_indices = set(s["index"] for s in servers_data) - set(s["index"] for s in test_queue)
                for idx in skipped_indices:
                    sd = next(s for s in servers_data if s["index"] == idx)
                    results.append({
                        "index": idx,
                        "name": sd["parsed"]["name"] if sd["parsed"] else sd["url"][:80],
                        "protocol": sd["parsed"]["protocol"] if sd["parsed"] else "unknown",
                        "server": sd["parsed"]["host"] if sd["parsed"] else None,
                        "port": sd["parsed"]["port"] if sd["parsed"] else None,
                        "url": sd["url"][:300],
                        "ts": datetime.now().isoformat(),
                        "connected": False,
                        "exit_ip": None,
                        "exit_country": None,
                        "exit_country_code": None,
                        "exit_city": None,
                        "isp": None,
                        "ping_ms": None,
                        "error": "Недоступен (TCP-пинг не прошёл)",
                    })
            
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    results.append(res)
    finally:
        tester.cleanup()

    elapsed = time.time() - t0
    results.sort(key=lambda x: x["index"])

    print_report(results, elapsed)
    save_html_report(results, elapsed)

    print("\n  ✅ Готово!\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Прервано пользователем")
        sys.exit(0)
    except Exception as exc:
        print(f"\n❌ Критическая ошибка: {exc}")
        import traceback
        traceback.print_exc()
        sys.exit(1)