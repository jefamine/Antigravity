#!/usr/bin/env python3
"""Defensive overlay for loysger/Antigravity v1.0.46 (master, 2026-10-12).
Does not contact the network, install software, or run the target app.
Run from the root of a fresh checkout: python apply_hardening.py
"""
from pathlib import Path
import sys

ROOT = Path.cwd()
EXPECTED = [
    'src-tauri/src/tunnel.rs',
    'src-tauri/src/local_proxy.rs',
    'src-tauri/src/db.rs',
    'src-tauri/src/lib.rs',
    'src/App.tsx',
]

TUNNEL = r'''//! Hardened reverse tunnel: explicit remote CONNECT policy.
//! Default: TLS gateway only; destination public IPv4:443; official AI vendor hosts only.
//! Override host allowlist with AG_TUNNEL_EXTRA_HOSTS=host.example,*.example.org.
//! Compatibility escape hatch AG_TUNNEL_MODE=public_443 permits arbitrary PUBLIC IPv4:443.
//! Never permits loopback, link-local, private, CGNAT or special-purpose destinations.

use futures_util::{SinkExt, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};

const DEFAULT_DOMAINS: &[&str] = &[
    "googleapis.com", "google.com", "google.dev", "googlecloud.com",
    "googleusercontent.com", "gstatic.com", "antigravity.google",
    "anthropic.com", "claude.ai",
];

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    match o {
        [0, ..] | [10, ..] | [127, ..] | [224..=255, ..] => false,
        [100, 64..=127, ..] => false,               // shared / CGNAT
        [169, 254, ..] => false,                   // link local
        [172, 16..=31, ..] => false,               // RFC1918
        [192, 0, 0, ..] => false,                  // IETF protocol assignments
        [192, 0, 2, ..] => false,                  // documentation
        [192, 88, 99, ..] => false,                // legacy anycast
        [192, 168, ..] => false,                   // RFC1918
        [198, 18..=19, ..] => false,               // benchmarks
        [198, 51, 100, ..] => false,               // documentation
        [203, 0, 113, ..] => false,                // documentation
        [255, ..] => false,
        _ => true,
    }
}

fn permitted_domain(host: &str) -> bool {
    let clean = host.trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() || clean.len() > 253 || !clean.is_ascii() { return false; }
    if !clean.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && !label.starts_with('-') && !label.ends_with('-')
    }) { return false; }
    let match_suffix = |suffix: &str| {
        let s = suffix.trim().trim_start_matches("*.").trim_start_matches('.').to_ascii_lowercase();
        !s.is_empty() && (clean == s || clean.ends_with(&format!(".{}", s)))
    };
    DEFAULT_DOMAINS.iter().any(|x| match_suffix(x))
        || std::env::var("AG_TUNNEL_EXTRA_HOSTS").ok().map_or(false, |v| {
            v.split(',').any(match_suffix)
        })
}

fn permitted_host(host: &str, port: u16) -> bool {
    if port != 443 { return false; }
    let public_only = std::env::var("AG_TUNNEL_MODE")
        .map(|v| v == "public_443").unwrap_or(false);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return public_only && matches!(ip, IpAddr::V4(v4) if is_public_v4(v4));
    }
    public_only || permitted_domain(host)
}

async fn checked_endpoint(host: &str, port: u16) -> Result<SocketAddr, String> {
    if !permitted_host(host, port) {
        return Err(format!("Host/port denied by policy: {}:{}", host, port));
    }
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await
        .map_err(|e| format!("DNS: {}", e))?.collect();
    if addresses.is_empty() { return Err("DNS produced no endpoints".to_string()); }
    // Reject any private IPv4. Ignore AAAA records because this client uses only
    // pinned, checked IPv4 destinations; many normal Google domains have AAAA.
    if addresses.iter().any(|a| matches!(a.ip(), IpAddr::V4(ip) if !is_public_v4(ip))) {
        return Err(format!("DNS contains private or reserved IPv4: {}", host));
    }
    addresses.into_iter()
        .find(|a| matches!(a.ip(), IpAddr::V4(ip) if is_public_v4(ip)))
        .ok_or_else(|| format!("No permitted public IPv4 endpoint for {}", host))
}

pub async fn start_tunnel_worker(server_url: String, token: String) {
    // The tunnel gateway is trusted with traffic. Reject insecure transports.
    if !server_url.starts_with("https://") {
        eprintln!("[Tunnel] Refusing non-HTTPS gateway: {}", server_url);
        return;
    }
    eprintln!("[Tunnel] Starting bounded remote CONNECT tunnel workers");
    for _ in 0..12 {
        let url = server_url.clone();
        let tok = token.clone();
        tokio::spawn(async move { tunnel_loop(url, tok).await; });
    }
}

async fn tunnel_loop(server_url: String, token: String) {
    let ws_url = format!("{}/v1/tunnel?token={}",
        server_url.trim_end_matches('/').replacen("https://", "wss://", 1), token);
    loop {
        let mut request = match tokio_tungstenite::tungstenite::client::IntoClientRequest::into_client_request(ws_url.clone()) {
            Ok(r) => r,
            Err(e) => { eprintln!("[Tunnel] Invalid URL: {}", e); return; }
        };
        if let Ok(header) = format!("Bearer {}", token).parse() {
            request.headers_mut().insert("Authorization", header);
        }
        request.headers_mut().insert("User-Agent", "Antigravity-Client/1.0".parse().unwrap());
        match connect_async(request).await {
            Ok((ws_stream, _)) => {
                let (mut write, mut read) = ws_stream.split();
                let mut command_received: Option<String> = None;
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
                interval.tick().await;
                loop {
                    tokio::select! {
                        msg = read.next() => match msg {
                            Some(Ok(Message::Text(cmd))) if cmd.starts_with("CONNECT ") => {
                                command_received = Some(cmd.to_string()); break;
                            },
                            Some(Ok(Message::Ping(_))) => {
                                if write.send(Message::Pong(vec![].into())).await.is_err() { break; }
                            },
                            Some(Ok(Message::Close(_))) | Some(Err(_)) | None => break,
                            _ => {},
                        },
                        _ = interval.tick() => {
                            if write.send(Message::Ping(vec![].into())).await.is_err() { break; }
                        }
                    }
                }
                if let Some(cmd) = command_received {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() != 3 || parts[0] != "CONNECT" || cmd.len() > 1024 {
                        let _ = write.send(Message::Text("ERROR Bad CONNECT syntax".to_string().into())).await;
                        continue;
                    }
                    let host = parts[1];
                    let port: u16 = match parts[2].parse() {
                        Ok(v) => v,
                        Err(_) => {
                            let _ = write.send(Message::Text("ERROR Invalid port".to_string().into())).await;
                            continue;
                        }
                    };
                    let endpoint = match checked_endpoint(host, port).await {
                        Ok(v) => v,
                        Err(e) => {
                            eprintln!("[Tunnel] Blocked remote CONNECT: {}", e);
                            let _ = write.send(Message::Text("ERROR Destination blocked by local policy".to_string().into())).await;
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                    };
                    match tokio::net::TcpStream::connect(endpoint).await {
                        Ok(target_stream) => {
                            let _ = write.send(Message::Text("CONNECTED".to_string().into())).await;
                            let (mut target_read, mut target_write) = target_stream.into_split();
                            let mut ws_to_tcp = tokio::spawn(async move {
                                while let Some(Ok(Message::Binary(data))) = read.next().await {
                                    if target_write.write_all(&data).await.is_err() { break; }
                                }
                            });
                            let mut tcp_to_ws = tokio::spawn(async move {
                                let mut buf = vec![0u8; 8192];
                                loop {
                                    match target_read.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => {
                                            if write.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() { break; }
                                        }
                                    }
                                }
                            });
                            tokio::select! {
                                _ = &mut ws_to_tcp => { tcp_to_ws.abort(); },
                                _ = &mut tcp_to_ws => { ws_to_tcp.abort(); },
                            }
                        },
                        Err(e) => {
                            eprintln!("[Tunnel] TCP connect failure: {}", e);
                            let _ = write.send(Message::Text("ERROR Upstream TCP connection failed".to_string().into())).await;
                        }
                    }
                    continue;
                }
            },
            Err(e) => eprintln!("[Tunnel] Gateway connection error: {}", e),
        }
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
'''


def read(rel):
    return (ROOT / rel).read_text(encoding='utf-8')

def replace_once(text, old, new, name):
    if text.count(old) != 1:
        raise ValueError(f'{name}: expected one occurrence, found {text.count(old)}')
    return text.replace(old, new, 1)

def replace_braced_function(text, needle, replacement, label):
    start = text.find(needle)
    if start < 0: raise ValueError(f'{label}: function signature not found')
    brace = text.find('{', start)
    if brace < 0: raise ValueError(f'{label}: opening brace absent')
    depth = 0
    end = -1
    for i in range(brace, len(text)):
        if text[i] == '{': depth += 1
        elif text[i] == '}':
            depth -= 1
            if depth == 0: end = i + 1; break
    if end < 0: raise ValueError(f'{label}: unbalanced braces')
    return text[:start] + replacement + text[end:]


def main():
    missing = [p for p in EXPECTED if not (ROOT/p).is_file()]
    if missing:
        sys.exit('Run from repository root. Missing: ' + ', '.join(missing))
    if '1.0.46' not in read('src-tauri/Cargo.toml'):
        sys.exit('This overlay targets v1.0.46; refusing to patch another version.')

    changed = {}
    changed['src-tauri/src/tunnel.rs'] = TUNNEL

    proxy = read('src-tauri/src/local_proxy.rs')
    proxy_old = '''    let cors_origin = req.headers().get("origin").map(|v| v.to_str().unwrap_or("*")).unwrap_or("*").to_string();'''
    proxy_new = '''    // Browser-originated requests must not turn the local privileged gateway into
    // a cross-origin request proxy. Tauri GUI itself uses Rust IPC (not this port).
    let fetch_site = req.headers().get("sec-fetch-site")
        .and_then(|v| v.to_str().ok());
    if matches!(fetch_site, Some("cross-site")) {
        return Ok(hyper::Response::builder().status(403)
            .body(full_box(bytes::Bytes::from("Cross-site requests forbidden"))).unwrap());
    }
    let origin = req.headers().get("origin").and_then(|v| v.to_str().ok());
    if let Some(v) = origin {
        if !matches!(v, "tauri://localhost" | "http://tauri.localhost"
            | "http://localhost:1421" | "http://127.0.0.1:1421") {
            eprintln!("[LocalProxy] Rejected foreign Origin: {}", v);
            return Ok(hyper::Response::builder().status(403)
                .body(full_box(bytes::Bytes::from("Forbidden Origin"))).unwrap());
        }
    }
    let cors_origin = origin.unwrap_or("http://localhost:1421").to_string();'''
    proxy = replace_once(proxy, proxy_old, proxy_new, 'local_proxy CORS')
    changed['src-tauri/src/local_proxy.rs'] = proxy

    db = read('src-tauri/src/db.rs')
    beg = db.find('pub fn inject_real_token(')
    store_start = db.find('    let conn = init_db()?;', beg)
    store_end = db.find('    // Store in OS Keyring / Credential Manager', store_start)
    if min(beg, store_start, store_end) < 0 or not (beg < store_start < store_end):
        raise ValueError('DB credential storage block not found')
    db = db[:store_start] + '''    // Do not persist bearer/refresh tokens in unencrypted SQLite.
    // Erase previous versions' stored rows, vacuum orphaned DB pages.
    let conn = init_db()?;
    conn.execute("DELETE FROM sessions", [])
        .map_err(|e| format!("Failed to purge old credentials: {}", e))?;
    conn.execute_batch("VACUUM;")
        .map_err(|e| format!("Failed to compact credentials database: {}", e))?;

''' + db[store_end:]
    db = replace_once(db,
        'obj.insert("http.proxyStrictSSL".to_string(), serde_json::json!(false));',
        'obj.insert("http.proxyStrictSSL".to_string(), serde_json::json!(true));',
        'strict SSL')
    changed['src-tauri/src/db.rs'] = db

    lib = read('src-tauri/src/lib.rs')
    # Reject unencrypted gateway URLs before enabling a privileged proxy.
    lib = replace_once(lib,
        '    let base_url = proxy_url.trim_end_matches("/v1").to_string();',
        '''    let base_url = proxy_url.trim_end_matches("/v1").to_string();
    if !base_url.starts_with("https://") {
        return Err("Insecure HTTP gateways are disabled in this build".to_string());
    }''',
        'HTTPS gateway')
    lib = replace_braced_function(lib,
        'async fn install_client_update(',
        '''async fn install_client_update(_app_handle: tauri::AppHandle, _download_url: String) -> Result<(), String> {
    Err("Unverified in-app binary updates are disabled in the hardened build. Rebuild from verified source.".to_string())
}''', 'remote update')
    lib = replace_once(lib,
        '    let client = reqwest::Client::new();',
        '''    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build().map_err(|e| e.to_string())?;''',
        'request_server HTTPS proxy')
    lib = replace_once(lib,
        '    let mut req = match method.to_uppercase().as_str() {',
        '''    if !url.starts_with("https://") {
        return Err("Only HTTPS gateway requests are allowed".to_string());
    }
    let mut req = match method.to_uppercase().as_str() {''',
        'secure UI request')
    lib = replace_braced_function(lib, 'fn save_token(',
        '''fn save_token(_token: String) -> Result<(), String> {
    // Keep bearer token in process memory only, not as plaintext on disk.
    Ok(())
}''', 'save_token')
    lib = replace_braced_function(lib, 'fn get_saved_token(',
        '''fn get_saved_token() -> Result<String, String> {
    // Purge legacy plaintext credentials from earlier client versions.
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".antigravity-client").join("saved_token.txt");
        if p.exists() { std::fs::remove_file(p).map_err(|e| e.to_string())?; }
    }
    Ok(String::new())
}''', 'get_saved_token')
    lib = replace_braced_function(lib, 'fn clear_saved_token(',
        '''fn clear_saved_token() -> Result<(), String> {
    if let Some(home) = dirs::home_dir() {
        let p = home.join(".antigravity-client").join("saved_token.txt");
        if p.exists() { std::fs::remove_file(p).map_err(|e| e.to_string())?; }
    }
    Ok(())
}''', 'clear_saved_token')
    changed['src-tauri/src/lib.rs'] = lib

    app = read('src/App.tsx')
    first = app.index('    let savedToken = localStorage.getItem(LS_TOKEN_KEY);')
    second = app.index('    const savedServer = localStorage.getItem(LS_SERVER_KEY)', first)
    app = app[:first] + '''    // Never persist bearer tokens in WebView localStorage.
    localStorage.removeItem(LS_TOKEN_KEY);
    invoke('clear_saved_token').catch(() => {});
''' + app[second:]
    app = replace_once(app,
        '    // Token loading handled via disk/localStorage above',
        '    checkServerHealth(url); // token must be entered afresh on each launch',
        'startup health')
    app = replace_once(app,
        '''        const cleanToken = tokenToUse.trim();
        localStorage.setItem(LS_TOKEN_KEY, cleanToken);
        invoke('save_token', { token: cleanToken }).catch(() => {});''',
        '''        // Token exists in React state only for this session.''',
        'browser token save')
    app = replace_braced_function(app,
        'const handleInstallUpdate = async () =>',
        '''const handleInstallUpdate = async () => {
    setUpdating(true);
    setUpdateError('The hardened build disables server-supplied installers. Update the source, reapply the security patch, then rebuild.');
    setUpdating(false);
  }''', 'frontend updater')
    changed['src/App.tsx'] = app

    # A single successful validation pass precedes all writes.
    for rel, content in changed.items():
        if not content or len(content) < 200: raise ValueError(f'Refusing suspicious output: {rel}')
    for rel, content in changed.items():
        path = ROOT / rel
        backup = path.with_suffix(path.suffix + '.pre-hardening')
        if backup.exists(): raise FileExistsError(f'Refusing to overwrite previous backup: {backup}')
        backup.write_bytes(path.read_bytes())
        path.write_text(content, encoding='utf-8')
        print('patched:', rel)
    print('Completed: review changes with git diff, then build in a controlled environment.')

if __name__ == '__main__':
    main()
