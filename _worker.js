import { connect } from "cloudflare:sockets";

// ============================================
// CONFIGURATION & ENVIRONMENT
// ============================================
const DEFAULT_PROXY_IP = "cdn-b100.xn--b6gac.eu.org";
const DEFAULT_PROXY_IP_POOL = [
    "cdn-b100.xn--b6gac.eu.org",
    "cdn.xn--b6gac.eu.org",
    "cdn-all.xn--b6gac.eu.org",
    "workers.cloudflare.com",
    "icook.hk",
    "icook.tw",
    "www.visa.com.sg"
];
const DEFAULT_WS_PATH = "vless-ws";
const DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query";

// Rate Limiting
const RATE_LIMIT_WINDOW_MS = 60000;
const RATE_LIMIT_MAX_REQUESTS = 100;

// Timeouts
const CONNECT_TIMEOUT_MS = 30000;
const IDLE_TIMEOUT_MS = 300000;

// VLESS Protocol Constants
const VLESS_PROTOCOL_VERSION = 0;
const VLESS_UUID_LENGTH = 16;
const VLESS_COMMAND_TCP = 1;
const VLESS_COMMAND_UDP = 2;
const VLESS_COMMAND_MUX = 3;

// Address Types
const ADDRESS_TYPE_IPV4 = 1;
const ADDRESS_TYPE_DOMAIN = 2;
const ADDRESS_TYPE_IPV6 = 3;

// HTTP Status Codes
const HTTP_STATUS = {
    OK: 200,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    METHOD_NOT_ALLOWED: 405,
    UPGRADE_REQUIRED: 426,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_ERROR: 500,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503
};

// ============================================
// LOGGING SYSTEM
// ============================================
const LOG_COLORS = {
    debug: "\x1B[36m",
    info: "\x1B[32m",
    warn: "\x1B[33m",
    error: "\x1B[31m",
    reset: "\x1B[0m"
};

const LOG_LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };
let LOG_LEVEL = "info";

function log(level, message, data = null) {
    const currentLevel = LOG_LEVELS[LOG_LEVEL] || 1;
    const msgLevel = LOG_LEVELS[level] || 1;
    if (msgLevel < currentLevel) return;

    const timestamp = new Date().toISOString();
    const color = LOG_COLORS[level] || "";
    const reset = LOG_COLORS.reset;

    console.log(`${color}[${timestamp}] [${level.toUpperCase()}] ${message}${reset}`);
    if (data && level === "debug") {
        console.log(JSON.stringify(data, null, 2));
    }
}

// ============================================
// UUID UTILITIES
// ============================================
function uuidToBytes(uuid) {
    const hex = uuid.replace(/-/g, "");
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return bytes;
}

function bytesToUUID(bytes) {
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

function isValidUUID(uuid) {
    if (!uuid) return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid.trim());
}

async function timingSafeUUIDCompare(providedUUID, expectedUUID) {
    if (!providedUUID || !expectedUUID) return false;
    const providedBytes = uuidToBytes(providedUUID);
    const expectedBytes = uuidToBytes(expectedUUID);
    if (providedBytes.length !== expectedBytes.length) return false;

    try {
        let result = 0;
        for (let i = 0; i < providedBytes.length; i++) {
            result |= providedBytes[i] ^ expectedBytes[i];
        }
        return result === 0;
    } catch (error) {
        return false;
    }
}

// ============================================
// RATE LIMITER
// ============================================
class RateLimiter {
    constructor() {
        this.requests = new Map();
    }

    isAllowed(clientIP) {
        const now = Date.now();
        const windowStart = now - RATE_LIMIT_WINDOW_MS;

        // Clean old entries
        for (const [ip, timestamps] of this.requests) {
            const filtered = timestamps.filter((t) => t > windowStart);
            if (filtered.length === 0) {
                this.requests.delete(ip);
            } else {
                this.requests.set(ip, filtered);
            }
        }

        const clientRequests = this.requests.get(clientIP) || [];
        const recentRequests = clientRequests.filter((t) => t > windowStart);

        if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
            return false;
        }

        recentRequests.push(now);
        this.requests.set(clientIP, recentRequests);
        return true;
    }
}

const rateLimiter = new RateLimiter();

// ============================================
// AD & TRACKER BLOCKING
// ============================================
const AD_DOMAIN_SUFFIXES = [
    "doubleclick.net", "googleadservices.com", "googlesyndication.com",
    "adservice.google.com", "pagead2.googlesyndication.com", "adcolony.com",
    "appsflyer.com", "unityads.unity3d.com", "vungle.com", "applovin.com",
    "flurry.com", "adjust.com", "branch.io", "admob.com", "mopub.com",
    "criteo.com", "taboola.com", "outbrain.com", "scorecardresearch.com",
    "quantserve.com", "popads.net", "inmobi.com", "adroll.com",
    "amazon-adsystem.com", "adsafeprotected.com", "moatads.com",
    "openx.net", "rubiconproject.com", "pubmatic.com"
];

function isAdDomain(domain) {
    if (!domain) return false;
    const lower = domain.toLowerCase().trim();
    if (AD_DOMAIN_SUFFIXES.some(suffix => lower === suffix || lower.endsWith("." + suffix))) {
        return true;
    }
    if (/^(ad|ads|adservice|adserver|telemetry|track|tracker|analytics)\./i.test(lower)) {
        return true;
    }
    return false;
}

// ============================================
// PRIVATE/LOCAL ADDRESS CHECK
// ============================================
const DIRECT_BYPASS_DOMAINS = ["localhost", "local", "internal", "lan", "home.arpa"];

function isPrivateOrLocalAddress(address) {
    if (!address) return false;
    const lower = address.toLowerCase().trim();

    if (DIRECT_BYPASS_DOMAINS.some(d => lower === d || lower.endsWith("." + d))) {
        return true;
    }
    if (/^127\./.test(lower)) return true;
    if (/^10\./.test(lower)) return true;
    if (/^192\.168\./.test(lower)) return true;
    const match172 = lower.match(/^172\.(\d{1,3})\./);
    if (match172) {
        const secondOctet = parseInt(match172[1], 10);
        if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
    if (/^169\.254\./.test(lower)) return true;
    if (lower === "::1" || lower.startsWith("fc00:") || lower.startsWith("fe80:") || lower.startsWith("fd")) {
        return true;
    }
    return false;
}

// ============================================
// VLESS HEADER PARSER
// ============================================
class VLESSHeaderParser {
    constructor(buffer) {
        this.buffer = new Uint8Array(buffer);
        this.offset = 0;
        this.error = null;
    }

    readExactly(n) {
        if (this.offset + n > this.buffer.length) {
            this.error = `Insufficient data: need ${n}, have ${this.buffer.length - this.offset}`;
            return null;
        }
        const result = this.buffer.slice(this.offset, this.offset + n);
        this.offset += n;
        return result;
    }

    parse() {
        try {
            const versionBytes = this.readExactly(1);
            if (!versionBytes) return null;
            const version = versionBytes[0];
            if (version !== VLESS_PROTOCOL_VERSION) {
                this.error = `Unsupported VLESS version: ${version}`;
                log("warn", `Unsupported VLESS version: ${version}`);
                return null;
            }

            const uuidBytes = this.readExactly(VLESS_UUID_LENGTH);
            if (!uuidBytes) return null;
            const uuid = bytesToUUID(uuidBytes);

            const commandBytes = this.readExactly(1);
            if (!commandBytes) return null;
            const command = commandBytes[0];
            if (![VLESS_COMMAND_TCP, VLESS_COMMAND_UDP, VLESS_COMMAND_MUX].includes(command)) {
                this.error = `Invalid command: ${command}`;
                log("warn", `Invalid VLESS command: ${command}`);
                return null;
            }

            const addrTypeBytes = this.readExactly(1);
            if (!addrTypeBytes) return null;
            const addressType = addrTypeBytes[0];

            let address = "";
            switch (addressType) {
                case ADDRESS_TYPE_IPV4:
                    const ipv4Bytes = this.readExactly(4);
                    if (!ipv4Bytes) return null;
                    address = `${ipv4Bytes[0]}.${ipv4Bytes[1]}.${ipv4Bytes[2]}.${ipv4Bytes[3]}`;
                    break;
                case ADDRESS_TYPE_DOMAIN:
                    const domainLenBytes = this.readExactly(1);
                    if (!domainLenBytes) return null;
                    const domainLen = domainLenBytes[0];
                    const domainBytes = this.readExactly(domainLen);
                    if (!domainBytes) return null;
                    address = new TextDecoder().decode(domainBytes);
                    break;
                case ADDRESS_TYPE_IPV6:
                    const ipv6Bytes = this.readExactly(16);
                    if (!ipv6Bytes) return null;
                    const parts = [];
                    for (let i = 0; i < 8; i++) {
                        const part = (ipv6Bytes[i * 2] << 8) | ipv6Bytes[i * 2 + 1];
                        parts.push(part.toString(16));
                    }
                    address = parts.join(":");
                    break;
                default:
                    this.error = `Unknown address type: ${addressType}`;
                    log("warn", `Unknown address type: ${addressType}`);
                    return null;
            }

            const portBytes = this.readExactly(2);
            if (!portBytes) return null;
            const port = (portBytes[0] << 8) | portBytes[1];
            const remaining = this.buffer.slice(this.offset);

            log("debug", "VLESS header parsed", {
                version, uuid, command, addressType, address, port,
                remainingLength: remaining.length
            });

            return { version, uuid, command, addressType, address, port, remaining };
        } catch (error) {
            this.error = `Parse error: ${error.message}`;
            log("error", "VLESS header parse error", { error: error.message });
            return null;
        }
    }
}

// ============================================
// PROXY IP POOL MANAGEMENT
// ============================================
let activeProxyPool = [...DEFAULT_PROXY_IP_POOL];

async function getHybridProxyIP(defaultProxy, rawUrl) {
    if (!rawUrl) {
        return activeProxyPool[Math.floor(Math.random() * activeProxyPool.length)] || defaultProxy;
    }
    try {
        const response = await fetch(rawUrl, {
            cf: { cacheTtl: 300, cacheEverything: true }
        });
        if (response.ok) {
            const text = await response.text();
            const fetchedIPs = text.split("\n")
                .map(line => line.trim())
                .filter(line => line.length > 0 && !line.startsWith("#"));

            if (fetchedIPs.length > 0) {
                activeProxyPool = Array.from(new Set([...fetchedIPs, ...DEFAULT_PROXY_IP_POOL]));
                if (defaultProxy && !activeProxyPool.includes(defaultProxy)) {
                    activeProxyPool.unshift(defaultProxy);
                }
            }
        }
    } catch (err) {
        log("warn", "GitHub ProxyIP Fetch Error, falling back to local pool", { error: err.message });
    }
    return activeProxyPool[Math.floor(Math.random() * activeProxyPool.length)] || defaultProxy;
}

// ============================================
// TCP CONNECTION WITH PROXY FALLBACK
// ============================================
async function createTCPConnection(address, port, proxyIP, proxyListURL, timeoutMs = CONNECT_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    try {
        log("debug", `Creating TCP connection to ${address}:${port}`);

        // Try direct connection first
        try {
            const conn = await connect({ hostname: address, port });
            log("info", `Connected directly to ${address}:${port}`);
            clearTimeout(timeoutId);
            return conn;
        } catch (directError) {
            log("debug", `Direct connection failed, trying proxies`, { error: directError.message });
        }

        // Fallback to proxy IPs
        const proxyIPs = [proxyIP, ...DEFAULT_PROXY_IP_POOL.filter(ip => ip !== proxyIP)];
        for (const proxy of proxyIPs) {
            try {
                const conn = await connect({ hostname: proxy, port });
                log("info", `Connected via proxy: ${proxy}:${port}`);
                clearTimeout(timeoutId);
                return conn;
            } catch (proxyError) {
                log("debug", `Proxy ${proxy} failed`, { error: proxyError.message });
                continue;
            }
        }

        throw new Error(`Failed to connect to ${address}:${port} via all routes`);
    } catch (error) {
        clearTimeout(timeoutId);
        log("error", `Connection failed to ${address}:${port}`, { error: error.message });
        throw error;
    }
}

// ============================================
// TCP PROXY HANDLER
// ============================================
async function handleTCPProxy(webSocket, vlessHeader, proxyIP, proxyListURL) {
    let remoteConnection = null;
    let isClosed = false;

    const cleanup = () => {
        if (isClosed) return;
        isClosed = true;
        try { webSocket.close(); } catch (e) {}
        if (remoteConnection) {
            try { remoteConnection.close(); } catch (e) {}
        }
        log("debug", "TCP proxy connection cleaned up");
    };

    try {
        // Block ads
        if (isAdDomain(vlessHeader.address)) {
            log("warn", `[AdBlock] Blocked connection to ad domain: ${vlessHeader.address}`);
            cleanup();
            return;
        }

        remoteConnection = await createTCPConnection(
            vlessHeader.address, 
            vlessHeader.port, 
            proxyIP, 
            proxyListURL
        );

        // Send VLESS response header
        const responseHeader = new Uint8Array([VLESS_PROTOCOL_VERSION, 0, 0]);
        webSocket.send(responseHeader);

        // Send remaining data from initial request
        if (vlessHeader.remaining && vlessHeader.remaining.length > 0) {
            await remoteConnection.write(vlessHeader.remaining);
        }

        log("info", `TCP proxy established: ${vlessHeader.address}:${vlessHeader.port}`);

        // Pipe WebSocket -> Remote
        const pipeWebSocketToRemote = async () => {
            try {
                while (!isClosed) {
                    const message = await new Promise((resolve, reject) => {
                        const timeout = setTimeout(() => reject(new Error("WebSocket read timeout")), IDLE_TIMEOUT_MS);
                        webSocket.addEventListener("message", (event) => {
                            clearTimeout(timeout);
                            resolve(event.data);
                        }, { once: true });
                        webSocket.addEventListener("close", () => {
                            clearTimeout(timeout);
                            reject(new Error("WebSocket closed"));
                        }, { once: true });
                        webSocket.addEventListener("error", (error) => {
                            clearTimeout(timeout);
                            reject(error);
                        }, { once: true });
                    });

                    if (message instanceof ArrayBuffer) {
                        await remoteConnection.write(new Uint8Array(message));
                    } else if (typeof message === "string") {
                        await remoteConnection.write(new TextEncoder().encode(message));
                    }
                }
            } catch (error) {
                if (!isClosed) {
                    log("debug", "WebSocket to remote pipe ended", { error: error.message });
                }
            }
        };

        // Pipe Remote -> WebSocket
        const pipeRemoteToWebSocket = async () => {
            try {
                const reader = remoteConnection.readable.getReader();
                while (!isClosed) {
                    const { done, value } = await reader.read();
                    if (done) {
                        log("debug", "Remote connection closed by peer");
                        break;
                    }
                    if (value) {
                        webSocket.send(value);
                    }
                }
            } catch (error) {
                if (!isClosed) {
                    log("debug", "Remote to WebSocket pipe ended", { error: error.message });
                }
            }
        };

        await Promise.race([pipeWebSocketToRemote(), pipeRemoteToWebSocket()]);
    } catch (error) {
        log("error", "TCP proxy error", {
            error: error.message,
            address: vlessHeader.address,
            port: vlessHeader.port
        });
    } finally {
        cleanup();
    }
}

// ============================================
// UDP PROXY HANDLER (DNS-over-HTTPS via DoH)
// ============================================
async function handleUDPProxy(webSocket, vlessHeader, dohURL) {
    log("info", `UDP proxy (DNS) requested: ${vlessHeader.address}:${vlessHeader.port}`);

    let isClosed = false;
    let isHeaderSent = false;

    const cleanup = () => {
        if (isClosed) return;
        isClosed = true;
        try { webSocket.close(); } catch (e) {}
    };

    try {
        // Only allow DNS (port 53)
        if (vlessHeader.port !== 53) {
            log("warn", `UDP proxy rejected: port ${vlessHeader.port} not allowed (only 53)`);
            const errorResponse = new Uint8Array([VLESS_PROTOCOL_VERSION, 1, 0]);
            webSocket.send(errorResponse);
            cleanup();
            return;
        }

        // Send VLESS response header
        const responseHeader = new Uint8Array([VLESS_PROTOCOL_VERSION, 0, 0]);
        webSocket.send(responseHeader);
        isHeaderSent = true;

        // Transform stream for DNS packets
        const transformStream = new TransformStream({
            transform(chunk, controller) {
                for (let index = 0; index < chunk.byteLength;) {
                    const lengthBuffer = chunk.slice(index, index + 2);
                    const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                    const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                    index = index + 2 + udpPacketLength;
                    controller.enqueue(udpData);
                }
            }
        });

        // Process DNS queries via DoH
        transformStream.readable.pipeTo(new WritableStream({
            async write(chunk) {
                const resp = await fetch(dohURL, {
                    method: "POST",
                    headers: { "content-type": "application/dns-message" },
                    body: chunk
                });
                const dnsQueryResult = await resp.arrayBuffer();
                const udpSize = dnsQueryResult.byteLength;
                const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);

                log("debug", `DoH success, DNS message length: ${udpSize}`);

                const fullPacket = new Uint8Array([...udpSizeBuffer, ...new Uint8Array(dnsQueryResult)]);

                if (webSocket.readyState === 1) {
                    webSocket.send(fullPacket.buffer);
                }
            }
        })).catch((error) => {
            log("error", "DNS UDP error", { error: error.message });
        });

        const writer = transformStream.writable.getWriter();

        // Handle incoming WebSocket messages as DNS queries
        webSocket.addEventListener("message", async (event) => {
            if (isClosed) return;
            const data = event.data;
            if (data instanceof ArrayBuffer) {
                await writer.write(new Uint8Array(data));
            }
        });

        webSocket.addEventListener("close", cleanup);
        webSocket.addEventListener("error", cleanup);

    } catch (error) {
        log("error", "UDP proxy error", { error: error.message });
        cleanup();
    }
}

// ============================================
// WEBSOCKET HANDLER
// ============================================
async function handleWebSocket(request, env, config) {
    const upgradeHeader = request.headers.get("Upgrade");
    if (upgradeHeader !== "websocket") {
        return new Response("Expected WebSocket", {
            status: HTTP_STATUS.UPGRADE_REQUIRED,
            headers: { "Upgrade": "websocket" }
        });
    }

    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    server.accept();

    let isAuthenticated = false;
    let vlessHeader = null;

    server.addEventListener("message", async (event) => {
        try {
            if (!isAuthenticated) {
                const data = event.data;
                if (!(data instanceof ArrayBuffer)) {
                    log("warn", "First message must be binary (VLESS header)");
                    server.close(1002, "Invalid VLESS header");
                    return;
                }

                const parser = new VLESSHeaderParser(data);
                vlessHeader = parser.parse();
                if (!vlessHeader) {
                    log("warn", "Failed to parse VLESS header", { error: parser.error });
                    server.close(1002, "Invalid VLESS header");
                    return;
                }

                // Validate UUID against all allowed UUIDs
                const allowedUUIDs = config.allowedUUIDs;
                let isValid = false;
                for (const allowedUUID of allowedUUIDs) {
                    if (await timingSafeUUIDCompare(vlessHeader.uuid, allowedUUID)) {
                        isValid = true;
                        break;
                    }
                }

                if (!isValid) {
                    log("warn", "Invalid UUID attempted", {
                        provided: vlessHeader.uuid,
                        allowed: allowedUUIDs.length
                    });
                    server.close(1008, "Authentication failed");
                    return;
                }

                isAuthenticated = true;
                log("info", "VLESS authentication successful", {
                    uuid: vlessHeader.uuid,
                    command: vlessHeader.command,
                    address: vlessHeader.address,
                    port: vlessHeader.port
                });

                switch (vlessHeader.command) {
                    case VLESS_COMMAND_TCP:
                        await handleTCPProxy(server, vlessHeader, config.proxyIP, config.proxyListURL);
                        break;
                    case VLESS_COMMAND_UDP:
                        await handleUDPProxy(server, vlessHeader, config.dohURL);
                        break;
                    case VLESS_COMMAND_MUX:
                        log("info", "MUX command received - handling as TCP");
                        await handleTCPProxy(server, vlessHeader, config.proxyIP, config.proxyListURL);
                        break;
                    default:
                        server.close(1002, "Unsupported command");
                }
            }
        } catch (error) {
            log("error", "WebSocket message handler error", { error: error.message });
            try { server.close(1011, "Internal error"); } catch (e) {}
        }
    });

    server.addEventListener("close", (event) => {
        log("debug", "WebSocket closed", { code: event.code, reason: event.reason });
    });

    server.addEventListener("error", (error) => {
        log("error", "WebSocket error", { error: error.message });
    });

    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

// ============================================
// CONFIG GENERATORS
// ============================================
function generateVLESSLink(host, uuid, wsPath) {
    const cleanPath = wsPath.replace(/^\/+/, "");
    const params = new URLSearchParams({
        encryption: "none",
        security: "tls",
        sni: host,
        type: "ws",
        host,
        path: `/${cleanPath}?ed=2048`
    });
    return `vless://${uuid}@${host}:443?${params.toString()}#VLESS-${host}`;
}

function generateClashConfig(host, uuid, wsPath) {
    const cleanPath = wsPath.replace(/^\/+/, "");
    return {
        proxies: [{
            name: "VLESS-Worker",
            type: "vless",
            server: host,
            port: 443,
            uuid,
            cipher: "auto",
            tls: true,
            "skip-cert-verify": false,
            servername: host,
            network: "ws",
            "ws-opts": {
                path: `/${cleanPath}?ed=2048`,
                headers: { Host: host }
            }
        }]
    };
}

function generateXrayConfig(host, uuid, wsPath) {
    const cleanPath = wsPath.replace(/^\/+/, "");
    return {
        log: { loglevel: "warning" },
        inbounds: [{
            port: 10808,
            protocol: "socks",
            settings: { auth: "noauth", udp: true }
        }],
        outbounds: [{
            protocol: "vless",
            settings: {
                vnext: [{
                    address: host,
                    port: 443,
                    users: [{ id: uuid, encryption: "none", level: 0 }]
                }]
            },
            streamSettings: {
                network: "ws",
                security: "tls",
                tlsSettings: { serverName: host, allowInsecure: false },
                wsSettings: {
                    path: `/${cleanPath}?ed=2048`,
                    headers: { Host: host }
                }
            }
        }]
    };
}

// ============================================
// SUBSCRIPTION PAGE (HTML DASHBOARD)
// ============================================
function getDashboardHTML(host, uuid, wsPath, proxyIP, proxyPool) {
    const vlessLink = generateVLESSLink(host, uuid, wsPath);
    const cleanPath = wsPath.replace(/^\/+/, "");

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VLESS Worker Proxy | Dashboard</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #334155 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
      color: #e2e8f0;
    }
    .container {
      background: rgba(15, 23, 42, 0.95);
      backdrop-filter: blur(20px);
      border-radius: 24px;
      padding: 40px;
      max-width: 720px;
      width: 100%;
      box-shadow: 0 25px 80px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.08);
    }
    h1 {
      text-align: center;
      margin-bottom: 8px;
      font-size: 32px;
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
    }
    .subtitle {
      text-align: center;
      color: #94a3b8;
      font-size: 14px;
      margin-bottom: 30px;
    }
    .status {
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 10px;
      margin-bottom: 30px;
      padding: 12px 24px;
      background: rgba(34, 197, 94, 0.1);
      border: 1px solid rgba(34, 197, 94, 0.2);
      border-radius: 12px;
      width: fit-content;
      margin-left: auto;
      margin-right: auto;
    }
    .status-dot {
      width: 10px; height: 10px;
      background: #22c55e;
      border-radius: 50%;
      box-shadow: 0 0 12px #22c55e;
      animation: pulse 2s infinite;
    }
    @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
    .status-text { color: #4ade80; font-weight: 700; font-size: 14px; }
    .section { margin-bottom: 24px; }
    .section-title {
      font-size: 12px; text-transform: uppercase; letter-spacing: 1.5px;
      color: #64748b; margin-bottom: 12px; font-weight: 700;
    }
    .info-grid {
      display: grid; grid-template-columns: 130px 1fr; gap: 10px; font-size: 14px;
    }
    .info-label { color: #94a3b8; font-weight: 500; }
    .info-value {
      color: #e2e8f0; font-family: 'SF Mono', 'Courier New', monospace;
      background: rgba(30, 41, 59, 0.8); padding: 6px 10px;
      border-radius: 8px; word-break: break-all; border: 1px solid rgba(255,255,255,0.05);
    }
    .link-box {
      background: #0f172a; color: #4ade80; padding: 16px;
      border-radius: 12px; font-family: 'SF Mono', monospace; font-size: 12px;
      word-break: break-all; margin-top: 10px; position: relative;
      border: 1px solid rgba(74, 222, 128, 0.15);
    }
    .copy-btn {
      position: absolute; top: 12px; right: 12px;
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      color: white; border: none; padding: 6px 16px;
      border-radius: 8px; cursor: pointer; font-size: 12px; font-weight: 700;
      transition: all 0.2s;
    }
    .copy-btn:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59,130,246,0.4); }
    .tabs {
      display: flex; gap: 6px; margin-bottom: 16px;
    }
    .tab {
      padding: 8px 18px; border: none;
      background: rgba(30, 41, 59, 0.8); color: #94a3b8;
      border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 600;
      transition: all 0.2s; border: 1px solid rgba(255,255,255,0.05);
    }
    .tab.active {
      background: linear-gradient(135deg, #3b82f6, #6366f1);
      color: white;
    }
    .tab:hover:not(.active) { background: rgba(51, 65, 85, 0.8); color: #e2e8f0; }
    .config-content { display: none; }
    .config-content.active { display: block; }
    pre {
      background: #0f172a; color: #a5b4fc; padding: 16px;
      border-radius: 12px; overflow-x: auto; font-size: 12px; line-height: 1.6;
      border: 1px solid rgba(255,255,255,0.05);
    }
    .footer {
      text-align: center; margin-top: 30px;
      color: #475569; font-size: 12px;
    }
    .badge {
      display: inline-flex; align-items: center; gap: 6px;
      background: rgba(59, 130, 246, 0.1); color: #60a5fa;
      padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 700;
      border: 1px solid rgba(59, 130, 246, 0.2);
    }
    @media (max-width: 600px) {
      .container { padding: 24px; }
      .info-grid { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ VLESS Worker Proxy</h1>
    <p class="subtitle">High-Performance Edge Proxy with AdBlock & DoH</p>

    <div class="status">
      <div class="status-dot"></div>
      <span class="status-text">Running on ${host}</span>
    </div>

    <div class="section">
      <div class="section-title">Connection Info</div>
      <div class="info-grid">
        <span class="info-label">Protocol:</span>
        <span class="info-value">VLESS <span class="badge">v0</span></span>
        <span class="info-label">Transport:</span>
        <span class="info-value">WebSocket (WS)</span>
        <span class="info-label">Security:</span>
        <span class="info-value">TLS 1.3 / AEAD</span>
        <span class="info-label">Port:</span>
        <span class="info-value">443</span>
        <span class="info-label">WS Path:</span>
        <span class="info-value">/${cleanPath}</span>
        <span class="info-label">Proxy IP:</span>
        <span class="info-value">${proxyIP}</span>
        <span class="info-label">Features:</span>
        <span class="info-value">
          <span class="badge">AdBlock</span>
          <span class="badge">DoH DNS</span>
          <span class="badge">Rate Limit</span>
        </span>
      </div>
    </div>

    <div class="section">
      <div class="section-title">VLESS Link</div>
      <div class="link-box">
        <button class="copy-btn" onclick="copyLink()">Copy</button>
        <div id="vless-link">${vlessLink}</div>
      </div>
    </div>

    <div class="section">
      <div class="section-title">Client Configuration</div>
      <div class="tabs">
        <button class="tab active" onclick="showTab('v2ray')">V2Ray / Xray</button>
        <button class="tab" onclick="showTab('clash')">Clash</button>
        <button class="tab" onclick="showTab('nekoray')">NekoRay</button>
      </div>

      <div id="v2ray" class="config-content active">
        <pre>${JSON.stringify(generateXrayConfig(host, uuid, wsPath), null, 2)}</pre>
      </div>
      <div id="clash" class="config-content">
        <pre>${JSON.stringify(generateClashConfig(host, uuid, wsPath), null, 2)}</pre>
      </div>
      <div id="nekoray" class="config-content">
        <div class="info-grid" style="margin-top: 10px;">
          <span class="info-label">Type:</span><span class="info-value">VLESS</span>
          <span class="info-label">Address:</span><span class="info-value">${host}</span>
          <span class="info-label">Port:</span><span class="info-value">443</span>
          <span class="info-label">ID:</span><span class="info-value">${uuid}</span>
          <span class="info-label">Security:</span><span class="info-value">tls</span>
          <span class="info-label">Network:</span><span class="info-value">ws</span>
          <span class="info-label">Path:</span><span class="info-value">/${cleanPath}?ed=2048</span>
          <span class="info-label">Host:</span><span class="info-value">${host}</span>
        </div>
      </div>
    </div>

    <div class="footer">
      Powered by Cloudflare Workers • VLESS Protocol • Built with ❤️
    </div>
  </div>

  <script>
    function copyLink() {
      const text = document.getElementById('vless-link').textContent;
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.querySelector('.copy-btn');
        btn.textContent = 'Copied!';
        setTimeout(() => btn.textContent = 'Copy', 2000);
      });
    }
    function showTab(tabName) {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.config-content').forEach(c => c.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById(tabName).classList.add('active');
    }
  <\/script>
</body>
</html>`;
}

// ============================================
// MAIN FETCH HANDLER
// ============================================
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const clientIP = request.headers.get("CF-Connecting-IP") || "unknown";

        // Resolve configuration from environment
        const envUUID = (env.UUID || env.uuid || "").trim();
        const envProxyIP = (env.PROXYIP || env.proxyip || env.PROXY_IP || DEFAULT_PROXY_IP).trim();
        const envWSPath = (env.WS_PATH || DEFAULT_WS_PATH).trim().replace(/^\/+/, "");
        const envProxyListURL = (env.PROXY_LIST_URL || "").trim();
        const envDoHURL = (env.DNS_RESOLVER_URL || DEFAULT_DOH_URL).trim();
        const envLogLevel = (env.LOG_LEVEL || "info").trim().toLowerCase();

        LOG_LEVEL = ["debug", "info", "warn", "error"].includes(envLogLevel) ? envLogLevel : "info";

        // Parse UUIDs (support comma-separated)
        const allowedUUIDs = [];
        if (envUUID) {
            if (envUUID.includes(",")) {
                envUUID.split(",").forEach(u => {
                    const trimmed = u.trim().toLowerCase();
                    if (isValidUUID(trimmed)) allowedUUIDs.push(trimmed);
                });
            } else if (isValidUUID(envUUID)) {
                allowedUUIDs.push(envUUID.toLowerCase());
            }
        }

        // Build config object
        const config = {
            allowedUUIDs,
            proxyIP: envProxyIP,
            wsPath: envWSPath,
            proxyListURL: envProxyListURL,
            dohURL: envDoHURL
        };

        log("debug", `${request.method} ${path}`, { clientIP });

        // Rate limiting
        if (!rateLimiter.isAllowed(clientIP)) {
            log("warn", "Rate limit exceeded", { clientIP });
            return new Response("Rate limit exceeded", {
                status: HTTP_STATUS.TOO_MANY_REQUESTS,
                headers: { "Retry-After": "60" }
            });
        }

        // No UUID configured
        if (allowedUUIDs.length === 0) {
            return new Response(JSON.stringify({
                error: "Configuration Error",
                message: "No valid UUID configured. Set UUID environment variable.",
                timestamp: new Date().toISOString()
            }), {
                status: HTTP_STATUS.SERVICE_UNAVAILABLE,
                headers: { "Content-Type": "application/json" }
            });
        }

        try {
            // WebSocket upgrade
            if (request.headers.get("Upgrade") === "websocket") {
                const wsPathPattern = new RegExp(`^\/${config.wsPath}([/?#]|$)`);
                if (!wsPathPattern.test(path)) {
                    return new Response("Invalid WebSocket path", {
                        status: HTTP_STATUS.BAD_REQUEST
                    });
                }
                return await handleWebSocket(request, env, config);
            }

            // HTTP endpoints
            switch (path) {
                case "/":
                case "/sub":
                case "/subscribe":
                    return new Response(
                        getDashboardHTML(url.hostname, allowedUUIDs[0], config.wsPath, config.proxyIP, activeProxyPool),
                        { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" } }
                    );

                case "/sub/base64": {
                    const vlessLink = generateVLESSLink(url.hostname, allowedUUIDs[0], config.wsPath);
                    const encoded = btoa(vlessLink);
                    return new Response(encoded, {
                        headers: {
                            "Content-Type": "text/plain; charset=utf-8",
                            "Subscription-Userinfo": "upload=0; download=0; total=0; expire=0"
                        }
                    });
                }

                case "/sub/clash":
                    return new Response(
                        JSON.stringify(generateClashConfig(url.hostname, allowedUUIDs[0], config.wsPath), null, 2),
                        { headers: { "Content-Type": "application/json; charset=utf-8" } }
                    );

                case "/sub/v2ray":
                case "/sub/xray":
                    return new Response(
                        JSON.stringify(generateXrayConfig(url.hostname, allowedUUIDs[0], config.wsPath), null, 2),
                        { headers: { "Content-Type": "application/json; charset=utf-8" } }
                    );

                case "/config":
                    return new Response(JSON.stringify({
                        uuid: allowedUUIDs[0],
                        proxyIP: config.proxyIP,
                        proxyIPPool: DEFAULT_PROXY_IP_POOL,
                        websocketPath: config.wsPath,
                        dohURL: config.dohURL,
                        logLevel: LOG_LEVEL,
                        status: "running",
                        timestamp: new Date().toISOString()
                    }), {
                        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
                    });

                case "/health":
                    return new Response(JSON.stringify({
                        status: "healthy",
                        protocols: ["VLESS"],
                        edge: "Cloudflare Anycast",
                        colo: request.cf?.colo || "EDGE",
                        country: request.cf?.country || "US",
                        clientIp: clientIP,
                        timestamp: new Date().toISOString()
                    }), {
                        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
                    });

                default:
                    return new Response("Not Found", {
                        status: HTTP_STATUS.NOT_FOUND,
                        headers: { "Content-Type": "text/plain" }
                    });
            }
        } catch (error) {
            log("error", "Request handler error", {
                error: error.message,
                stack: error.stack,
                path,
                clientIP
            });
            return new Response(JSON.stringify({
                error: "Internal Server Error",
                message: error.message,
                timestamp: new Date().toISOString()
            }), {
                status: HTTP_STATUS.INTERNAL_ERROR,
                headers: { "Content-Type": "application/json" }
            });
        }
    }
};
