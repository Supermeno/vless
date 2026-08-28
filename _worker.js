import { connect } from "cloudflare:sockets";

// ============================================
// DEFAULT CONFIGURATION & ENVIRONMENT
// ============================================
const DEFAULT_UUID = "";
const DEFAULT_TROJAN_PASS = "";
const DEFAULT_PROXY_IP = "cdn-b100.xn--b6gac.eu.org";
const DEFAULT_DOH_URL = "https://cloudflare-dns.com/dns-query";
const DEFAULT_WS_PATH = "galaxy-tunnel";

let userID = "";
let trojanPassword = "";
let proxyIP = DEFAULT_PROXY_IP;
let dohURL = DEFAULT_DOH_URL;
let wsPath = DEFAULT_WS_PATH;

// Fast Static Proxy Pool for Failover (Zero Latency)
const STATIC_PROXY_POOL = [
    "cdn-b100.xn--b6gac.eu.org",
    "cdn.xn--b6gac.eu.org",
    "cdn-all.xn--b6gac.eu.org",
    "bpb.yousef.isegaro.com",
    "icook.hk",
    "icook.tw",
    "www.visa.com.sg"
];

// ============================================
// SHA-224 Hash Implementation for Trojan
// ============================================
function sha224(str) {
    if (!str) return "";
    function rotateRight(n, x) { return (x >>> n) | (x << (32 - n)); }
    function choice(x, y, z) { return (x & y) ^ (~x & z); }
    function majority(x, y, z) { return (x & y) ^ (x & z) ^ (y & z); }
    function sigma0(x) { return rotateRight(2, x) ^ rotateRight(13, x) ^ rotateRight(22, x); }
    function sigma1(x) { return rotateRight(6, x) ^ rotateRight(11, x) ^ rotateRight(25, x); }
    function gamma0(x) { return rotateRight(7, x) ^ rotateRight(18, x) ^ (x >>> 3); }
    function gamma1(x) { return rotateRight(17, x) ^ rotateRight(19, x) ^ (x >>> 10); }

    const K = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];

    let H0 = 0xc1059ed8, H1 = 0x367cd507, H2 = 0x3070dd17, H3 = 0xf70e5939;
    let H4 = 0xffc00b31, H5 = 0x68581511, H6 = 0x64f98fa7, H7 = 0xbefa4fa4;

    const utf8 = new TextEncoder().encode(str.trim());
    const l = utf8.length;
    const bitLen = l * 8;
    const k = (56 - ((l + 1) % 64) + 64) % 64;
    const padded = new Uint8Array(l + 1 + k + 8);
    padded.set(utf8);
    padded[l] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 4, bitLen, false);

    const W = new Uint32Array(64);
    for (let i = 0; i < padded.length; i += 64) {
        for (let t = 0; t < 16; t++) {
            W[t] = view.getUint32(i + t * 4, false);
        }
        for (let t = 16; t < 64; t++) {
            W[t] = (gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16]) >>> 0;
        }

        let a = H0, b = H1, c = H2, d = H3, e = H4, f = H5, g = H6, h = H7;
        for (let t = 0; t < 64; t++) {
            const T1 = (h + sigma1(e) + choice(e, f, g) + K[t] + W[t]) >>> 0;
            const T2 = (sigma0(a) + majority(a, b, c)) >>> 0;
            h = g; g = f; f = e; e = (d + T1) >>> 0;
            d = c; c = b; b = a; a = (T1 + T2) >>> 0;
        }

        H0 = (H0 + a) >>> 0; H1 = (H1 + b) >>> 0; H2 = (H2 + c) >>> 0; H3 = (H3 + d) >>> 0;
        H4 = (H4 + e) >>> 0; H5 = (H5 + f) >>> 0; H6 = (H6 + g) >>> 0; H7 = (H7 + h) >>> 0;
    }

    const out = [H0, H1, H2, H3, H4, H5, H6];
    return out.map(n => n.toString(16).padStart(8, "0")).join("");
}

function isValidUUID(uuid) {
    if (!uuid) return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid.trim());
}

function getFastProxyIP(configuredProxy) {
    if (configuredProxy && configuredProxy !== DEFAULT_PROXY_IP) {
        return configuredProxy;
    }
    return STATIC_PROXY_POOL[Math.floor(Math.random() * STATIC_PROXY_POOL.length)];
}

// ============================================
// Direct Local Bypass Check
// ============================================
function isPrivateOrLocalAddress(address) {
    if (!address) return false;
    const lower = address.toLowerCase().trim();
    if (lower === "localhost" || lower.endsWith(".local") || lower.endsWith(".internal") || lower.endsWith(".lan")) {
        return true;
    }
    if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    if (/^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    if (/^192\.168\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    const match172 = lower.match(/^172\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/);
    if (match172) {
        const secondOctet = parseInt(match172[1], 10);
        if (secondOctet >= 16 && secondOctet <= 31) return true;
    }
    if (/^169\.254\.\d{1,3}\.\d{1,3}$/.test(lower)) return true;
    if (lower === "::1" || lower.startsWith("fc00:") || lower.startsWith("fe80:") || lower.startsWith("fd")) {
        return true;
    }
    return false;
}

// ============================================
// Dynamic Config Parser
// ============================================
function extractDynamicConfig(url) {
    const parsed = new URL(url);
    const pathSegments = parsed.pathname.split("/").filter(Boolean);

    let extractedUUID = null;
    let extractedTrojanPass = null;
    let extractedPath = null;

    const qUUID = parsed.searchParams.get("uuid") || parsed.searchParams.get("id");
    const qTrojan = parsed.searchParams.get("trojan") || parsed.searchParams.get("pass") || parsed.searchParams.get("trojan_pass");
    const qProxyIP = parsed.searchParams.get("proxyip") || parsed.searchParams.get("ip");
    const qWSPath = parsed.searchParams.get("path") || parsed.searchParams.get("wspath");

    if (qUUID && isValidUUID(qUUID)) {
        extractedUUID = qUUID.trim().toLowerCase();
    }
    if (qTrojan) {
        extractedTrojanPass = qTrojan.trim();
    }

    if (isValidUUID(pathSegments[0])) {
        extractedUUID = pathSegments[0].toLowerCase();
        if (pathSegments[1]) {
            extractedPath = pathSegments.slice(1).join("/");
        }
    }

    return {
        uuid: extractedUUID,
        trojanPass: extractedTrojanPass || extractedUUID,
        proxyIP: qProxyIP ? qProxyIP.trim() : null,
        wsPath: qWSPath ? qWSPath.trim().replace(/^\/+/, "") : (extractedPath || null)
    };
}

// ============================================
// High Stability Direct Node Generator (TLS & Non-TLS / 80 & 8080)
// ============================================
function generateDirectNodes(host, activeUUID, activeTrojanPass, activeWSPath, activeProxy) {
    const cleanPath = (activeWSPath || DEFAULT_WS_PATH).replace(/^\/+/, "");
    const titleHost = host.replace(/[^a-zA-Z0-9.-]/g, "");
    const trojanKey = activeTrojanPass || activeUUID;

    // --- VLESS Configurations ---
    // 1. VLESS TLS (Port 443)
    const vlessTls443 = `vless://${activeUUID}@${host}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#VLESS-TLS-443%20(${titleHost})`;
    
    // 2. VLESS No-TLS / HTTP (Port 80)
    const vlessHttp80 = `vless://${activeUUID}@${host}:80?encryption=none&security=none&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#VLESS-NoTLS-80%20(${titleHost})`;
    
    // 3. VLESS No-TLS / HTTP (Port 8080)
    const vlessHttp8080 = `vless://${activeUUID}@${host}:8080?encryption=none&security=none&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#VLESS-NoTLS-8080%20(${titleHost})`;
    
    // 4. VLESS with ProxyIP (TLS 443)
    const vlessProxy = activeProxy ? `vless://${activeUUID}@${activeProxy}:443?encryption=none&security=tls&sni=${host}&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#VLESS-ProxyIP%20(${activeProxy})` : "";

    // --- Trojan Configurations ---
    // 5. Trojan TLS (Port 443)
    const trojanTls443 = `trojan://${encodeURIComponent(trojanKey)}@${host}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#Trojan-TLS-443%20(${titleHost})`;
    
    // 6. Trojan with ProxyIP (TLS 443)
    const trojanProxy = activeProxy ? `trojan://${encodeURIComponent(trojanKey)}@${activeProxy}:443?security=tls&sni=${host}&type=ws&host=${host}&path=%2F${encodeURIComponent(cleanPath)}%3Fed%3D2048#Trojan-ProxyIP%20(${activeProxy})` : "";

    return {
        vlessTls443,
        vlessHttp80,
        vlessHttp8080,
        vlessProxy,
        trojanTls443,
        trojanProxy
    };
}

// ============================================
// Worker Main Fetch Handler
// ============================================
var worker_default = {
    async fetch(request, env = {}, ctx) {
        const url = new URL(request.url);
        const host = request.headers.get("Host") || url.host;

        // 1. Resolve Environment Variables
        const envUUID = env.UUID || env.uuid;
        const envTrojanPass = env.TROJAN_PASS || env.trojan_pass || env.TROJAN_PASSWORD || "";
        const envPassword = (env.PASSWORD || env.password || "").trim();
        const maskPageEnabled = (env.MASK_PAGE !== "false" && env.MASK_PAGE !== false);

        userID = envUUID && isValidUUID(envUUID) ? envUUID.trim().toLowerCase() : "";
        trojanPassword = envTrojanPass ? envTrojanPass.trim() : (userID || "");
        proxyIP = env.PROXYIP || env.proxyip || env.PROXY_IP || DEFAULT_PROXY_IP;
        dohURL = env.DNS_RESOLVER_URL || DEFAULT_DOH_URL;
        wsPath = (env.WS_PATH || DEFAULT_WS_PATH).replace(/^\/+/, "");

        // 2. Dynamic Runtime Config extraction
        const dynConfig = extractDynamicConfig(request.url);
        const runtimeUUID = dynConfig.uuid || userID;
        const runtimeTrojanPass = dynConfig.trojanPass || trojanPassword || runtimeUUID;
        const runtimeWSPath = dynConfig.wsPath || wsPath;
        const runtimeProxyIP = dynConfig.proxyIP || proxyIP;

        const allowedUUIDList = Array.from(
            new Set([
                ...(userID && isValidUUID(userID) ? [userID] : []),
                ...(dynConfig.uuid && isValidUUID(dynConfig.uuid) ? [dynConfig.uuid] : []),
                ...(envUUID && envUUID.includes(",") ? envUUID.split(",").map(u => u.trim().toLowerCase()).filter(isValidUUID) : [])
            ])
        ).filter(Boolean);

        const allowedTrojanPassList = Array.from(
            new Set([
                ...(runtimeTrojanPass ? [runtimeTrojanPass] : []),
                ...(trojanPassword ? [trojanPassword] : []),
                ...allowedUUIDList,
                ...(envPassword ? [envPassword] : [])
            ])
        ).filter(Boolean);

        const allowedTrojanHashes = allowedTrojanPassList.map(p => sha224(p).toLowerCase()).filter(Boolean);

        // 3. WebSocket Proxy Route (VLESS & Trojan - Supports Port 443 TLS, Port 80, Port 8080 No-TLS)
        const upgradeHeader = request.headers.get("Upgrade");
        if (upgradeHeader === "websocket") {
            return await proxyOverWSHandler(request, allowedUUIDList, allowedTrojanHashes);
        }

        // 4. Auth Verification for Direct Node Console
        const cookieHeader = request.headers.get("Cookie") || "";
        const hasAuthCookie = cookieHeader.includes("galaxy_auth=1") || (envPassword && cookieHeader.includes(`galaxy_pwd=${encodeURIComponent(envPassword)}`));
        const qPwd = url.searchParams.get("pwd") || url.searchParams.get("password") || url.searchParams.get("key");
        const isAuthorizedByPwd = (envPassword && qPwd === envPassword) || (userID && qPwd === userID) || (runtimeTrojanPass && qPwd === runtimeTrojanPass);
        const isAuthorizedByUuid = (dynConfig.uuid && isValidUUID(dynConfig.uuid));
        const pathSegments = url.pathname.split("/").filter(Boolean);
        const isDirectUuidPath = (pathSegments[0] && isValidUUID(pathSegments[0]));

        // Login API endpoint
        if (url.pathname === "/api/login" && request.method === "POST") {
            try {
                const body = await request.json().catch(() => ({}));
                const submittedKey = (body.key || body.password || body.uuid || "").trim();
                const isValidKey = (envPassword && submittedKey === envPassword) || 
                                   (userID && submittedKey.toLowerCase() === userID.toLowerCase()) || 
                                   (trojanPassword && submittedKey === trojanPassword) ||
                                   isValidUUID(submittedKey);

                if (isValidKey) {
                    return new Response(JSON.stringify({ success: true, redirect: isValidUUID(submittedKey) ? `/${submittedKey}` : `/?pwd=${encodeURIComponent(submittedKey)}` }), {
                        status: 200,
                        headers: {
                            "Content-Type": "application/json",
                            "Set-Cookie": "galaxy_auth=1; Path=/; Max-Age=86400; SameSite=Lax; HttpOnly"
                        }
                    });
                }
                return new Response(JSON.stringify({ success: false, message: "Invalid UUID or Password" }), {
                    status: 401,
                    headers: { "Content-Type": "application/json" }
                });
            } catch (e) {
                return new Response(JSON.stringify({ success: false, message: "Login error" }), { status: 400 });
            }
        }

        // Logout API endpoint
        if (url.pathname === "/api/logout") {
            return new Response(null, {
                status: 302,
                headers: {
                    "Location": "/",
                    "Set-Cookie": "galaxy_auth=0; Path=/; Max-Age=0; SameSite=Lax"
                }
            });
        }

        // 5. API Health Endpoint
        if (url.pathname === "/api/health" || url.pathname === "/api/ping") {
            return new Response(JSON.stringify({
                status: "healthy",
                protocols: ["VLESS", "Trojan"],
                transport: "WebSocket",
                ports: {
                    tls: [443, 8443, 2053, 2083, 2087, 2096],
                    notls: [80, 8080, 8880, 2052, 2082, 2086, 2095]
                },
                edge: "Cloudflare Anycast",
                colo: request.cf?.colo || "EDGE",
                country: request.cf?.country || "US",
                clientIp: request.headers.get("CF-Connecting-IP") || "127.0.0.1",
                timestamp: Date.now()
            }), {
                status: 200,
                headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
            });
        }

        // 6. Direct Node Console vs Mask Page Rendering
        const isAuthorizedToViewConsole = !maskPageEnabled || isDirectUuidPath || isAuthorizedByUuid || isAuthorizedByPwd || hasAuthCookie;

        if (isAuthorizedToViewConsole) {
            const nodes = generateDirectNodes(host, runtimeUUID, runtimeTrojanPass, runtimeWSPath, runtimeProxyIP);
            return new Response(getConsolePage(host, runtimeUUID, runtimeTrojanPass, runtimeWSPath, runtimeProxyIP, nodes), {
                status: 200,
                headers: {
                    "Content-Type": "text/html; charset=utf-8",
                    ...(qPwd || isAuthorizedByUuid ? { "Set-Cookie": "galaxy_auth=1; Path=/; Max-Age=86400; SameSite=Lax" } : {})
                }
            });
        }

        const clientIp = request.headers.get("CF-Connecting-IP") || "127.0.0.1";
        const colo = request.cf?.colo || "EDGE-GLOBAL";
        return new Response(getMaskPage(host, Boolean(envPassword || userID), clientIp, colo), {
            status: 200,
            headers: { "Content-Type": "text/html; charset=utf-8" }
        });
    }
};

// ============================================
// Dual Protocol Header Parser (VLESS & Trojan)
// ============================================
function processProxyHeader(buffer, allowedUUIDs, allowedTrojanHashes) {
    if (!buffer || buffer.byteLength < 24) {
        return { hasError: true, message: "Invalid payload data (too short)" };
    }

    const uint8 = new Uint8Array(buffer);

    // --- CHECK 1: Trojan Protocol ---
    if (uint8.byteLength >= 58 && uint8[56] === 0x0D && uint8[57] === 0x0A) {
        const hexHash = new TextDecoder().decode(uint8.slice(0, 56)).toLowerCase().trim();
        const isValidTrojan = allowedTrojanHashes.some(h => h && h === hexHash);

        if (!isValidTrojan) {
            return { hasError: true, message: "Invalid Trojan credential hash" };
        }

        const command = uint8[58];
        const isUDP = (command === 3);

        const addressType = uint8[59];
        let addressLength = 0;
        let addressValueIndex = 60;
        let addressValue = "";

        switch (addressType) {
            case 1: // IPv4
                addressLength = 4;
                addressValue = new Uint8Array(uint8.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
                break;
            case 3: // Domain
                addressLength = uint8[addressValueIndex];
                addressValueIndex += 1;
                addressValue = new TextDecoder().decode(uint8.slice(addressValueIndex, addressValueIndex + addressLength));
                break;
            case 4: // IPv6
                addressLength = 16;
                const dataView = new DataView(uint8.buffer, uint8.byteOffset + addressValueIndex, addressLength);
                const ipv6 = [];
                for (let i = 0; i < 8; i++) {
                    ipv6.push(dataView.getUint16(i * 2).toString(16));
                }
                addressValue = ipv6.join(":");
                break;
            default:
                return { hasError: true, message: `Invalid Trojan address type ${addressType}` };
        }

        const portIndex = addressValueIndex + addressLength;
        const portRemote = new DataView(uint8.buffer, uint8.byteOffset + portIndex, 2).getUint16(0);
        const rawDataIndex = portIndex + 4; // Skip port and trailing \r\n

        return {
            hasError: false,
            protocol: "trojan",
            addressRemote: addressValue,
            addressType,
            portRemote,
            rawDataIndex,
            responseHeader: null,
            isUDP
        };
    }

    // --- CHECK 2: VLESS Protocol ---
    const version = uint8[0];
    const slicedBuffer = uint8.slice(1, 17);
    const slicedBufferString = unsafeStringify(slicedBuffer);

    const validList = Array.isArray(allowedUUIDs) ? allowedUUIDs : [allowedUUIDs];
    const isValidUser = validList.some((userUuid) => userUuid && slicedBufferString === userUuid.trim().toLowerCase());

    if (!isValidUser) {
        return { hasError: true, message: `Invalid VLESS user (${slicedBufferString})` };
    }

    const optLength = uint8[17];
    const command = uint8[18 + optLength];
    const isUDP = (command === 2);

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(uint8.buffer, uint8.byteOffset + portIndex, 2).getUint16(0);

    const addressIndex = portIndex + 2;
    const addressType = uint8[addressIndex];

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";

    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(uint8.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = uint8[addressValueIndex];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(uint8.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(uint8.buffer, uint8.byteOffset + addressValueIndex, addressLength);
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `Invalid VLESS address type ${addressType}` };
    }

    if (!addressValue) {
        return { hasError: true, message: "VLESS address value is empty" };
    }

    const responseHeader = new Uint8Array([version, 0]);
    return {
        hasError: false,
        protocol: "vless",
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        responseHeader,
        isUDP
    };
}

// ============================================
// High-Speed WebSocket Proxy Handler
// ============================================
async function proxyOverWSHandler(request, allowedUUIDs, allowedTrojanHashes) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const result = processProxyHeader(chunk, allowedUUIDs, allowedTrojanHashes);
            if (result.hasError) {
                webSocket.close();
                return;
            }

            const {
                addressRemote = "",
                portRemote = 443,
                rawDataIndex,
                responseHeader,
                isUDP
            } = result;

            if (isUDP && portRemote === 53) {
                isDns = true;
                const { write } = await handleUDPOutBound(webSocket, responseHeader);
                udpStreamWrite = write;
                const rawClientData = chunk.slice(rawDataIndex);
                if (rawClientData.length > 0) {
                    udpStreamWrite(rawClientData);
                }
                return;
            }

            const rawClientData = chunk.slice(rawDataIndex);
            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader);
        },
        close() {},
        abort() {}
    })).catch(() => {
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, { status: 101, webSocket: client });
}

// ============================================
// Optimized TCP Outbound with Instant Failover
// ============================================
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, client, responseHeader) {
    const isDirect = isPrivateOrLocalAddress(addressRemote);

    async function connectAndWrite(targetHost, targetPort) {
        const socket = connect({ hostname: targetHost, port: targetPort });
        remoteSocket.value = socket;
        const writer = socket.writable.getWriter();
        if (rawClientData && rawClientData.byteLength > 0) {
            await writer.write(rawClientData);
        }
        writer.releaseLock();
        return socket;
    }

    async function retryWithProxy() {
        if (isDirect) {
            safeCloseWebSocket(client);
            return;
        }

        const fallbackProxy = getFastProxyIP(proxyIP);
        try {
            const socket = await connectAndWrite(fallbackProxy, portRemote);
            socket.closed.catch(() => {}).finally(() => safeCloseWebSocket(client));
            pipeRemoteToClient(socket, client, responseHeader, null);
        } catch (err) {
            safeCloseWebSocket(client);
        }
    }

    try {
        const socket = await connectAndWrite(addressRemote, portRemote);
        pipeRemoteToClient(socket, client, responseHeader, isDirect ? null : retryWithProxy);
    } catch (err) {
        if (!isDirect) {
            await retryWithProxy();
        } else {
            safeCloseWebSocket(client);
        }
    }
}

// Zero-Copy Fast Stream Piping
async function pipeRemoteToClient(remoteSocket, client, responseHeader, retry) {
    let header = responseHeader;
    let hasReceivedData = false;

    await remoteSocket.readable.pipeTo(new WritableStream({
        write(chunk, controller) {
            hasReceivedData = true;
            if (client.readyState !== 1) {
                controller.error("WebSocket closed");
                return;
            }

            if (header) {
                const chunkBytes = chunk instanceof Uint8Array ? chunk : new Uint8Array(chunk);
                const merged = new Uint8Array(header.length + chunkBytes.length);
                merged.set(header, 0);
                merged.set(chunkBytes, header.length);
                client.send(merged.buffer);
                header = null;
            } else {
                client.send(chunk);
            }
        },
        close() {},
        abort() {}
    })).catch(() => {
        safeCloseWebSocket(client);
    });

    if (!hasReceivedData && retry) {
        retry();
    }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        cancel() {
            safeCloseWebSocket(webSocketServer);
        }
    });
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

var byteToHex = [];
for (let i = 0; i < 256; ++i) {
    byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function safeCloseWebSocket(socket) {
    if (!socket) return;
    try {
        if (socket.readyState === 1 || socket.readyState === 2) {
            socket.close();
        }
    } catch (error) {}
}

async function handleUDPOutBound(webSocket, responseHeader) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength; ) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            try {
                const resp = await fetch(dohURL, {
                    method: "POST",
                    headers: { "content-type": "application/dns-message" },
                    body: chunk
                });
                const dnsQueryResult = await resp.arrayBuffer();
                const udpSize = dnsQueryResult.byteLength;
                const udpSizeBuffer = new Uint8Array([udpSize >> 8 & 255, udpSize & 255]);

                const fullPacket = isHeaderSent || !responseHeader
                    ? new Uint8Array([...udpSizeBuffer, ...new Uint8Array(dnsQueryResult)])
                    : new Uint8Array([...responseHeader, ...udpSizeBuffer, ...new Uint8Array(dnsQueryResult)]);
                isHeaderSent = true;

                if (webSocket.readyState === 1) {
                    webSocket.send(fullPacket.buffer);
                }
            } catch (err) {}
        }
    })).catch(() => {});

    const writer = transformStream.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
}

// ============================================
// 1. CAMOUFLAGE MASK PAGE (Default Disguise)
// ============================================
function getMaskPage(host = "localhost", isAuthEnabled = true, clientIp = "127.0.0.1", colo = "EDGE-GLOBAL") {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>EdgeTunnel Cloud | Edge Network &amp; Diagnostics</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
      background: #f8fafc;
      color: #0f172a;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      background: #ffffff;
      border-bottom: 1px solid #e2e8f0;
      padding: 14px 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .logo-area {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 800;
      font-size: 17px;
      color: #000000;
      cursor: pointer;
      user-select: none;
      line-height: 1.15;
    }
    .logo-icon {
      width: 32px;
      height: 32px;
      background: #000000;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      color: #ffffff;
      font-weight: 900;
      font-size: 16px;
    }
    .header-actions {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .status-pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: #000000;
      padding: 6px 14px;
      border-radius: 9999px;
      font-size: 11px;
      font-weight: 800;
      color: #ffffff;
      letter-spacing: 0.5px;
    }
    .btn-portal {
      background: transparent;
      border: none;
      color: #000000;
      padding: 4px 8px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 4px;
      transition: opacity 0.2s;
    }
    .btn-portal:hover { opacity: 0.7; }
    main {
      flex: 1;
      max-width: 960px;
      width: 100%;
      margin: 0 auto;
      padding: 24px 16px;
      display: flex;
      flex-direction: column;
      gap: 20px;
    }
    .hero-card {
      background: linear-gradient(180deg, #ecfdf5 0%, #ffffff 40%);
      border: 1px solid #e2e8f0;
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 4px 20px -2px rgba(0, 0, 0, 0.03);
      position: relative;
    }
    .hero-top-badge {
      position: absolute;
      top: 24px;
      right: 24px;
      background: #dcfce7;
      border: 1px solid #bbf7d0;
      color: #166534;
      font-size: 12px;
      font-weight: 700;
      padding: 4px 12px;
      border-radius: 9999px;
    }
    .hero-title {
      font-size: 23px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 8px;
      padding-right: 70px;
      line-height: 1.25;
    }
    .hero-desc {
      color: #475569;
      font-size: 14px;
      line-height: 1.6;
      max-width: 680px;
      margin-bottom: 18px;
    }
    .btn-run {
      background: #000000;
      color: #ffffff;
      border: none;
      padding: 9px 18px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 13px;
      cursor: pointer;
      transition: opacity 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      box-shadow: 0 2px 6px rgba(0, 0, 0, 0.15);
    }
    .btn-run:hover { opacity: 0.85; }
    .bench-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 12px;
      margin-top: 20px;
    }
    .bench-box {
      border-radius: 12px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }
    .bench-box-1 {
      background: linear-gradient(135deg, #d1fae5 0%, #ecfdf5 100%);
      border: 1px solid #a7f3d0;
    }
    .bench-box-2 {
      background: linear-gradient(135deg, #dcfce7 0%, #f0fdf4 100%);
      border: 1px solid #bbf7d0;
    }
    .bench-box-3 {
      background: linear-gradient(135deg, #e0e7ff 0%, #f5f3ff 100%);
      border: 1px solid #c7d2fe;
    }
    .bench-box-4 {
      background: linear-gradient(135deg, #fce7f3 0%, #fdf4ff 100%);
      border: 1px solid #fbcfe8;
    }
    .bench-label {
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .bench-box-1 .bench-label { color: #047857; }
    .bench-box-2 .bench-label { color: #15803d; }
    .bench-box-3 .bench-label { color: #4338ca; }
    .bench-box-4 .bench-label { color: #9d174d; }
    .bench-val {
      font-size: 24px;
      font-weight: 800;
      color: #0f172a;
      margin-top: 4px;
      font-family: monospace;
    }
    .bench-meta {
      font-size: 12px;
      font-weight: 600;
      margin-top: 2px;
    }
    .bench-box-1 .bench-meta { color: #059669; }
    .bench-box-2 .bench-meta { color: #16a34a; }
    .bench-box-3 .bench-meta { color: #4f46e5; }
    .bench-box-4 .bench-meta { color: #db2777; }
    .grid-2 {
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
    }
    @media (min-width: 768px) {
      .grid-2 { grid-template-columns: 1fr 1fr; }
    }
    .card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      border-radius: 14px;
      padding: 20px;
      box-shadow: 0 2px 8px rgba(0, 0, 0, 0.02);
    }
    .card-heading {
      font-size: 15px;
      font-weight: 800;
      color: #0f172a;
      margin-bottom: 14px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 9px 0;
      border-bottom: 1px solid #f1f5f9;
      font-size: 13px;
    }
    .info-row:last-child { border-bottom: none; }
    .info-k { color: #475569; font-weight: 500; }
    .info-v { color: #0f172a; font-family: monospace; font-weight: 700; }
    
    .modal-overlay {
      position: fixed;
      top: 0; left: 0; width: 100%; height: 100%;
      background: rgba(15, 23, 42, 0.6);
      backdrop-filter: blur(6px);
      display: flex;
      align-items: center;
      justify-content: center;
      z-index: 100;
      opacity: 0;
      pointer-events: none;
      transition: opacity 0.2s;
    }
    .modal-overlay.open { opacity: 1; pointer-events: auto; }
    .modal-card {
      background: #ffffff;
      border: 1px solid #e2e8f0;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
      border-radius: 16px;
      width: 100%;
      max-width: 420px;
      padding: 24px;
      margin: 16px;
    }
    .modal-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 14px;
    }
    .modal-title {
      font-size: 17px;
      font-weight: 800;
      color: #0f172a;
    }
    .btn-close {
      background: transparent;
      border: none;
      color: #64748b;
      font-size: 18px;
      cursor: pointer;
    }
    .modal-input {
      width: 100%;
      background: #f8fafc;
      border: 1px solid #cbd5e1;
      padding: 11px 14px;
      border-radius: 8px;
      color: #0f172a;
      font-family: monospace;
      font-size: 14px;
      outline: none;
      margin-bottom: 14px;
    }
    .modal-input:focus {
      border-color: #000000;
      background: #ffffff;
      box-shadow: 0 0 0 3px rgba(0, 0, 0, 0.05);
    }
    .btn-submit {
      width: 100%;
      background: #000000;
      color: #ffffff;
      border: none;
      padding: 11px;
      border-radius: 8px;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
    }
    .btn-submit:hover { opacity: 0.85; }
    .auth-msg {
      font-size: 12px;
      margin-top: 10px;
      text-align: center;
      color: #dc2626;
      font-weight: 600;
      display: none;
    }
  </style>
</head>
<body>
  <header>
    <div class="logo-area" onclick="handleLogoClick()">
      <div class="logo-icon">⚡</div>
      <div>
        <div>EdgeTunnel</div>
        <div>Cloud</div>
      </div>
    </div>
    <div class="header-actions">
      <div class="status-pill">
        <span>EDGE OPERATIONAL</span>
      </div>
      <button class="btn-portal" onclick="openPortalModal()">
        <span>🔒 Portal Access</span>
      </button>
    </div>
  </header>

  <main>
    <div class="hero-card">
      <div class="hero-top-badge">Active</div>
      <h1 class="hero-title">Edge Network Diagnostic &amp; Latency Monitor</h1>
      <p class="hero-desc">Real-time edge server telemetry, DNS-over-HTTPS status verification, and full-duplex socket connectivity diagnostics for cloud edge clusters.</p>
      
      <button class="btn-run" id="btnBench" onclick="runDiagnostics()">
        ⚡ Re-Run Benchmark
      </button>

      <div class="bench-grid">
        <div class="bench-box bench-box-1">
          <div class="bench-label">Edge Roundtrip Ping</div>
          <div class="bench-val" id="pingVal">-- ms</div>
          <div class="bench-meta" id="pingStatus">Measuring...</div>
        </div>
        <div class="bench-box bench-box-2">
          <div class="bench-label">DNS-Over-HTTPS (DoH)</div>
          <div class="bench-val">Active</div>
          <div class="bench-meta">Cloudflare 1.1.1.1</div>
        </div>
        <div class="bench-box bench-box-3">
          <div class="bench-label">Supported Ports</div>
          <div class="bench-val">TLS &amp; Non-TLS</div>
          <div class="bench-meta">443, 80, 8080 Active</div>
        </div>
        <div class="bench-box bench-box-4">
          <div class="bench-label">Edge Cluster Location</div>
          <div class="bench-val">${colo}</div>
          <div class="bench-meta">Anycast Network</div>
        </div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card">
        <div class="card-heading">🌐 Connection Telemetry</div>
        <div class="info-row">
          <span class="info-k">Client Remote IP:</span>
          <span class="info-v">${clientIp}</span>
        </div>
        <div class="info-row">
          <span class="info-k">Serving Host:</span>
          <span class="info-v">${host}</span>
        </div>
        <div class="info-row">
          <span class="info-k">Supported Protocols:</span>
          <span class="info-v" style="color: #0284c7;">VLESS &amp; Trojan (Dual)</span>
        </div>
        <div class="info-row">
          <span class="info-k">Supported Ports:</span>
          <span class="info-v">443 (TLS) | 80, 8080 (No-TLS)</span>
        </div>
      </div>

      <div class="card">
        <div class="card-heading">🛡️ Edge Security &amp; Health</div>
        <div class="info-row">
          <span class="info-k">DDoS Mitigation:</span>
          <span class="info-v" style="color: #16a34a;">Active (Strict)</span>
        </div>
        <div class="info-row">
          <span class="info-k">Global Edge Cache:</span>
          <span class="info-v">100% Operational</span>
        </div>
        <div class="info-row">
          <span class="info-k">Service Status:</span>
          <span class="info-v" style="color: #16a34a;">Optimal (99.99%)</span>
        </div>
      </div>
    </div>
  </main>

  <div class="modal-overlay" id="portalModal">
    <div class="modal-card">
      <div class="modal-head">
        <div class="modal-title">🔒 Edge Gateway Access</div>
        <button class="btn-close" onclick="closePortalModal()">✕</button>
      </div>
      <p style="font-size: 13px; color: #64748b; margin-bottom: 14px; line-height: 1.5;">
        Enter your UUID or Password to access direct proxy configuration nodes.
      </p>
      <form onsubmit="handlePortalLogin(event)">
        <input type="password" id="authKeyInput" class="modal-input" placeholder="Enter UUID or Password" required autofocus />
        <button type="submit" class="btn-submit" id="submitBtn">Unlock Nodes</button>
      </form>
      <div class="auth-msg" id="authErrorMsg">⚠️ Invalid UUID or Password. Access Denied.</div>
    </div>
  </div>

  <script>
    let logoClicks = 0;
    function handleLogoClick() {
      logoClicks++;
      if (logoClicks >= 3) {
        openPortalModal();
        logoClicks = 0;
      }
    }

    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === 'A' || e.key === 'a')) {
        openPortalModal();
      }
      if (e.key === 'Escape') {
        closePortalModal();
      }
    });

    function openPortalModal() {
      document.getElementById('portalModal').classList.add('open');
      document.getElementById('authKeyInput').focus();
    }

    function closePortalModal() {
      document.getElementById('portalModal').classList.remove('open');
      document.getElementById('authErrorMsg').style.display = 'none';
    }

    async function handlePortalLogin(e) {
      e.preventDefault();
      const key = document.getElementById('authKeyInput').value.trim();
      const errorMsg = document.getElementById('authErrorMsg');
      const submitBtn = document.getElementById('submitBtn');

      if (!key) return;
      submitBtn.textContent = "Verifying...";
      submitBtn.disabled = true;
      errorMsg.style.display = 'none';

      try {
        const resp = await fetch('/api/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ key })
        });
        const data = await resp.json();

        if (resp.ok && data.success) {
          window.location.href = data.redirect || ('/' + encodeURIComponent(key));
        } else {
          errorMsg.textContent = data.message || "⚠️ Invalid Access Key / UUID.";
          errorMsg.style.display = 'block';
          submitBtn.textContent = "Unlock Nodes";
          submitBtn.disabled = false;
        }
      } catch (err) {
        window.location.href = '/' + encodeURIComponent(key);
      }
    }

    async function runDiagnostics() {
      const btn = document.getElementById('btnBench');
      const pingVal = document.getElementById('pingVal');
      const pingStatus = document.getElementById('pingStatus');

      btn.disabled = true;
      btn.textContent = "Testing Edge Latency...";
      pingVal.textContent = "...";
      pingStatus.textContent = "Measuring round-trip...";

      const pings = [];
      for (let i = 0; i < 3; i++) {
        const start = performance.now();
        try {
          await fetch('/api/health?t=' + Date.now(), { cache: 'no-store' });
          const latency = Math.round(performance.now() - start);
          pings.push(latency);
        } catch (e) {
          pings.push(32);
        }
        await new Promise(r => setTimeout(r, 120));
      }

      const avg = Math.round(pings.reduce((a, b) => a + b, 0) / pings.length);
      pingVal.textContent = avg + ' ms';
      pingStatus.textContent = "Good Latency";
      btn.disabled = false;
      btn.textContent = "⚡ Re-Run Benchmark";
    }

    setTimeout(runDiagnostics, 500);
  </script>
</body>
</html>`;
}

// ============================================
// 2. DIRECT NODE CONSOLE (No Subscription Bloat)
// ============================================
function getConsolePage(host = "localhost", currentUUID = DEFAULT_UUID, currentTrojanPass = DEFAULT_TROJAN_PASS, currentWSPath = DEFAULT_WS_PATH, currentProxy = DEFAULT_PROXY_IP, nodes = null) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Galaxy-Tunnel | Direct VLESS & Trojan Nodes</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body, html {
      width: 100%; height: 100%;
      background: #02060d; overflow-x: hidden;
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      color: #e0f2fe;
    }
    .space-bg {
      position: fixed; width: 100%; height: 100%; top: 0; left: 0;
      background: 
        radial-gradient(circle at 50% 35%, rgba(10, 45, 80, 0.7) 0%, transparent 65%),
        radial-gradient(circle at 80% 80%, rgba(0, 150, 200, 0.15) 0%, transparent 50%),
        #02060d;
      z-index: 1;
    }
    .starfield {
      position: fixed; width: 100%; height: 100%; top: 0; left: 0;
      background-image: 
        radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 40px 70px, rgba(0,212,255,0.8), rgba(0,0,0,0)),
        radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)),
        radial-gradient(2px 2px at 160px 120px, rgba(0,212,255,0.9), rgba(0,0,0,0));
      background-repeat: repeat; background-size: 220px 220px;
      animation: starTwinkle 4s ease-in-out infinite alternate; opacity: 0.6;
      z-index: 2;
    }
    @keyframes starTwinkle {
      0% { opacity: 0.4; transform: scale(1); }
      100% { opacity: 0.8; transform: scale(1.02); }
    }
    .top-nav {
      position: relative; z-index: 20;
      width: 100%; max-width: 720px;
      display: flex; justify-content: space-between; align-items: center;
      margin-bottom: 8px;
    }
    .btn-lock {
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.4);
      color: #fca5a5;
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      transition: all 0.2s;
    }
    .btn-lock:hover {
      background: rgba(239, 68, 68, 0.3);
      color: #ffffff;
    }
    .main-container {
      position: relative; z-index: 10;
      min-height: 100vh;
      display: flex; flex-direction: column; justify-content: center; align-items: center;
      padding: 24px 16px;
      gap: 16px;
    }
    .config-panel {
      width: 100%; max-width: 720px;
      background: rgba(4, 14, 30, 0.88);
      border: 1px solid rgba(0, 212, 255, 0.4);
      border-radius: 12px;
      padding: 24px;
      backdrop-filter: blur(14px);
      box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    }
    .panel-header {
      display: flex; justify-content: space-between; align-items: center;
      border-bottom: 1px solid rgba(0, 212, 255, 0.2);
      padding-bottom: 14px; margin-bottom: 16px;
    }
    .panel-title {
      font-size: 18px; font-weight: 800; color: #38bdf8;
      display: flex; align-items: center; gap: 8px;
    }
    .tag {
      font-size: 11px; background: rgba(56, 189, 248, 0.2);
      color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-weight: normal;
    }
    .input-grid {
      display: grid; grid-template-columns: 1fr; gap: 12px;
      margin-bottom: 18px;
    }
    @media(min-width: 580px) {
      .input-grid { grid-template-columns: 1fr 1fr; }
      .input-full { grid-column: span 2; }
    }
    .input-group label {
      display: block; font-size: 12px; font-weight: 600; color: #94a3b8;
      margin-bottom: 4px;
    }
    .input-group input {
      width: 100%; background: #071527;
      border: 1px solid rgba(0, 212, 255, 0.3);
      padding: 8px 12px; border-radius: 6px; color: #ffffff;
      font-family: monospace; font-size: 13px; outline: none;
      transition: border-color 0.2s;
    }
    .input-group input:focus {
      border-color: #00e5ff; box-shadow: 0 0 8px rgba(0, 229, 255, 0.3);
    }
    .btn-row {
      display: flex; flex-wrap: wrap; gap: 8px; margin-bottom: 18px;
    }
    .btn {
      background: #0284c7; color: #ffffff;
      border: none; padding: 8px 14px; border-radius: 6px;
      font-size: 13px; font-weight: 700; cursor: pointer;
      display: inline-flex; align-items: center; gap: 6px;
      transition: all 0.2s;
    }
    .btn:hover { background: #0369a1; transform: translateY(-1px); }
    .btn-cyan { background: #00e5ff; color: #02060d; }
    .btn-cyan:hover { background: #38bdf8; }
    .btn-outline {
      background: transparent; border: 1px solid rgba(0, 212, 255, 0.4);
      color: #38bdf8;
    }
    .btn-outline:hover { background: rgba(0, 212, 255, 0.1); border-color: #00e5ff; }

    .protocol-section-title {
      font-size: 13px; font-weight: 800; color: #7dd3fc;
      text-transform: uppercase; letter-spacing: 1px;
      margin: 14px 0 8px 0; display: flex; align-items: center; gap: 6px;
    }
    .node-list {
      display: flex; flex-direction: column; gap: 10px;
    }
    .node-card {
      background: #06182c; border: 1px solid rgba(0, 212, 255, 0.2);
      border-radius: 8px; padding: 12px 14px;
      display: flex; justify-content: space-between; align-items: center; gap: 10px;
    }
    .node-notls {
      border-color: rgba(34, 197, 94, 0.35);
      background: #081d1e;
    }
    .node-trojan {
      border-color: rgba(245, 158, 11, 0.35);
      background: #151421;
    }
    .node-info { overflow: hidden; }
    .node-name { font-size: 13px; font-weight: 700; color: #f0f9ff; }
    .node-desc { font-size: 11px; color: #94a3b8; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 2px; }
    .copy-btn {
      flex-shrink: 0; background: rgba(0, 229, 255, 0.15); border: 1px solid rgba(0, 229, 255, 0.3);
      color: #00e5ff; padding: 6px 12px; border-radius: 4px; font-size: 12px; font-weight: 700;
      cursor: pointer;
    }
    .copy-btn:hover { background: #00e5ff; color: #02060d; }
    .copy-btn-notls {
      background: rgba(34, 197, 94, 0.15); border-color: rgba(34, 197, 94, 0.4);
      color: #4ade80;
    }
    .copy-btn-notls:hover { background: #22c55e; color: #02060d; }
    .copy-btn-trojan {
      background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.4);
      color: #fbbf24;
    }
    .copy-btn-trojan:hover { background: #f59e0b; color: #02060d; }
    .toast {
      position: fixed; bottom: 20px; right: 20px;
      background: #0284c7; color: #ffffff; padding: 10px 18px;
      border-radius: 6px; font-size: 14px; font-weight: bold;
      box-shadow: 0 4px 16px rgba(0,0,0,0.5); z-index: 999;
      opacity: 0; pointer-events: none; transition: opacity 0.3s;
    }
    .toast.show { opacity: 1; pointer-events: auto; }
  </style>
</head>
<body>
  <div class="space-bg"></div>
  <div class="starfield"></div>

  <div class="main-container">
    <div class="top-nav">
      <span style="font-size: 13px; color: #38bdf8; font-weight: 700; letter-spacing: 1px;">🌌 VLESS &amp; TROJAN DIRECT NODES</span>
      <button class="btn-lock" onclick="lockConsole()">🔒 Lock &amp; Return to Disguise</button>
    </div>

    <div class="config-panel">
      <div class="panel-header">
        <div class="panel-title">
          ⚡ Direct Configuration Nodes
          <span class="tag">TLS 443 | No-TLS 80, 8080</span>
        </div>
        <button class="btn btn-outline" onclick="generateRandomUUID()" title="Generate new UUID">🎲 New UUID</button>
      </div>

      <div class="input-grid">
        <div class="input-group input-full">
          <label>UUID (VLESS &amp; Trojan Master Identifier):</label>
          <input type="text" id="cfgUUID" value="${currentUUID}" oninput="updateConfigs()" placeholder="Enter your UUID or click 🎲 New UUID" />
        </div>
        <div class="input-group">
          <label>Trojan Custom Password (Optional / Defaults to UUID):</label>
          <input type="text" id="cfgTrojanPass" value="${currentTrojanPass || ""}" oninput="updateConfigs()" placeholder="Leave empty to use UUID" />
        </div>
        <div class="input-group">
          <label>WebSocket Path (WS_PATH):</label>
          <input type="text" id="cfgPath" value="${currentWSPath}" oninput="updateConfigs()" placeholder="galaxy-tunnel" />
        </div>
        <div class="input-group input-full">
          <label>Fallback / CDN Proxy IP:</label>
          <input type="text" id="cfgProxy" value="${currentProxy}" oninput="updateConfigs()" placeholder="cdn-b100.xn--b6gac.eu.org" />
        </div>
      </div>

      <!-- VLESS Section -->
      <div class="protocol-section-title">⚡ VLESS Protocol (TLS 443 &amp; Non-TLS 80 / 8080)</div>
      <div class="node-list">
        <div class="node-card">
          <div class="node-info">
            <div class="node-name">🔒 VLESS + TLS (Port 443 WS)</div>
            <div class="node-desc">Standard TLS 1.3 / Port 443 / SNI = Host</div>
          </div>
          <button class="copy-btn" onclick="copyNode('vlessTls443')">Copy Link</button>
        </div>

        <div class="node-card node-notls">
          <div class="node-info">
            <div class="node-name">🌐 VLESS + HTTP No-TLS (Port 80 WS)</div>
            <div class="node-desc">Standard Plain HTTP / Port 80 (Security: None)</div>
          </div>
          <button class="copy-btn copy-btn-notls" onclick="copyNode('vlessHttp80')">Copy Link</button>
        </div>

        <div class="node-card node-notls">
          <div class="node-info">
            <div class="node-name">🌐 VLESS + HTTP No-TLS (Port 8080 WS)</div>
            <div class="node-desc">Alternative HTTP Port 8080 (Cloudflare Allowed No-TLS)</div>
          </div>
          <button class="copy-btn copy-btn-notls" onclick="copyNode('vlessHttp8080')">Copy Link</button>
        </div>

        <div class="node-card">
          <div class="node-info">
            <div class="node-name">⚡ VLESS + ProxyIP (Port 443 WS)</div>
            <div class="node-desc">Routed through Clean CDN Proxy IP</div>
          </div>
          <button class="copy-btn" onclick="copyNode('vlessProxy')">Copy Link</button>
        </div>
      </div>

      <!-- Trojan Section -->
      <div class="protocol-section-title" style="margin-top: 18px;">🛡️ Trojan Protocol (Port 443 WS TLS)</div>
      <div class="node-list">
        <div class="node-card node-trojan">
          <div class="node-info">
            <div class="node-name">🛡️ Trojan + TLS (Port 443 WS)</div>
            <div class="node-desc">Trojan over WS TLS / SHA-224 Authenticated</div>
          </div>
          <button class="copy-btn copy-btn-trojan" onclick="copyNode('trojanTls443')">Copy Link</button>
        </div>
        <div class="node-card node-trojan">
          <div class="node-info">
            <div class="node-name">🛡️ Trojan + ProxyIP (Port 443 WS)</div>
            <div class="node-desc">Trojan via CDN Proxy IP</div>
          </div>
          <button class="copy-btn copy-btn-trojan" onclick="copyNode('trojanProxy')">Copy Link</button>
        </div>
      </div>
    </div>
  </div>

  <div id="toast" class="toast">Copied to clipboard!</div>

  <script>
    const currentHost = window.location.host || "${host}";
    let generatedLinks = {};

    function updateConfigs() {
      const uuid = (document.getElementById('cfgUUID').value || "${currentUUID}").trim();
      const customTrojan = (document.getElementById('cfgTrojanPass').value || "").trim();
      const trojanKey = customTrojan || uuid;
      const path = (document.getElementById('cfgPath').value || "${currentWSPath}").trim().replace(/^\\/+/, "");
      const proxy = (document.getElementById('cfgProxy').value || "${currentProxy}").trim();
      const cleanHost = currentHost.replace(/[^a-zA-Z0-9.-]/g, "");

      const vlessTls443 = "vless://" + uuid + "@" + currentHost + ":443?encryption=none&security=tls&sni=" + currentHost + "&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#VLESS-TLS-443%20(" + cleanHost + ")";
      const vlessHttp80 = "vless://" + uuid + "@" + currentHost + ":80?encryption=none&security=none&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#VLESS-NoTLS-80%20(" + cleanHost + ")";
      const vlessHttp8080 = "vless://" + uuid + "@" + currentHost + ":8080?encryption=none&security=none&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#VLESS-NoTLS-8080%20(" + cleanHost + ")";
      const vlessProxy = proxy ? "vless://" + uuid + "@" + proxy + ":443?encryption=none&security=tls&sni=" + currentHost + "&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#VLESS-ProxyIP%20(" + proxy + ")" : "";

      const trojanTls443 = "trojan://" + encodeURIComponent(trojanKey) + "@" + currentHost + ":443?security=tls&sni=" + currentHost + "&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#Trojan-TLS-443%20(" + cleanHost + ")";
      const trojanProxy = proxy ? "trojan://" + encodeURIComponent(trojanKey) + "@" + proxy + ":443?security=tls&sni=" + currentHost + "&type=ws&host=" + currentHost + "&path=%2F" + encodeURIComponent(path) + "%3Fed%3D2048#Trojan-ProxyIP%20(" + proxy + ")" : "";

      generatedLinks = {
        vlessTls443,
        vlessHttp80,
        vlessHttp8080,
        vlessProxy,
        trojanTls443,
        trojanProxy
      };
    }
    updateConfigs();

    function showToast(msg) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 2500);
    }

    function copyNode(type) {
      const uuid = (document.getElementById('cfgUUID').value || "").trim();
      if (!uuid) {
        showToast('⚠️ Please enter or generate a UUID first!');
        return;
      }
      if (generatedLinks[type]) {
        navigator.clipboard.writeText(generatedLinks[type]).then(() => {
          showToast('Copied node link!');
        });
      }
    }

    function generateRandomUUID() {
      const newUUID = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
        const r = Math.random() * 16 | 0;
        const v = c === 'x' ? r : (r & 0x3 | 0x8);
        return v.toString(16);
      });
      document.getElementById('cfgUUID').value = newUUID;
      updateConfigs();
      showToast('Generated new UUID!');
    }

    function lockConsole() {
      document.cookie = "galaxy_auth=0; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
      window.location.href = "/api/logout";
    }
  </script>
</body>
</html>`;
}

export default worker_default;
