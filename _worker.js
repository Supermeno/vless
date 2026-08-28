// _worker.js
import { connect } from "cloudflare:sockets";

// ============================================
// ENVIRONMENT VARIABLES & DEFAULTS
// Set UUID / TROJAN_PASS in Cloudflare Dashboard / wrangler.toml
// ============================================
var userID = "";                    // VLESS UUID (e.g. "d342d11e-d424-4583-b36e-524ab1f0afa4")
var trojanPass = "";              // Trojan Password

// Clean Fallback ProxyIP Pool (Cloudflare CDN / Clean IPs)
var defaultProxyIP = "cdn-b100.xn--b6gac.eu.org";

// Dynamic ProxyIP List from GitHub Raw URL
var githubProxyURL = "https://raw.githubusercontent.com/gprox-galaxy/Cloudflare-Galaxytunnel/refs/heads/main/PROXYIP.txt";

// Fast DoH Providers (Cloudflare & Google failover)
var dohURLs = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query"
];

// UUID Validator
function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

// SHA224 for Trojan Password Matching
function sha224(str) {
    function rightRotate(v, a) { return (v >>> a) | (v << (32 - a)); }
    const mathPow = Math.pow, maxWord = mathPow(2, 32);
    let result = '', words = [];
    const asciiBitLength = str.length * 8;
    let hash = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ];
    let s = str + '\x80';
    while (s.length % 64 - 56) s += '\x00';
    for (let i = 0; i < s.length; i++) {
        let j = s.charCodeAt(i);
        if (j >> 8) return null;
        words[i >> 2] |= j << ((3 - i) % 4) * 8;
    }
    words[words.length] = ((asciiBitLength / maxWord) | 0);
    words[words.length] = (asciiBitLength);
    for (let j = 0; j < words.length;) {
        const w = words.slice(j, j += 16);
        const oldHash = hash.slice(0);
        for (let i = 0; i < 64; i++) {
            if (i >= 16) {
                const w15 = w[i - 15], w2 = w[i - 2];
                w[i] = (w[i - 16] + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3)) + w[i - 7] + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))) | 0;
            }
            const a = hash[0], e = hash[4];
            const temp1 = (hash[7] + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)) + ((e & hash[5]) ^ (~e & hash[6])) + k[i] + w[i]);
            const temp2 = ((rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)) + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2])));
            hash = [(temp1 + temp2) | 0].concat(hash);
            hash[4] = (hash[4] + temp1) | 0;
            hash.pop();
        }
        for (let i = 0; i < 8; i++) hash[i] = (hash[i] + oldHash[i]) | 0;
    }
    for (let i = 0; i < 7; i++) {
        const hex = hash[i];
        result += ((hex >> 28) & 0xf).toString(16) + ((hex >> 24) & 0xf).toString(16) + ((hex >> 20) & 0xf).toString(16) + ((hex >> 16) & 0xf).toString(16) + ((hex >> 12) & 0xf).toString(16) + ((hex >> 8) & 0xf).toString(16) + ((hex >> 4) & 0xf).toString(16) + (hex & 0xf).toString(16);
    }
    return result;
}

// Fetch Random ProxyIP from GitHub
async function getDynamicProxyIP(fallbackProxy, rawUrl) {
    if (!rawUrl) return fallbackProxy;
    try {
        const response = await fetch(rawUrl, { cf: { cacheTtl: 300, cacheEverything: true } });
        if (response.ok) {
            const text = await response.text();
            const ipList = text.split('\n').map(l => l.trim()).filter(l => l.length > 0 && !l.startsWith('#'));
            if (ipList.length > 0) return ipList[Math.floor(Math.random() * ipList.length)];
        }
    } catch (e) {
        console.error("ProxyIP fetch error:", e);
    }
    return fallbackProxy;
}

// ============================================
// MAIN FETCH HANDLER
// ============================================
export default {
    async fetch(request, env, ctx) {
        userID = env.UUID || env.uuid || userID;
        trojanPass = env.TROJAN_PASS || env.trojan_pass || trojanPass;
        defaultProxyIP = env.PROXYIP || env.proxyip || defaultProxyIP;
        githubProxyURL = env.PROXY_LIST_URL || githubProxyURL;

        const upgradeHeader = request.headers.get("Upgrade");
        if (upgradeHeader === "websocket") {
            return await proxyOverWSHandler(request);
        }

        return new Response(`⚡ Galaxy Proxy Worker is Active!\nVLESS Status: ${isValidUUID(userID) ? "Ready" : "No UUID Set"}\nTrojan Status: ${trojanPass ? "Ready" : "No Password Set"}`, {
            status: 200,
            headers: { "Content-Type": "text/plain; charset=utf-8" }
        });
    }
};

// ============================================
// WEBSOCKET HANDLER
// ============================================
async function proxyOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (info) => console.log(`[${address}:${portWithRandomLog}] ${info}`);

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableStream.pipeTo(new WritableStream({
        async write(chunk) {
            if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const firstByte = new Uint8Array(chunk.slice(0, 1))[0];
            let result = null;

            if (firstByte === 0x00 && isValidUUID(userID)) {
                try { result = processVlessHeader(chunk, userID); } catch (e) { }
            }

            if ((!result || result.hasError) && trojanPass) {
                result = processTrojanHeader(chunk, trojanPass);
            }

            if (!result || result.hasError) {
                throw new Error("Invalid VLESS/Trojan authentication packet");
            }

            const { addressRemote = "", portRemote = 443, rawDataIndex, responseHeader, isUDP } = result;
            address = addressRemote;
            portWithRandomLog = `${portRemote} ${isUDP ? "UDP" : "TCP"}`;

            if (isUDP && portRemote === 53) isDns = true;

            const rawClientData = chunk.slice(rawDataIndex);

            if (isDns) {
                const { write } = await handleUDPOutBound(webSocket, responseHeader, log);
                udpStreamWrite = write;
                udpStreamWrite(rawClientData);
                return;
            }

            handleTCPOutBound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log);
        },
        close() { log("WebSocket closed"); },
        abort(r) { log("WebSocket aborted: " + JSON.stringify(r)); }
    })).catch((e) => log("WebSocket stream error: " + e));

    return new Response(null, { status: 101, webSocket: client });
}

// TCP Connections
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
    async function connectAndWrite(addr, port) {
        const cleanAddr = addr.replace(/^\[|\]$/g, '');
        const tcpSocket = connect({ hostname: cleanAddr, port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        const activeProxy = await getDynamicProxyIP(defaultProxyIP, githubProxyURL);
        log(`Retrying via ProxyIP: ${activeProxy}`);
        const tcpSocket = await connectAndWrite(activeProxy, portRemote);
        tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
        remoteSocketToWS(tcpSocket, webSocket, null, log);
    }

    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
    } catch (e) {
        await retry();
    }
}

// Parsers & Helpers
function processVlessHeader(vlessBuffer, validUuid) {
    if (vlessBuffer.byteLength < 24) return { hasError: true, message: "Too short" };
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);
    
    if (slicedBufferString !== validUuid) return { hasError: true, message: "Invalid UUID" };

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
    const isUDP = command === 2;

    const portIndex = 18 + optLength + 1;
    const portRemote = new DataView(vlessBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressType = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1))[0];

    let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";
    if (addressType === 1) {
        addressLength = 4;
        addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
    } else if (addressType === 2) {
        addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
        addressValueIndex += 1;
        addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
    } else if (addressType === 3) {
        addressLength = 16;
        const dv = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        const ipv6 = [];
        for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
        addressValue = ipv6.join(":");
    }

    return {
        hasError: false, addressRemote: addressValue, portRemote,
        rawDataIndex: addressValueIndex + addressLength, responseHeader: new Uint8Array([version[0], 0]), isUDP
    };
}

function processTrojanHeader(trojanBuffer, password) {
    if (trojanBuffer.byteLength < 58) return { hasError: true };
    const bytes = new Uint8Array(trojanBuffer);
    const receivedHash = new TextDecoder().decode(bytes.slice(0, 56));
    if (receivedHash !== sha224(password)) return { hasError: true };

    const command = bytes[58];
    const addressType = bytes[59];
    let addressValue = "", addressLength = 0, addressValueIndex = 60;

    if (addressType === 0x01) {
        addressLength = 4;
        addressValue = Array.from(bytes.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
    } else if (addressType === 0x03) {
        addressLength = bytes[60];
        addressValueIndex = 61;
        addressValue = new TextDecoder().decode(bytes.slice(addressValueIndex, addressValueIndex + addressLength));
    }

    const portIndex = addressValueIndex + addressLength;
    const portRemote = new DataView(trojanBuffer).getUint16(portIndex);
    return {
        hasError: false, addressRemote: addressValue, portRemote,
        rawDataIndex: portIndex + 4, responseHeader: new Uint8Array(0), isUDP: command === 0x03
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
    let header = responseHeader;
    let hasData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk) {
            hasData = true;
            if (webSocket.readyState !== 1) return;
            if (header && header.byteLength > 0) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else {
                webSocket.send(chunk);
            }
        }
    })).catch(() => safeCloseWebSocket(webSocket));

    if (!hasData && retry) await retry();
}

function makeReadableWebSocketStream(ws, earlyDataHeader, log) {
    return new ReadableStream({
        start(controller) {
            ws.addEventListener("message", (e) => controller.enqueue(e.data));
            ws.addEventListener("close", () => { safeCloseWebSocket(ws); controller.close(); });
            ws.addEventListener("error", (e) => controller.error(e));
            const { earlyData } = base64ToArrayBuffer(earlyDataHeader);
            if (earlyData) controller.enqueue(earlyData);
        }
    });
}

function base64ToArrayBuffer(b64) {
    if (!b64) return { earlyData: null };
    try {
        const bin = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
        return { earlyData: Uint8Array.from(bin, c => c.charCodeAt(0)).buffer };
    } catch { return { earlyData: null }; }
}

var byteToHex = Array.from({ length: 256 }, (_, i) => (i + 256).toString(16).slice(1));
function stringify(arr) {
    return (byteToHex[arr[0]] + byteToHex[arr[1]] + byteToHex[arr[2]] + byteToHex[arr[3]] + "-" +
        byteToHex[arr[4]] + byteToHex[arr[5]] + "-" + byteToHex[arr[6]] + byteToHex[arr[7]] + "-" +
        byteToHex[arr[8]] + byteToHex[arr[9]] + "-" + byteToHex[arr[10]] + byteToHex[arr[11]] +
        byteToHex[arr[12]] + byteToHex[arr[13]] + byteToHex[arr[14]] + byteToHex[arr[15]]).toLowerCase();
}

function safeCloseWebSocket(ws) {
    try { if (ws.readyState === 1 || ws.readyState === 2) ws.close(); } catch {}
}

async function handleUDPOutBound(webSocket, responseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let i = 0; i < chunk.byteLength;) {
                const len = new DataView(chunk.slice(i, i + 2)).getUint16(0);
                controller.enqueue(new Uint8Array(chunk.slice(i + 2, i + 2 + len)));
                i += 2 + len;
            }
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            for (const url of dohURLs) {
                try {
                    const resp = await fetch(url, { method: "POST", headers: { "content-type": "application/dns-message" }, body: chunk });
                    const dnsResult = await resp.arrayBuffer();
                    const udpSizeBuffer = new Uint8Array([dnsResult.byteLength >> 8 & 255, dnsResult.byteLength & 255]);
                    if (webSocket.readyState === 1) {
                        webSocket.send(isHeaderSent ? await new Blob([udpSizeBuffer, dnsResult]).arrayBuffer() : await new Blob([responseHeader, udpSizeBuffer, dnsResult]).arrayBuffer());
                        isHeaderSent = true;
                        return;
                    }
                } catch {}
            }
        }
    }));

    const writer = transformStream.writable.getWriter();
    return { write: (c) => writer.write(c) };
            }
