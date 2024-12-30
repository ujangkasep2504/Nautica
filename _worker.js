import { connect } from "cloudflare:sockets";

// Variables
const rootDomain = "foolvpn.me"; // Ganti dengan domain utama kalian
const serviceName = "nautica"; // Ganti dengan nama workers kalian
const apiKey = ""; // Ganti dengan Global API key kalian (https://dash.cloudflare.com/profile/api-tokens)
const apiEmail = ""; // Ganti dengan email yang kalian gunakan
const accountID = ""; // Ganti dengan Account ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
const zoneID = ""; // Ganti dengan Zone ID kalian (https://dash.cloudflare.com -> Klik domain yang kalian gunakan)
let isApiReady = false;
let proxyIP = "";
let cachedProxyList = [];

// Constant
const PROXY_HEALTH_CHECK_API = "https://p01--boiling-frame--kw6dd7bjv2nr.code.run/check";
const PROXY_PER_PAGE = 24;
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

async function getProxyList(proxyBankUrl) {
  /**
   * Format:
   *
   * <IP>,<Port>,<Country ID>,<ORG>
   * Contoh:
   * 1.1.1.1,443,SG,Cloudflare Inc.
   */
  if (!proxyBankUrl) {
    throw new Error("No Proxy Bank URL Provided!");
  }

  const proxyBank = await fetch(proxyBankUrl);
  if (proxyBank.status == 200) {
    const text = (await proxyBank.text()) || "";

    const proxyString = text.split("\n").filter(Boolean);
    cachedProxyList = proxyString
      .map((entry) => {
        const [proxyIP, proxyPort, country, org] = entry.split(",");
        return {
          proxyIP: proxyIP || "Unknown",
          proxyPort: proxyPort || "Unknown",
          country: country || "Unknown",
          org: org || "Unknown Org",
        };
      })
      .filter(Boolean);
  }

  return cachedProxyList;
}

async function reverseProxy(request, target) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk.toString() || "443";

  const modifiedRequest = new Request(targetUrl, request);

  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

function getAllConfig(request, hostName, proxyList, page = 0) {
  const startIndex = PROXY_PER_PAGE * page;

  try {
    const uuid = crypto.randomUUID();
    const ports = [443, 80];
    const protocols = ["trojan", "vless", "ss"];

    // Build URI
    const uri = new URL(`trojan://${hostName}`);
    uri.searchParams.set("encryption", "none");
    uri.searchParams.set("type", "ws");
    uri.searchParams.set("host", hostName);

    // Build HTML
    const document = new Document(request);
    document.setTitle("Welcome to <span class='text-blue-500 font-semibold'>Nautica</span>");
    document.addInfo(`Total: ${proxyList.length}`);
    document.addInfo(`Page: ${page}/${Math.floor(proxyList.length / PROXY_PER_PAGE)}`);

    for (let i = startIndex; i < startIndex + PROXY_PER_PAGE; i++) {
      const proxy = proxyList[i];
      if (!proxy) break;

      const { proxyIP, proxyPort, country, org } = proxy;

      uri.searchParams.set("path", `/${proxyIP}-${proxyPort}`);
      uri.hash = `${country} ${org}`;

      const proxies = [];
      for (const port of ports) {
        uri.port = port.toString();
        for (const protocol of protocols) {
          // Special exceptions
          if (protocol === "ss") {
            uri.username = btoa(`none:${uuid}`);
          } else {
            uri.username = uuid;
          }

          uri.protocol = protocol;
          uri.searchParams.set("security", port == 443 ? "tls" : "none");
          uri.searchParams.set("sni", port == 80 && protocol == "vless" ? "" : hostName);

          // Build VPN URI
          proxies.push(uri.toString());
        }
      }
      document.registerProxies(
        {
          proxyIP,
          proxyPort,
          country,
          org,
        },
        proxies
      );
    }

    // Build pagination
    document.addPageButton("Prev", `/sub/${page > 0 ? page - 1 : 0}`, page > 0 ? false : true);
    document.addPageButton("Next", `/sub/${page + 1}`, page < Math.floor(proxyList.length / 10) ? false : true);

    return document.build();
  } catch (error) {
    return `An error occurred while generating the VLESS configurations. ${error}`;
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      const upgradeHeader = request.headers.get("Upgrade");

      // Gateway check
      if (apiKey && apiEmail && accountID && zoneID) {
        isApiReady = true;
      }

      // Handle proxy client
      if (upgradeHeader === "websocket") {
        const proxyMatch = url.pathname.match(/^\/(.+[:=-]\d+)$/);

        if (proxyMatch) {
          proxyIP = proxyMatch[1];
          return await websockerHandler(request);
        }
      }

      if (url.pathname.startsWith("/sub")) {
        const page = url.pathname.match(/^\/sub\/(\d+)$/);
        const pageIndex = parseInt(page ? page[1] : "0");
        const hostname = request.headers.get("Host");

        // Queries
        const countrySelect = url.searchParams.get("cc")?.split(",");
        const proxyBankUrl = url.searchParams.get("proxy-list") || env.PROXY_BANK_URL;
        let proxyList = (await getProxyList(proxyBankUrl)).filter((proxy) => {
          // Filter proxies by Country
          if (countrySelect) {
            return countrySelect.includes(proxy.country);
          }

          return true;
        });

        const result = getAllConfig(request, hostname, proxyList, pageIndex);
        return new Response(result, {
          status: 200,
          headers: { "Content-Type": "text/html;charset=utf-8" },
        });
      } else if (url.pathname.startsWith("/check")) {
        const target = url.searchParams.get("target").split(":");
        const tls = url.searchParams.get("tls");
        const result = await checkProxyHealth(target[0], target[1] || "443", tls);

        return new Response(JSON.stringify(result), {
          status: 200,
          headers: {
            ...CORS_HEADER_OPTIONS,
            "Content-Type": "application/json",
          },
        });
      } else if (url.pathname.startsWith("/api/v1")) {
        const apiPath = url.pathname.replace("/api/v1", "");

        if (!isApiReady) {
          return new Response("Api not ready", {
            status: 500,
          });
        }

        if (apiPath.startsWith("/domains")) {
          const wildcardApiPath = apiPath.replace("/domains", "");
          const cloudflareApi = new CloudflareApi();

          if (wildcardApiPath == "/get") {
            const domains = await cloudflareApi.getDomainList();
            return new Response(JSON.stringify(domains), {
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          } else if (wildcardApiPath == "/put") {
            const domain = url.searchParams.get("domain");
            const register = await cloudflareApi.registerDomain(domain);

            return new Response(register.toString(), {
              status: register,
              headers: {
                ...CORS_HEADER_OPTIONS,
              },
            });
          }
        }
      }

      const targetReverseProxy = env.REVERSE_PROXY_TARGET || "example.com";
      return await reverseProxy(request, targetReverseProxy);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: {
          ...CORS_HEADER_OPTIONS,
        },
      });
    }
  },
};

async function websockerHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === "Trojan") {
            protocolHeader = parseTrojanHeader(chunk);
          } else if (protocol === "VLESS") {
            protocolHeader = parseVlessHeader(chunk);
          } else if (protocol === "Shadowsocks") {
            protocolHeader = parseShadowsocksHeader(chunk);
          } else {
            parseVmessHeader(chunk);
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
            } else {
              throw new Error("UDP only support for DNS port 53");
            }
          }

          if (isDNS) {
            const { write } = await handleUDPOutbound(webSocket, protocolHeader.version, log);
            udpStreamWrite = write;
            udpStreamWrite(protocolHeader.rawClientData);
            return;
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const trojanDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (trojanDelimiter[0] === 0x0d && trojanDelimiter[1] === 0x0a) {
      if (trojanDelimiter[2] === 0x01 || trojanDelimiter[2] === 0x03 || trojanDelimiter[2] === 0x7f) {
        if (trojanDelimiter[3] === 0x01 || trojanDelimiter[3] === 0x03 || trojanDelimiter[3] === 0x04) {
          return "Trojan";
        }
      }
    }
  }

  const vlessDelimiter = new Uint8Array(buffer.slice(1, 17));
  // Hanya mendukung UUID v4
  if (arrayBufferToHex(vlessDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return "VLESS";
  }

  return "Shadowsocks"; // default
}

async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();

    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = await connectAndWrite(
      proxyIP.split(/[:=-]/)[0] || addressRemote,
      proxyIP.split(/[:=-]/)[1] || portRemote
    );
    tcpSocket.closed
      .catch((error) => {
        console.log("retry tcpSocket closed error", error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);

  remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
}

async function handleUDPOutbound(webSocket, responseHeader, log) {
  let isVlessHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });
  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch("https://1.1.1.1/dns-query", {
            method: "POST",
            headers: {
              "content-type": "application/dns-message",
            },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            log(`doh success and dns message length is ${udpSize}`);
            if (isVlessHeaderSent) {
              webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
            } else {
              webSocket.send(await new Blob([responseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              isVlessHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {
      log("dns udp has error" + error);
    });

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function parseVmessHeader(vmessBuffer) {
  // https://xtls.github.io/development/protocols/vmess.html#%E6%8C%87%E4%BB%A4%E9%83%A8%E5%88%86
}

function parseShadowsocksHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for Shadowsocks: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function parseVlessHeader(vlessBuffer) {
  const version = new Uint8Array(vlessBuffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];

  const cmd = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2: // For Domain
      addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3: // For IPv6
      addressLength = 16;
      const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: vlessBuffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function parseTrojanHeader(buffer) {
  const socks5DataBuffer = buffer.slice(58);
  if (socks5DataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid SOCKS5 request data",
    };
  }

  let isUDP = false;
  const view = new DataView(socks5DataBuffer);
  const cmd = view.getUint8(0);
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  switch (addressType) {
    case 1: // For IPv4
      addressLength = 4;
      addressValue = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(
        "."
      );
      break;
    case 3: // For Domain
      addressLength = new Uint8Array(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 4: // For IPv6
      addressLength = 16;
      const dataView = new DataView(socks5DataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: socks5DataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection!.readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) {
    log(`retry`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

async function checkProxyHealth(proxyIP, proxyPort, tls) {
  const req = await fetch(
    `${PROXY_HEALTH_CHECK_API}?ip=${proxyIP}&port=${proxyPort}&host=speed.cloudflare.com&tls=${tls}`
  );
  return await req.json();
}

// Helpers
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

async function generateHashFromText(text) {
  const msgUint8 = new TextEncoder().encode(text); // encode as (utf-8) Uint8Array
  const hashBuffer = await crypto.subtle.digest("MD5", msgUint8); // hash the message
  const hashArray = Array.from(new Uint8Array(hashBuffer)); // convert buffer to byte array
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join(""); // convert bytes to hex string

  return hashHex;
}

function getFlagEmoji(isoCode) {
  const codePoints = isoCode
    .toUpperCase()
    .split("")
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

// CloudflareApi Class
class CloudflareApi {
  constructor() {
    this.bearer = `Bearer ${apiKey}`;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.apiKey = apiKey;

    this.headers = {
      Authorization: this.bearer,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
    };
  }

  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      headers: {
        ...this.headers,
      },
    });

    if (res.status == 200) {
      const respJson = await res.json();

      return respJson.result.filter((data) => data.service == serviceName).map((data) => data.hostname);
    }

    return [];
  }

  async registerDomain(domain) {
    domain = domain.toLowerCase();
    const registeredDomains = await this.getDomainList();

    if (!domain.endsWith(rootDomain)) return 400;
    if (registeredDomains.includes(domain)) return 409;

    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, {
      method: "PUT",
      body: JSON.stringify({
        environment: "production",
        hostname: domain,
        service: serviceName,
        zone_id: this.zoneID,
      }),
      headers: {
        ...this.headers,
      },
    });

    return res.status;
  }
}

// HTML page base
/**
 * Cloudflare worker gak support DOM API, tetapi mereka menggunakan HTML Rewriter.
 * Tapi, karena kelihatannta repot kalo pake HTML Rewriter. Kita pake cara konfensional saja...
 */
let baseHTML = `
  
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FREE | CF | LIFETIME | BMKG.XYZ</title>
    <meta name="description" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta name="keywords" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta name="author" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta name="robots" content="FREE | CF | LIFETIME | BMKG.XYZ">

    <!-- Open Graph Meta Tags untuk SEO Media Sosial -->
    <meta property="og:title" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta property="og:description" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta property="og:image" content="https://png.pngtree.com/background/20231016/original/pngtree-high-definition-3d-wallpaper-in-black-and-red-picture-image_5583707.jpg"> <!-- Ganti dengan URL gambar yang sesuai -->
    <meta property="og:url" content="https://png.pngtree.com/background/20231016/original/pngtree-high-definition-3d-wallpaper-in-black-and-red-picture-image_5583707.jpg">
    <meta property="og:type" content="website">

    <!-- Twitter Card Meta Tags -->
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta name="twitter:description" content="FREE | CF | LIFETIME | BMKG.XYZ">
    <meta name="twitter:image" content="https://png.pngtree.com/background/20231016/original/pngtree-high-definition-3d-wallpaper-in-black-and-red-picture-image_5583707.jpg"> <!-- Ganti dengan URL gambar yang sesuai -->
    <link href="https://png.pngtree.com/background/20231016/original/pngtree-high-definition-3d-wallpaper-in-black-and-red-picture-image_5583707.jpg" rel="icon" type="image/png">
    <link href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flag-icon-css/css/flag-icon.min.css">

  <style>
 
    




#link-sub {
    border: 2px solid #007bff; /* Warna biru */
    border-radius: 5px; /* Opsional: Membuat sudut melengkung */
    padding: 10px; /* Opsional: Memberi jarak dalam input */
    background-color: #f9f9f9; /* Opsional: Warna latar belakang */
    color: #333; /* Opsional: Warna teks */
    width: 100%; /* Opsional: Menyesuaikan lebar */
    box-sizing: border-box; /* Opsional: Memastikan padding tidak menambah ukuran total */
}

#link-sub:focus {
    border-color: #0056b3; /* Warna saat input terfokus */
    outline: none; /* Menghapus garis luar bawaan browser */
}

body {
      background-color: #000; /* Hitam pekat (dark mode) */
      color: #4CAF50; /* Teks hijau agar kontras dengan background */
      margin: 0;
      font-family: Arial, sans-serif; /* Font sederhana dan bersih */
    }
.flag-icon {
    position: relative; /* Pastikan posisinya tidak fixed atau absolute */
    z-index: 1; /* Memberi prioritas lebih rendah daripada header */
}
    h1 {
      color: black;
            text-align: center;
            font-size: 8vw;
            font-weight: bold;
            text-shadow: 
                0 0 5px rgba(0, 123, 255, 0.8),
                0 0 10px rgba(0, 123, 255, 0.8),
                0 0 20px rgba(0, 123, 255, 0.8),
                0 0 30px rgba(0, 123, 255, 0.8),
                0 0 40px rgba(0, 123, 255, 0.8);
    }
    h2 {
      color: black;
            text-align: center;
            font-size: 4vw;
            font-weight: bold;
            text-shadow: 
                0 0 5px rgba(0, 123, 255, 0.8),
                0 0 10px rgba(0, 123, 255, 0.8),
                0 0 20px rgba(0, 123, 255, 0.8),
                0 0 30px rgba(0, 123, 255, 0.8),
                0 0 40px rgba(0, 123, 255, 0.8);
    }
    header, footer {
      box-sizing: border-box; /* Pastikan padding dihitung dalam lebar elemen */
      background-color: ;
      color: white;
      text-align: center;
      border: 0px solid rgba(143, 0, 0, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      padding: 0 20px;
      position: fixed;
      width: 100%;
      left: 0;
      right: 2px;
      pointer-events: none;
      z-index: 10;
    }

    header {
      top: 0;
    }

    footer {
      bottom: 0;
    }
   .service-selector {
        width: 100%;
        padding: 10px;
        font-size: 16px;
        border: 2px solid #4CAF50; /* Border warna hijau */
        border-radius: 5px; /* Sudut membulat */
        background-color: #f9f9f9; /* Warna latar belakang */
        color: #333; /* Warna teks */
        transition: background-color 0.3s, border-color 0.3s;
    }

    .service-selector:hover {
        background-color: #e0f7fa; /* Warna latar belakang saat hover */
        border-color: #00796b; /* Warna border saat hover */
    }

    .service-selector option {
        padding: 10px;
    }  
    .container, .content {
      
      flex: 1;
      padding-top: 80px; /* To avoid content being hidden under the header */
      padding-bottom: 50px;
      margin-top: 80px;
      margin-bottom: 50px;/* To avoid content being hidden under the footer */
      padding-left: 10px;
      padding-right: 10px;
      display: flex;
      flex-direction: column;
      max-width: 960px;
      align-items: center;
    /* overflow: hidden;*/
    }
.contentd {
  padding: 60px 20px 40px; /* Memberikan ruang untuk header dan footer */
  height: 100%;
  overflow-y: auto;
}
    .filters {
      display: flex;
      justify-content: space-between;
      width: 80%;
      margin-bottom: 20px;
    }
.filters > div,
.button {
  margin-right: 20px;
}
    .filter-label {
      margin-right: 10px;
    }

    /* Memberikan sudut melengkung pada tabel */
    table {
      
      border-collapse: separate;
      border-spacing: 0;
      border: 0px solid rgba(26, 4, 83, 0.81); /* Warna border hijau */
      border-radius: 10px; /* Sudut melengkung */
      overflow: hidden;
      width: 100%; /* Membuat tabel lebar penuh */
    }

    /* Membungkus tabel dalam elemen scroll */
    .table-container {
    width: 100%;
    overflow-x: auto; /* Mengaktifkan scroll horizontal */
    margin-bottom: 0px;
    border: 1px solid rgba(143, 0, 0, 0.89); /* Border dengan warna abu-abu */
    border-radius: 10px; /* Membuat sudut melengkung */
    padding: 0px; /* Memberi jarak antara border dan konten */
    background-color: ; /* Warna latar belakang */
}


thhhh {
    background-color: rgba(26, 4, 83, 0.81); /* Warna latar belakang */
    color: white; /* Warna teks putih */
    font-weight: bold;
    padding: 10px;
    text-align: center;
    position: sticky; /* Menempelkan elemen saat digulir */
    top: 0; /* Menempel di bagian atas tabel */
    z-index: 1; /* Memberikan prioritas tampilan lebih tinggi */
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1); /* Bayangan untuk efek */
}
    th {
      background-color: rgba(26, 4, 83, 0.81); /* Warna hijau */
      color: white; /* Warna teks putih */
      font-weight: bold;
      padding: 10px;
      text-align: center;
    }
    #total-proxy {
      margin: 20px 0; /* 20px atas dan bawah, 0px kiri dan kanan */
      text-align: center;
    }
    td {
      padding: 10px;
      text-align: center;
      background-color: rgba(26, 4, 83, 0.81); /* Warna hijau transparan */
      color: #fff; /* Warna teks */
      border-bottom: 1px solid #ddd; /* Garis pembatas antar baris */
      transition: background-color 0.3s ease; /* Efek transisi */
    }

    td:hover {
      background-color: rgba(0, 19, 46, 0.86); /* Warna hijau lebih gelap saat dihover */
    }

    tr:nth-child(odd) td {
      background-color: rgba(0, 45, 70, 0.81); /* Warna abu terang */
    }

    tr:hover td {
      background-color: rgba(0, 0, 0, 0.38); /* Warna latar biru muda saat baris dihover */
      color: #fff; /* Warna teks saat dihover */
    }

    .copy-vless, .cekproxy, .copy-vless1, .copy-trojan, .copy-ss {
      margin: 5px;
      padding: 5px 10px;
      border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      background-color: #007bff;
      color: #fff;
      cursor: pointer;
    }

    .copy-vless:hover, .cekproxy:hover, .copy-vless1:hover, .copy-trojan:hover, .copy-ss:hover {
      background-color: #0069d9;
    }

    .copy-vless-clash, .copy-vless2, .copy-trojan-clash, .copy-ss1 {
      margin: 5px;
      padding: 5px 10px;
      border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      background-color: #4CAF50;
      color: #fff;
      cursor: pointer;
    }

    .copy-vless-clash:hover, .copy-vless2:hover, .copy-trojan-clash:hover, .copy-ss1:hover {
      background-color: #4CAF50;
    }

    .pagination {
      text-align: center;
    }

    .pagination button {
      margin: 5px;
      padding: 12px 12px;
      border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      background-color: rgba(0, 3, 63, 0.84);
      color: #fff;
      cursor: pointer;
    }

    .pagination button:hover {
      background-color: rgba(50, 0, 63, 0.84);
    }

    .pagination .active {
      background-color: rgba(0, 15, 123, 0.78);
    }

    #search-bar, #items-per-page {
      padding: 10px;
      width: 150px;
      max-width: 100px;
      border: 2px solid #4CAF50;
      border-radius: 5px; 
    }

    /* Responsif */
    @media (max-width: 100%) {
      header, footer {
        padding: 0%;
      }

      table {
        width: 100%;
        margin-bottom: 10px;
      }

      #search-bar, #items-per-page {
        width: 60px;
        max-width: none;
        margin-bottom: 10px;
        border-radius: 5px; 
      }

      .pagination button {
        padding: 12px;
        font-size: 18px;
      }

      .copy-vless, .copy-vless1, .copy-trojan, .copy-ss {
        padding: 4px 8px;
        border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
        border-radius: 10px;
        font-size: 12px;
      }
    }
     
    
                .popup {
      display: none; /* Hidden by default */
      position: fixed;
      left: 0;
      top: 0;
      width: 100%;
      height: 100%;
      border: 0px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      background-color: rgba(0, 0, 0, 0.5);
      justify-content: center;
      align-items: center;
      z-index: 100;
    }
  .button {
      margin: 10px;
      padding: 10px 10px;
      border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      border-radius: 5px;
      background-color: rgba(255, 0, 0, 0.86);
      color: #fff;
      cursor: pointer;
    }
    
    .popup-content {
      background-color: rgba(0, 3, 63, 0.84);
      padding: 20px;
      border: 1px solid rgba(197, 51, 6, 0.89); /* Border dengan warna abu-abu */
      border-radius: 10px;
      text-align: center;
      z-index: 101;
    }
    .popup button {
      margin: 10px;
      padding: 10px 10px;
      border: 1px solid rgba(197, 51, 6, 0.89); 
      border-radius: 5px;
      background-color: rgba(255, 0, 0, 0.86);
      color: #fff;
      cursor: pointer;
      
    }
    .button1 {
      padding: 10px;
      background-color: rgba(255, 0, 0, 0.86);
      color: white;
      border: none;
      cursor: pointer;
      
    }
    .popup button:hover {
      background-color: rgba(255, 108, 0, 0.86);
    }
.highlight-text {
    color: #007bff; /* Warna biru */
    font-size: 18px; /* Ukuran teks */
}
  </style>
</head>
<body>
  <header>
  <h1>FREE PROXY CF BMKG.XYZ</h1>
    </header>
  <main class="content">
    <center><button class="button" onclick="showPopup()">SHOW LINK SUB</button></center>

    <div class="filters">
      <div>
        <span class="filter-label">Item Page:</span>
        <select id="items-per-page">
          <option value="10">10 Baris</option>
          <option value="25">25 Baris</option>
          <option value="50">50 Baris</option>
          <option value="100">100 Baris</option>
        </select>
      </div>
      <div>
        <span class="filter-label">Search:</span>
        <input type="text" id="search-bar" placeholder="Cari Isp, Country Code">
      </div></div>
      <div class="table-container">
    <table>
      <thead>
        <tr>          
          <th>ISP | COUNTRY</th>
          <th>Status</th>
          <th>WILDCARD</th>
          <th>Vless 443</th>
          <th>Vless 80</th>
          <th>Trojan</th>
          <th>Shadowsock</th>
        </tr>
      </thead>
      <tbody id="proxy-list"></tbody>  
    </table>
        </div>
    <div class="total-proxy" id="total-proxy"></div>
    <div class="pagination" id="pagination"></div>
  </div> 
<div class="popup" id="myPopup">
<div class="popup-content">
<div class="row"><hr/><span class="highlight-text">LINK SUB GENERATE</span><hr/>
     <div class="col">
      <label for="service-type">TYPE</label>
      <select class="service-selector" id="service-type">
        <option value="vless">VLESS</option>
        <option value="trojan">TROJAN</option>
        <option value="ss">SS</option>
      </select>
    </div>
    <div class="col">
      <label for="country-code">COUNTRY</label>
      <select class="service-selector" id="country-code">
     <option value="ID">Indonesia</option>
    <option value="SG">Singapore</option>
    <option value="US">United States</option>
    <option value="AF">Afghanistan</option>
    <option value="AL">Albania</option>
    <option value="DZ">Algeria</option>
    <option value="AS">American Samoa</option>
    <option value="AD">Andorra</option>
    <option value="AO">Angola</option>
    <option value="AI">Anguilla</option>
    <option value="AR">Argentina</option>
    <option value="AM">Armenia</option>
    <option value="AW">Aruba</option>
    <option value="AU">Australia</option>
    <option value="AT">Austria</option>
    <option value="AZ">Azerbaijan</option>
    <option value="BS">Bahamas</option>
    <option value="BH">Bahrain</option>
    <option value="BD">Bangladesh</option>
    <option value="BB">Barbados</option>
    <option value="BY">Belarus</option>
    <option value="BE">Belgium</option>
    <option value="BZ">Belize</option>
    <option value="BJ">Benin</option>
    <option value="BM">Bermuda</option>
    <option value="BT">Bhutan</option>
    <option value="BO">Bolivia</option>
    <option value="BA">Bosnia and Herzegovina</option>
    <option value="BW">Botswana</option>
    <option value="BR">Brazil</option>
    <option value="IO">British Indian Ocean Territory</option>
    <option value="BN">Brunei Darussalam</option>
    <option value="BG">Bulgaria</option>
    <option value="BF">Burkina Faso</option>
    <option value="BI">Burundi</option>
    <option value="KH">Cambodia</option>
    <option value="CM">Cameroon</option>
    <option value="CA">Canada</option>
    <option value="CV">Cape Verde</option>
    <option value="KY">Cayman Islands</option>
    <option value="CF">Central African Republic</option>
    <option value="TD">Chad</option>
    <option value="CL">Chile</option>
    <option value="CN">China</option>
    <option value="CX">Christmas Island</option>
    <option value="CC">Cocos (Keeling) Islands</option>
    <option value="CO">Colombia</option>
    <option value="KM">Comoros</option>
    <option value="CG">Congo</option>
    <option value="CD">Congo (Democratic Republic)</option>
    <option value="CK">Cook Islands</option>
    <option value="CR">Costa Rica</option>
    <option value="HR">Croatia</option>
    <option value="CU">Cuba</option>
    <option value="CY">Cyprus</option>
    <option value="CZ">Czech Republic</option>
    <option value="CI">Côte d'Ivoire</option>
    <option value="DK">Denmark</option>
    <option value="DJ">Djibouti</option>
    <option value="DM">Dominica</option>
    <option value="DO">Dominican Republic</option>
    <option value="EC">Ecuador</option>
    <option value="EG">Egypt</option>
    <option value="SV">El Salvador</option>
    <option value="GQ">Equatorial Guinea</option>
    <option value="ER">Eritrea</option>
    <option value="EE">Estonia</option>
    <option value="ET">Ethiopia</option>
    <option value="FK">Falkland Islands</option>
    <option value="FO">Faroe Islands</option>
    <option value="FJ">Fiji</option>
    <option value="FI">Finland</option>
    <option value="FR">France</option>
    <option value="GF">French Guiana</option>
    <option value="PF">French Polynesia</option>
    <option value="TF">French Southern Territories</option>
    <option value="GA">Gabon</option>
    <option value="GM">Gambia</option>
    <option value="GE">Georgia</option>
    <option value="DE">Germany</option>
    <option value="GH">Ghana</option>
    <option value="GI">Gibraltar</option>
    <option value="GR">Greece</option>
    <option value="GL">Greenland</option>
    <option value="GD">Grenada</option>
    <option value="GP">Guadeloupe</option>
    <option value="GU">Guam</option>
    <option value="GT">Guatemala</option>
    <option value="GG">Guernsey</option>
    <option value="GN">Guinea</option>
    <option value="GW">Guinea-Bissau</option>
    <option value="GY">Guyana</option>
    <option value="HT">Haiti</option>
    <option value="HN">Honduras</option>
    <option value="HK">Hong Kong</option>
    <option value="HU">Hungary</option>
    <option value="IS">Iceland</option>
    <option value="IN">India</option>
    <option value="ID">Indonesia</option>
    <option value="IR">Iran</option>
    <option value="IQ">Iraq</option>
    <option value="IE">Ireland</option>
    <option value="IL">Israel</option>
    <option value="IT">Italy</option>
    <option value="JM">Jamaica</option>
    <option value="JP">Japan</option>
    <option value="JE">Jersey</option>
    <option value="JO">Jordan</option>
    <option value="KZ">Kazakhstan</option>
    <option value="KE">Kenya</option>
    <option value="KI">Kiribati</option>
    <option value="KW">Kuwait</option>
    <option value="KG">Kyrgyzstan</option>
    <option value="LA">Laos</option>
    <option value="LV">Latvia</option>
    <option value="LB">Lebanon</option>
    <option value="LS">Lesotho</option>
    <option value="LR">Liberia</option>
    <option value="LY">Libya</option>
    <option value="LI">Liechtenstein</option>
    <option value="LT">Lithuania</option>
    <option value="LU">Luxembourg</option>
    <option value="MO">Macao</option>
    <option value="MK">North Macedonia</option>
    <option value="MG">Madagascar</option>
    <option value="MW">Malawi</option>
    <option value="MY">Malaysia</option>
    <option value="MV">Maldives</option>
    <option value="ML">Mali</option>
    <option value="MT">Malta</option>
    <option value="MH">Marshall Islands</option>
    <option value="MQ">Martinique</option>
    <option value="MR">Mauritania</option>
    <option value="MU">Mauritius</option>
    <option value="YT">Mayotte</option>
    <option value="MX">Mexico</option>
    <option value="FM">Micronesia</option>
    <option value="MD">Moldova</option>
    <option value="MC">Monaco</option>
    <option value="MN">Mongolia</option>
    <option value="ME">Montenegro</option>
    <option value="MS">Montserrat</option>
    <option value="MA">Morocco</option>
    <option value="MZ">Mozambique</option>
    <option value="MM">Myanmar</option>
    <option value="NA">Namibia</option>
    <option value="NR">Nauru</option>
    <option value="NP">Nepal</option>
    <option value="NL">Netherlands</option>
    <option value="NC">New Caledonia</option>
    <option value="NZ">New Zealand</option>
    <option value="NI">Nicaragua</option>
    <option value="NE">Niger</option>
    <option value="NG">Nigeria</option>
    <option value="NU">Niue</option>
    <option value="NF">Norfolk Island</option>
    <option value="KP">North Korea</option>
    <option value="MP">Northern Mariana Islands</option>
    <option value="NO">Norway</option>
    <option value="OM">Oman</option>
    <option value="PK">Pakistan</option>
    <option value="PW">Palau</option>
    <option value="PA">Panama</option>
    <option value="PG">Papua New Guinea</option>
    <option value="PY">Paraguay</option>
    <option value="PE">Peru</option>
    <option value="PH">Philippines</option>
    <option value="PL">Poland</option>
    <option value="PT">Portugal</option>
    <option value="PR">Puerto Rico</option>
    <option value="QA">Qatar</option>
    <option value="RE">Réunion</option>
    <option value="RO">Romania</option>
    <option value="RU">Russia</option>
    <option value="RW">Rwanda</option>
    <option value="BL">Saint Barthélemy</option>
    <option value="SH">Saint Helena</option>
    <option value="KN">Saint Kitts and Nevis</option>
    <option value="LC">Saint Lucia</option>
    <option value="MF">Saint Martin</option>
    <option value="PM">Saint Pierre and Miquelon</option>
    <option value="VC">Saint Vincent and the Grenadines</option>
    <option value="WS">Samoa</option>
    <option value="SM">San Marino</option>
    <option value="SA">Saudi Arabia</option>
    <option value="SN">Senegal</option>
    <option value="RS">Serbia</option>
    <option value="SC">Seychelles</option>
    <option value="SL">Sierra Leone</option>
    <option value="SG">Singapore</option>
    <option value="SX">Sint Maarten</option>
    <option value="SK">Slovakia</option>
    <option value="SI">Slovenia</option>
    <option value="SB">Solomon Islands</option>
    <option value="SO">Somalia</option>
    <option value="ZA">South Africa</option>
    <option value="KR">South Korea</option>
    <option value="SS">South Sudan</option>
    <option value="ES">Spain</option>
    <option value="LK">Sri Lanka</option>
    <option value="SD">Sudan</option>
    <option value="SR">Suriname</option>
    <option value="SJ">Svalbard and Jan Mayen</option>
    <option value="SE">Sweden</option>
    <option value="CH">Switzerland</option>
    <option value="SY">Syria</option>
    <option value="TW">Taiwan</option>
    <option value="TJ">Tajikistan</option>
    <option value="TZ">Tanzania</option>
    <option value="TH">Thailand</option>
    <option value="TL">Timor-Leste</option>
    <option value="TG">Togo</option>
    <option value="TK">Tokelau</option>
    <option value="TO">Tonga</option>
    <option value="TT">Trinidad and Tobago</option>
    <option value="TN">Tunisia</option>
    <option value="TR">Turkey</option>
    <option value="TM">Turkmenistan</option>
    <option value="TC">Turks and Caicos Islands</option>
    <option value="TV">Tuvalu</option>
    <option value="UG">Uganda</option>
    <option value="UA">Ukraine</option>
    <option value="AE">United Arab Emirates</option>
    <option value="GB">United Kingdom</option>
    <option value="US">United States</option>
    <option value="UY">Uruguay</option>
    <option value="UZ">Uzbekistan</option>
    <option value="VU">Vanuatu</option>
    <option value="VE">Venezuela</option>
    <option value="VN">Vietnam</option>
    <option value="WF">Wallis and Futuna</option>
    <option value="EH">Western Sahara</option>
    <option value="YE">Yemen</option>
    <option value="ZM">Zambia</option>
    <option value="ZW">Zimbabwe</option>
</select>
        </div>
    <div class="col">
      <label for="wildcard">WILDCARD</label>
      <select class="service-selector" id="wildcard">
        <option value="">NO WILDCARD</option>
          <option value="ava.game.naver.com">ava.game.naver.com</option>
          <option value="graph.instagram.com">graph.instagram.com</option>
          <option value="quiz.int.vidio.com">quiz.int.vidio.com</option>
          <option value="live.iflix.com">live.iflix.com</option>
          <option value="support.zoom.us">support.zoom.us</option>
          <option value="blog.webex.com">blog.webex.com</option>
          <option value="investors.spotify.com">investors.spotify.com</option>
          <option value="cache.netflix.com">cache.netflix.com</option>
          <option value="zaintest.vuclip.com">zaintest.vuclip.com</option>
          <option value="io.ruangguru.com">io.ruangguru.com</option>
          <option value="api.midtrans.com">api.midtrans.com</option>
        </select>
      </div>
    <div class="col">
      <label for="cons">COUNT</label>
      <select class="service-selector" id="cons">
        <option value="5">5</option>
        <option value="10">10</option>
        <option value="25">25</option>
        <option value="50">50</option>
        <option value="100">100</option>
        <option value="250">250</option>
      </select>
      </div>
    <div class="col">
      <label for="link-sub">SUB LINK</label>
      <input type="text" id="link-sub" value="" readonly />
      <button class="sub" onclick="copyLink()">COPY LINK</button>
    <button onclick="hidePopup()">Close</button>
 
    </div>
    </div>
    </div>
  </div>
  <footer class="footer">
    <h2><p>&copy; 2024 FREE PROXY CF BMKG.XYZ</p></h2>
  </footer>
<script>
  // Function to generate the link
  function generateLink() {
    const serviceType = document.getElementById('service-type').value;
    const countryCode = document.getElementById('country-code').value;
    const wildcard = document.getElementById('wildcard').value;
    const cons = document.getElementById('cons').value;

    // Base URL for the link
    let baseURL = `https://sub.bmkg.xyz/${serviceType}?sub1=${countryCode}&count=${cons}`;

    // If wildcard is selected, append it to the URL
    if (wildcard) {
      baseURL += `&wildcard=${wildcard}`;
    }

    // Set the generated URL to the input field
    document.getElementById('link-sub').value = baseURL;
  }

  // Add event listeners to the selects to trigger link generation
  document.getElementById('service-type').addEventListener('change', generateLink);
  document.getElementById('country-code').addEventListener('change', generateLink);
  document.getElementById('wildcard').addEventListener('change', generateLink);
  document.getElementById('cons').addEventListener('change', generateLink);

  // Function to copy the link to clipboard
  function copyLink() {
    const inputField = document.getElementById('link-sub');
    const link = inputField.value;

    // Salin teks ke clipboard
    navigator.clipboard.writeText(link).then(() => {
      // Tampilkan pesan popup yang menarik menggunakan Swal
      Swal.fire({
        title: 'Berhasil!',
        text: 'Link Sub telah berhasil disalin',
        background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
        icon: 'success',
        color: 'red', // Warna teks
        customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6' // Warna tombol konfirmasi
      });
    }).catch((err) => {
      // Tangani jika ada kesalahan saat menyalin
      Swal.fire({
        title: 'Gagal!',
        text: 'Terjadi kesalahan saat menyalin link.',
        icon: 'error',
        background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (merah tua transparan)
        color: 'red', // Warna teks
        confirmButtonColor: '#d33' // Warna tombol konfirmasi
      });
    });
  }

  // Call generateLink initially to populate the field
  generateLink();
</script>

  <script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
<script>
    // Function to show the popup
    function showPopup() {
      document.getElementById("myPopup").style.display = "flex";
    }

    // Function to hide the popup
    function hidePopup() {
      document.getElementById("myPopup").style.display = "none";
    }
  </script>
    <script>
let proxyPerPage = 15;
let currentPage = 1;
let filteredProxies = [];
let allProxies = [];

// Function to handle UUID generation
function uuidv4() {
  return ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
    (c ^ crypto.getRandomValues(new Uint8Array(1))[0] & 15 >> c / 4).toString(16)
  );
}

// Function to render proxies
function renderProxies(proxies, proxyList, pagination) {
  const start = (currentPage - 1) * proxyPerPage;
  const end = start + proxyPerPage;
  const currentPageProxies = proxies.slice(start, end);

  proxyList.innerHTML = ''; // Clear previous list

  currentPageProxies.forEach(proxy => {
    const [ip, port, negara, penyedia] = proxy.split(",");
    const uuid = uuidv4();
    const row = document.createElement('tr');
    row.innerHTML = `
      <td> <span class="aha">${penyedia} | ${negara} </span><span class="flag-icon flag-icon-${negara.toLowerCase()}"></span>
     </td>
      <td><button class="cekproxy" onclick="checkProxyStatus('${ip}:${port}', this)">CHECK</button>          
      <span class="latency-cell"></span></td>
      <td>
        <select class="service-selector">
          <option value="">NO WILDCARD</option>
          <option value="ava.game.naver.com">ava.game.naver.com</option>
          <option value="graph.instagram.com">graph.instagram.com</option>
          <option value="quiz.int.vidio.com">quiz.int.vidio.com</option>
          <option value="live.iflix.com.com">live.iflix.com</option>
          <option value="support.zoom.us">support.zoom.us</option>
          <option value="blog.webex.com">blog.webex.com</option>
          <option value="investors.spotify.com">investors.spotify.com</option>
          <option value="cache.netflix.com">cache.netflix.com</option>
          <option value="zaintest.vuclip.com">zaintest.vuclip.com</option>
          <option value="io.ruangguru.com">io.ruangguru.com</option>
          <option value="api.midtrans.com">api.midtrans.com</option>
        </select>
      </td>
      <td><button class="copy-vless">COPY VLESS 443</button>
      <button class="copy-vless-clash">COPY CLASH 443</button></td>
      <td><button class="copy-vless1">COPY VLESS 80</button>
      <button class="copy-vless2">COPY CLASH 80</button></td>
      <td><button class="copy-trojan">COPY TROJAN 443</button>
      <button class="copy-trojan-clash">COPY CLASH 443</button></td>
      <td><button class="copy-ss">COPY SHADOWSOCK</button>
      <button class="copy-ss1">COPY CLASH</button></td>
    `;
    proxyList.appendChild(row);

    // Event listeners for copy buttons
    
    
      
    

      
    
  row.querySelector('.copy-vless').addEventListener('click', () => {
    const selectedService = row.querySelector('.service-selector').value || "tp1.bmkg.xyz";
    const domain = selectedService === "tp1.bmkg.xyz" ? "tp1.bmkg.xyz" : `${selectedService}.tp1.bmkg.xyz`;
    const VLESS = `vless://${uuid}@${selectedService}:443?encryption=none&type=ws&host=${domain}&path=%2F${ip}-${port}&security=tls&sni=${domain}#(${selectedService})+${negara}+${penyedia}`;
    navigator.clipboard.writeText(VLESS);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY VLESS 443 SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-vless-clash').addEventListener('click', () => {
    const selectedService = row.querySelector('.service-selector').value || "tp1.bmkg.xyz";
    const domain = selectedService === "tp1.bmkg.xyz" ? "tp1.bmkg.xyz" : `${selectedService}.tp1.bmkg.xyz`;
    const VLESSC = `- name: (${selectedService})+${negara}+${penyedia}
  server: ${selectedService}
  port: 443
  type: vless
  uuid: ${uuid}
  cipher: auto
  tls: true
  udp: true
  skip-cert-verify: true
  network: ws
  servername: ${domain}
  ws-opts:
    path: /${ip}-${port}
    headers:
      Host: ${domain}`;
    navigator.clipboard.writeText(VLESSC);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY VLESS CLASH 443 SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-trojan').addEventListener('click', () => {
    const selectedService = row.querySelector('.service-selector').value || "tp1.bmkg.xyz";
    const domain = selectedService === "tp1.bmkg.xyz" ? "tp1.bmkg.xyz" : `${selectedService}.tp1.bmkg.xyz`;
    const TROJAN = `trojan://${uuid}@${selectedService}:443?encryption=none&type=ws&host=${domain}&path=%2F${ip}-${port}&security=tls&sni=${domain}#(${selectedService})+${negara}+${penyedia}`;
    navigator.clipboard.writeText(TROJAN);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY TROJAN SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-trojan-clash').addEventListener('click', () => {
    const selectedService = row.querySelector('.service-selector').value || "tp1.bmkg.xyz";
    const domain = selectedService === "tp1.bmkg.xyz" ? "tp1.bmkg.xyz" : `${selectedService}.tp1.bmkg.xyz`;
    const TROJANC = `- name: (${selectedService})+${negara}+${penyedia}
    server: ${selectedService}
    port: 443
    type: trojan
    password: ${uuid}
    skip-cert-verify: true
    sni: ${domain}
    network: ws
    ws-opts:
      path: /${ip}-${port}
      headers:
        Host: ${domain}
    udp: true `;
    navigator.clipboard.writeText(TROJANC);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY TROJAN CLASH SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-ss').addEventListener('click', () => {
    const selectedService = row.querySelector('.service-selector').value || "tp1.bmkg.xyz";
    const domain = selectedService === "tp1.bmkg.xyz" ? "tp1.bmkg.xyz" : `${selectedService}.tp1.bmkg.xyz`;
    const SS = `ss://bm9uZTo1ZDJlYmQyYS05Y2I5LTRkMWItYWY1NS04NjE3ZDNlODFmMzk%3D@${selectedService}:443?encryption=none&type=ws&host=${domain}&path=%2F${ip}-${port}&security=tls&sni=${domain}#(${selectedService})+${negara}+${penyedia}`;
    navigator.clipboard.writeText(SS);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY SHADOWSOCK SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-ss1').addEventListener('click', () => {
    const SS1 = `087861167414`;
    navigator.clipboard.writeText(SS1);
    Swal.fire({
      title: 'Perhatian!',
      text: 'SHADOWSOCK VERSI CLASH BELUM TERSEDIA',
      icon: 'warning',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#f39c12'
    });
  });

  row.querySelector('.copy-vless1').addEventListener('click', () => {
    const VLESS1 = `vless://${uuid}@tp1.bmkg.xyz:80?encryption=none&type=ws&host=tp1.bmkg.xyz&path=%2F${ip}-${port}&security=none&sni=#(${selectedService})+${negara}+${penyedia}`;
    navigator.clipboard.writeText(VLESS1);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY VLESS 80 SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

  row.querySelector('.copy-vless2').addEventListener('click', () => {
    const VLESS2 = `- name: (${selectedService})+${negara}+${penyedia}
  server: tp1.bmkg.xyz
  port: 80
  type: vless
  uuid: ${uuid}
  cipher: auto
  tls: false
  skip-cert-verify: false
  servername: tp1.bmkg.xyz
  network: ws
  ws-opts:
    path: /${ip}-${port}
    headers:
      Host: tp1.bmkg.xyz
  udp: true `;
    navigator.clipboard.writeText(VLESS2);
    Swal.fire({
      title: 'Berhasil!',
      text: 'COPY VLESS CLASH 80 SUKSES!',
      icon: 'success',
      background: 'rgba(6, 18, 67, 0.89)', // Warna latar belakang (biru pucat)
      color: 'red', // Warna teks
      customClass: {
        popup: 'rounded-popup',
      },
      confirmButtonColor: '#3085d6'
    });
  });

    
  });

  // Display total proxies
  const totalProxies = proxies.length;
  const totalProxyElement = document.getElementById('total-proxy');
  if (totalProxyElement) {
    totalProxyElement.textContent = `Total Proxies: ${totalProxies}`;
  }

  renderPagination(proxies, pagination);
}

// Function to render pagination
// Function to render pagination
function renderPagination(proxies, pagination) {
  const totalPages = Math.ceil(proxies.length / proxyPerPage);
  const maxButtons = 6;
  pagination.innerHTML = '';

  if (currentPage > 1) {
    const firstButton = document.createElement('button');
    firstButton.textContent = '<< First';
    firstButton.addEventListener('click', () => updatePage(1, proxies, pagination));
    pagination.appendChild(firstButton);

    const prevButton = document.createElement('button');
    prevButton.textContent = '<< Previous';
    prevButton.addEventListener('click', () => updatePage(currentPage - 1, proxies, pagination));
    pagination.appendChild(prevButton);
  }

  const startPage = Math.max(1, currentPage - Math.floor(maxButtons / 2));
  const endPage = Math.min(totalPages, startPage + maxButtons - 1);

  for (let i = startPage; i <= endPage; i++) {
    const pageButton = document.createElement('button');
    pageButton.textContent = i;
    if (i === currentPage) {
      pageButton.classList.add('active');
    }
    pageButton.addEventListener('click', () => updatePage(i, proxies, pagination));
    pagination.appendChild(pageButton);
  }

  if (currentPage < totalPages) {
    const nextButton = document.createElement('button');
    nextButton.textContent = 'Next >>';
    nextButton.addEventListener('click', () => updatePage(currentPage + 1, proxies, pagination));
    pagination.appendChild(nextButton);

    const lastButton = document.createElement('button');
    lastButton.textContent = 'Last >>';
    lastButton.addEventListener('click', () => updatePage(totalPages, proxies, pagination));
    pagination.appendChild(lastButton);
  }
}


// Function to update page
function updatePage(page, proxies, pagination) {
  currentPage = page;
  const proxyList = document.getElementById('proxy-list');
  renderProxies(proxies, proxyList, pagination);
}

// Function to filter proxies
function filterProxies(searchTerm) {
  searchTerm = searchTerm.toLowerCase();
  filteredProxies = allProxies.filter(proxy => proxy.toLowerCase().includes(searchTerm));
  currentPage = 1;
  const proxyList = document.getElementById('proxy-list');
  const pagination = document.getElementById('pagination');
  renderProxies(filteredProxies, proxyList, pagination);
}

// Event listener for search bar
document.getElementById('search-bar').addEventListener('input', (e) => {
  filterProxies(e.target.value);
});

// Event listener for items per page dropdown
document.getElementById('items-per-page').addEventListener('change', (e) => {
  proxyPerPage = parseInt(e.target.value);
  const proxyList = document.getElementById('proxy-list');
  const pagination = document.getElementById('pagination');
  renderProxies(filteredProxies, proxyList, pagination);
});

// Fetching proxy data
fetch("bot/proxy_list.txt")
  .then(response => response.text())
  .then(data => {
    allProxies = data.split("\n").filter(line => line.trim() !== "");
    filteredProxies = allProxies;
    const proxyList = document.getElementById('proxy-list');
    const pagination = document.getElementById('pagination');
    renderProxies(filteredProxies, proxyList, pagination);
  })
  .catch(error => console.error("Error fetching proxy data:", error)); // Correct placement here

// Check Proxy status function
function checkProxyStatus(proxy, button) {
  button.textContent = 'Loading';
  button.style.backgroundColor = 'yellow'; // Set background color to yellow when loading
  button.style.color = 'black'; // Set text color to black during loading
  const latencyCell = button.parentElement.querySelector('.latency-cell'); // Find the latency span in the same cell

  const startTime = performance.now();
  fetch('https://httpbin.org/ip', {
    method: 'GET',
    headers: {
      'Proxy': `http://${proxy}`,
    },
    timeout: 5000
  })
    .then(response => {
      const endTime = performance.now();
      const latency = (endTime - startTime).toFixed(2); // Calculate latency

      if (response.ok) {
        button.textContent = 'NGACENG';
        button.style.backgroundColor = 'green'; // Set background color to green if the proxy is working
        button.style.color = 'white'; // Set text color to white for active proxy
        latencyCell.textContent = `${latency} ms`; // Display latency in the same column

        // Display latency in a popup
        Swal.fire({
          title: 'Proxy Status: NGACENG',
          text: `${latency} ms.`,
          icon: 'success',
          background: 'rgba(6, 18, 67, 0.89)', // Background color
          color: 'white', // Text color
          customClass: {
            popup: 'rounded-popup',
          },
          confirmButtonColor: '#3085d6',
        });
      } else {
        throw new Error('TURU');
      }
    })
    .catch(() => {
      button.textContent = 'TURU';
      button.style.backgroundColor = 'red'; // Set background color to red if the proxy failed
      button.style.color = 'white'; // Set text color to white for failed proxy
      latencyCell.textContent = ''; // Clear latency cell text on failure

      // Display error in a popup
      Swal.fire({
        title: 'Proxy Status: TURU',
        text: ``,
        icon: 'error',
        background: 'rgba(6, 18, 67, 0.89)', // Background color
        color: 'white', // Text color
        customClass: {
          popup: 'rounded-popup',
        },
        confirmButtonColor: '#d33',
      });
    });
}



</script>
  
</body>
</html>


class Document {
  proxies = [];

  constructor(request) {
    this.html = baseHTML;
    this.request = request;
    this.url = new URL(this.request.url);
  }

  setTitle(title) {
    this.html = this.html.replaceAll("PLACEHOLDER_JUDUL", title);
  }

  addInfo(text) {
    text = `<span>${text}</span>`;
    this.html = this.html.replaceAll("PLACEHOLDER_INFO", `${text}\nPLACEHOLDER_INFO`);
  }

  registerProxies(data, proxies) {
    this.proxies.push({
      ...data,
      list: proxies,
    });
  }

  buildProxyGroup() {
    let proxyGroupElement = "";
    proxyGroupElement += `<div class="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-4 gap-6">`;
    for (let i = 0; i < this.proxies.length; i++) {
      const proxyData = this.proxies[i];

      // Assign proxies
      proxyGroupElement += `<div class="lozad scale-95 mb-2 bg-white dark:bg-neutral-800 transition-transform duration-200 rounded-lg p-4 w-60 border-2 border-neutral-800">`;
      proxyGroupElement += `  <div id="countryFlag" class="absolute -translate-y-10 -translate-x-2 border-2 border-neutral-800 rounded-md overflow-hidden scale-75"><img height="20" src="https://flagcdn.com/h40/${proxyData.country.toLowerCase()}.png" /></div>`;
      proxyGroupElement += `  <div>`;
      proxyGroupElement += `    <div id="ping-${i}" class="animate-pulse text-xs font-semibold dark:text-white">Idle ${proxyData.proxyIP}:${proxyData.proxyPort}</div>`;
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `  <div class="rounded py-1 px-2 bg-amber-400 dark:bg-neutral-800 dark:border-2 dark:border-amber-400">`;
      proxyGroupElement += `    <h5 class="font-bold text-md text-neutral-900 dark:text-white mb-1 overflow-x-scroll scrollbar-hide text-nowrap">${proxyData.org}</h5>`;
      proxyGroupElement += `    <div class="text-neutral-900 dark:text-white text-sm">`;
      proxyGroupElement += `      <p>IP: ${proxyData.proxyIP}</p>`;
      proxyGroupElement += `      <p>Port: ${proxyData.proxyPort}</p>`;
      proxyGroupElement += `    </div>`;
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `  <div class="flex flex-col gap-2 mt-3 text-sm">`;
      for (let x = 0; x < proxyData.list.length; x++) {
        const indexName = ["Trojan TLS", "VLESS TLS", "SS TLS", "Trojan NTLS", "VLESS NTLS", "SS NTLS"];
        const proxy = proxyData.list[x];

        if (x % 2 == 0) {
          proxyGroupElement += `<div class="flex gap-2 justify-around w-full">`;
        }

        proxyGroupElement += `<button class="bg-blue-500 dark:bg-neutral-800 dark:border-2 dark:border-blue-500 rounded p-1 w-full text-white" onclick="copyToClipboard('${proxy}')">${indexName[x]}</button>`;

        if (x % 2 == 1) {
          proxyGroupElement += `</div>`;
        }
      }
      proxyGroupElement += `  </div>`;
      proxyGroupElement += `</div>`;
    }
    proxyGroupElement += `</div>`;

    this.html = this.html.replaceAll("PLACEHOLDER_PROXY_GROUP", `${proxyGroupElement}`);
  }

  buildCountryFlag() {
    const proxyBankUrl = this.url.searchParams.get("proxy-list");
    const flagList = [];
    for (const proxy of cachedProxyList) {
      flagList.push(proxy.country);
    }

    let flagElement = "";
    for (const flag of new Set(flagList)) {
      flagElement += `<a href="/sub?cc=${flag}${
        proxyBankUrl ? "&proxy-list=" + proxyBankUrl : ""
      }" class="py-1" ><img width=20 src="https://flagcdn.com/h80/${flag.toLowerCase()}.png" /></a>`;
    }

    this.html = this.html.replaceAll("PLACEHOLDER_BENDERA_NEGARA", flagElement);
  }

  addPageButton(text, link, isDisabled) {
    const pageButton = `<li><button ${
      isDisabled ? "disabled" : ""
    } class="px-3 py-1 bg-amber-400 border-2 border-neutral-800 rounded" onclick=navigateTo('${link}')>${text}</button></li>`;

    this.html = this.html.replaceAll("PLACEHOLDER_PAGE_BUTTON", `${pageButton}\nPLACEHOLDER_PAGE_BUTTON`);
  }

  build() {
    this.buildProxyGroup();
    this.buildCountryFlag();

    this.html = this.html.replaceAll("PLACEHOLDER_API_READY", isApiReady ? "block" : "hidden");

    return this.html.replaceAll(/PLACEHOLDER_\w+/gim, "");
  }
}
