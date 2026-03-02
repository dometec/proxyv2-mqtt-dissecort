# proxyv2-mqtt-dissecort

> **A Wireshark plugin to decode PROXY Protocol v2 + MQTT connections**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Wireshark](https://img.shields.io/badge/Wireshark-Lua%20plugin-blue)](https://www.wireshark.org/)

---

## Overview

In IoT projects, MQTT clients often connect through a load balancer or reverse proxy that **terminates TLS** before forwarding traffic to the MQTT broker. To preserve the original client information (IP address, port, TLS certificate CN, etc.), the load balancer prepends a **PROXY Protocol v2** header to each connection.

This means the TCP stream received by the MQTT broker looks like:

```
[ PROXY Protocol v2 header ] + [ MQTT CONNECT packet ] + [ MQTT traffic... ]
```

Wireshark's built-in MQTT dissector does not understand the PROXY Protocol v2 header, so it fails to parse such captures correctly.

This plugin solves the problem by:

1. **Detecting** the PROXY Protocol v2 signature at the beginning of the stream.
2. **Parsing** and displaying all PROXY header fields (source/destination IP & port, TLV extensions, SSL Common Name).
3. **Handing off** the remaining bytes to the standard Wireshark MQTT dissector.

---

## Features

- ✅ Detects and parses **PROXY Protocol v2** headers
- ✅ Displays source/destination **IPv4 addresses and ports**
- ✅ Parses **TLV extensions**, including `PP2_TYPE_SSL` (type `0x20`)
- ✅ Extracts the **SSL Common Name** (`PP2_SUBTYPE_SSL_CN`, type `0x22`)
- ✅ Seamlessly delegates **MQTT payload** to Wireshark's built-in MQTT dissector
- ✅ Gracefully handles plain MQTT connections (without PROXY header)

---

## Requirements

- [Wireshark](https://www.wireshark.org/) with Lua scripting support (version 3.x or later recommended)

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/dometec/proxyv2-mqtt-dissecort.git

# 2. Copy the plugin to Wireshark's plugins directory
cp proxyv2-mqtt-dissecort/proxyv2_mqtt.lua ~/.config/wireshark/plugins/

# 3. Restart Wireshark (or reload Lua plugins via Analyze > Reload Lua Plugins)
```

> **Note:** On Windows, the plugins directory is typically:
> `%APPDATA%\Wireshark\plugins\`

---

## Usage

The plugin registers itself on **TCP port 1884** by default.

If your MQTT broker uses a different port, edit the last line of `proxyv2_mqtt.lua`:

```lua
-- Change 1884 to your actual TCP port
DissectorTable.get("tcp.port"):add(1884, proxy_mqtt)
```

Once installed, open a capture in Wireshark. Connections starting with the PROXY Protocol v2 signature will be labeled **`PROXYv2+MQTT`** in the Protocol column, and the packet details pane will show:

- **PROXY Protocol v2** subtree with header fields
  - Signature
  - Version / Command
  - Family / Protocol
  - Header Length
  - Source IP & Port
  - Destination IP & Port
  - TLV entries (including SSL Common Name if present)
- **MQTT** subtree (handed off to the standard dissector)

---

## How It Works

```
TCP stream
    │
    ├─ Starts with PROXY v2 signature (12 bytes: "\r\n\r\n\0\r\nQUIT\n")?
    │       │
    │       ├── YES → Parse PROXY header → hand MQTT bytes to mqtt dissector
    │       │
    │       └── NO  → Pass entire buffer directly to mqtt dissector
```

The plugin parses the following header structure:

| Offset | Size | Field              |
|--------|------|--------------------|
| 0      | 12   | Signature          |
| 12     | 1    | Version + Command  |
| 13     | 1    | Family + Protocol  |
| 14     | 2    | Address length (N) |
| 16     | N    | Addresses + TLVs   |

---

## License

[MIT](LICENSE)
