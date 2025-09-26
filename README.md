# 📘 Web Tracking Apache Module

## 📌 Overview

The **Web Tracking Apache Module** is a plugin for:

- **Apache HTTP Server 2.4.x**
- **IBM HTTP Server 9.0.x**
- **64-bit Linux (RHEL 8/9 and later)**

### 🔍 Purpose

| Use Case         | Description |
|------------------|-------------|
| Legal Auditing   | Tracks all HTTP transactions for compliance and forensic analysis |
| Security Auditing| Logs request/response data for security reviews |
| Debugging        | Helps developers trace and analyze anomalous web transactions |

> ⚠️ Only supports **HTTP/1.1**. Uses **zlib** (gzip/deflate) for compression. Does **not** handle threat detection.

---

## ⚙️ Requirements

### 🖥️ System Requirements

| Load (Hits/hour) | Storage | RAM | CPU Sockets |
|------------------|---------|-----|-------------|
| > 15,000,000     | 100 GB  | 20 GB | 16          |
| > 12,500,000     | 80 GB   | 16 GB | 12          |
| > 10,000,000     | 60 GB   | 12 GB | 8           |
| > 7,500,000      | 40 GB   | 8 GB  | 6           |
| > 5,000,000      | 25 GB   | 6 GB  | 4           |
| < 5,000,000      | 15 GB   | 4 GB  | 2           |

> 🔒 For high-load systems (>10M hits/hour), use a **dedicated filesystem** for log storage to avoid service disruption.

---

### ⚙️ Apache Configuration (MPM)

If using `mpm_worker`, configure to minimize process churn:

```apache
ThreadLimit         400
ServerLimit         4
StartServers        1
MaxClients          1600
MinSpareThreads     40
MaxSpareThreads     540
ThreadsPerChild     400
MaxRequestWorkers   1600
MaxRequestsPerChild 0
ListenBacklog       2048
MaxMemFree          4096
```

> For `mpm_event`, default settings are generally sufficient.

## 🌟 Features

The module is distributed as a shared library:

- **Executable**: `mod_web_tracking.so`
- **Package**: `webtracking-bin.zip`

### 🔧 Key Capabilities

| Feature | Description |
|--------|-------------|
| Disable Tracking | Globally disable tracking |
| Unique Identifier | Injects a unique UUID header per request |
| URI Filtering | Enable/disable tracking for specific URIs |
| Header Filtering | Exclude or suppress specific headers |
| IP Filtering | Disable tracking for specific source IPs |
| Proxy Support | Tracks real client IP behind reverse proxies |
| SSL Offloading | Handles HTTPS offloading via headers |
| Body Tracking | Enable/disable request/response body tracking |
| Compression | Supports gzip/deflate; can inflate responses |
| Environment Variables | Include Apache env vars in tracking records |

### 🧾 Special Headers

- **Tracking UUID Header**: Injected per request (default: `X-WTUUID`)
- **Sentinel Header**: `x-wt-request-to-be-tracked` signals tracking is active

## 🛠️ Configuration Directives

The module supports over **30 directives**. Here are some key ones:

### 🔐 Identification & Filtering

| Directive | Purpose | Example |
|----------|---------|---------|
| `WebTrackingApplicationId` | Map URI prefix to App ID | `/myroot MyApp` |
| `WebTrackingUuidHeader` | Define UUID header name | `X-APP1UUID` |
| `WebTrackingDisable` | Disable tracking globally | `On` |
| `WebTrackingDisablingHeader` | Disable tracking via header | `X-WT-OFF` |
| `WebTrackingEnableProxy` | Enable proxy IP tracking | `On` |
| `WebTrackingClientIpHeader` | Define proxy IP header | `X-Forwarded-For` |

### 🌐 URI & Host Matching

| Directive | Type | Example |
|----------|------|---------|
| `WebTrackingExactURI` | Exact URI match | `/myroot/home` |
| `WebTrackingStartsWithURI` | URI prefix match | `/mycontext/` |
| `WebTrackingExcludeExactURI` | Disable for exact URI | `/private/` |
| `WebTrackingHost` | Regex for Host header | `\\.mycorp\\.com$` |
| `WebTrackingExcludeIP` | Regex for IPs | `^192\\.168` |

### 📦 Body & Header Control

| Directive | Purpose | Example |
|----------|---------|---------|
| `WebTrackingRequestBodyType` | Track request body | `Always` |
| `WebTrackingResponseBodyType` | Track response body | `Content` |
| `WebTrackingBodyLimit` | Max body size (MB) | `10` |
| `WebTrackingExcludeHeader` | Remove headers | `SecureHeader` |
| `WebTrackingExcludeCookie` | Remove cookies | `JSESSIONID` |
| `WebTrackingExcludeFormParameter` | Remove POST params | `j_password` |

### 📁 File Management

| Directive | Purpose | Example |
|----------|---------|---------|
| `WebTrackingRecordFolder` | Save tracking logs | `/webtracking/logs` |
| `WebTrackingRecordArchiveFolder` | Archive logs | `/webtracking/splunk` |
| `WebTrackingRecordLifeTime` | Log file rotation (min) | `15` |

## 🧪 Examples

### 🔧 Configuration File Sample

To simplify setup, include the module configuration in `httpd.conf`:

```apache
# Web Tracking Module
Include "conf/webtracking.conf"
```

### 📁 Sample `webtracking.conf`

```apache
# Load module
LoadModule web_tracking_module /prod/webtracking/lib/mod_web_tracking.so

# Logging
LogLevel web_tracking:info

# Version
WebTrackingConfigVersion "16.0.1 (production)"

# UUID Header
WebTrackingUuidHeader X-WT-UUID

# Application ID
WebTrackingApplicationIdFromHeader application-id
WebTrackingApplicationId / WEBTRACKING

# URI Filters
WebTrackingExactURI /wlptest/snoop
WebTrackingStartsWithURI /mycontext/
WebTrackingExcludeExactURI /mycontext/login
WebTrackingExcludeURI \\.pdf \\.jpg \\.css \\.png \\.js \\.gif \\.ico \\.woff \\.woff2 \\.map \\.ttf \\.svg$
WebTrackingExcludeURI ^/server-status/

# Host Filter
WebTrackingHost \\.mycorp\\.com$

# Content Type
WebTrackingContentType html json text\\/\\(?\\!csv\\) application\\/x-www-form-urlencoded

# Proxy Settings
WebTrackingEnableProxy On
WebTrackingClientIpHeader X-Forwarded-For

# Output Headers
WebTrackingOutputHeader X-WT-USER X-WT-ID-SESSION
WebTrackingOutputHeader X-WT-CAMPI-LIBERI
WebTrackingOutputHeader X-WT-IP-APP-SERVER X-WT-HOSTNAME-APP-SERVER X-WT-APPSERVER-PORT X-WT-SERVER-ENCODING

# File Management
WebTrackingRecordFolder /webtracking/logs
WebTrackingRecordArchiveFolder /webtracking/splunk
WebTrackingRecordLifeTime 15
```

---

## 📄 Record Layout

Each tracked transaction includes structured fields:

### 🧾 Request Section

| Field | Description |
|-------|-------------|
| Timestamp | Date and time of request |
| Hostname | Web server hostname |
| UUID | Unique identifier (SHA256 + counter) |
| Application ID | From URI or header |
| Remote IP | Real client IP (proxy-aware) |
| Protocol | Only HTTP/1.1 supported |
| Method | HTTP method (GET, POST, etc.) |
| URL | Full request URL |
| Headers | Filtered request headers |
| Request Body | Base64-encoded (optional) |

### 📦 Response Section

| Field | Description |
|-------|-------------|
| Status Code | HTTP response code |
| Elapsed Time | Microseconds and milliseconds |
| Bytes Read | From client |
| Bytes Sent | To client |
| Headers | Filtered response headers |
| Response Body | Base64-encoded (optional) |

> Fields are separated by pipe (`|`) and enclosed in double quotes (`"`). Body content is stored in **Base64** format.

## 🧰 Troubleshooting

### 📊 Metrics Logging

If `LogLevel` is set to `info` or higher, the module writes a **metrics record** to the Apache error log for each tracked request.

#### 📋 Metrics Format

```
[WT-METRICS: <uuid> | <appid> | <uri> | <status code> |<response time> | <module overhead for request> | <if request body is present>REQUEST<else>NO | <if response body is present>RESPONSE<else>NO | <if the record is successfully written to file>#formatted written-bytes<else>KO | <elapsed time to write to file> | <log file name>]
```

#### 🧾 Sample Log Entry

```
[Wed Feb 05 17:36:50.248970 2025] [web_tracking:info] [pid 3819381:tid 140265348957952] [WT-METRICS: webtracking.server.local:Z6OToQuMcAc4W-gG8aTQ9wAAAeE | APP_23| /private/getuser | 200 | 1.295 ms | 934 us | NO | RESPONSE| 7.815 KB | 57 us | webtracking.3819381.9.log]

```

---

### 🐞 Hot Debug

Enable runtime debugging for specific URIs without restarting Apache:

- Create file: `/tmp/webtracking_debug_uris`
- Add URIs (one per line, comments start with `#`)

#### 📁 Example

```
# Private
https://private.mycorp.com/private/v1/

# Public
https://www.mycorp.com/html/
```

---

### ⏱️ Crontab Watchdog

To ensure log files are moved from `RecordFolder` to `ArchiveFolder`, use a cron job:

```bash
# record file watchdog
0,30 8-20 * * * find /webtracking/logs/ -name "webtracking*.log" -type f -mmin +30 -exec mv {} /webtracking/splunk/ \;
```

---

### 🚨 Incident Handling Procedure

If an issue is reported:

1. **Identify the affected URL**
2. **Enable hot debug** for that URL
3. **Collect logs**, then disable debug
4. **Temporarily exclude** the URL using `WebTrackingExcludeExactURI`
5. **Re-enable** tracking once resolved

> ⚠️ If CPU or memory issues are reported, **disable the module immediately** and collect metrics from error logs.
