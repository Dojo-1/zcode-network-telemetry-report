# ZCode network telemetry — bounded independent client-side forensic observations

**Date of analysis:** 2026-10-28 · **Host:** Windows 11 Pro (EU; location withheld) · **Subject:** ZCode desktop app (local path withheld)
**Tools:** Sniffnet 1.5.1, Wireshark/tshark, `Get-NetTCPConnection`, `Resolve-DnsName` (1.1.1.1), RIPE/APNIC RDAP, static analysis of `resources\app.asar`

## TL;DR

1. **The inspected ZCode build configures OpenTelemetry trace export and Real-User-Monitoring for an Alibaba Cloud project identified with a Beijing region** (`cn-beijing.log.aliyuncs.com`, service name `zcode-cli-agent`). ZCode's international privacy policy names a Singapore controller and processing "generally" in Singapore. Its Chinese policy names a Beijing controller and storage in China (§4).
2. The mainland Chinese IPs in Sniffnet (`8.130.222.161`, `123.56.37.46`, `123.57.116.48`, `59.110.96.221`, `39.97.141.140`) **are exactly the A-records of that Beijing trace collector**. They are not "DNS round-robin of api.z.ai", as the GLM model's own self-audit claimed.
3. **An image-handling tool record referenced a UCloud object-storage URL with region label `cn-wlcb`.** This does not independently establish storage, processing or retention for every image.
4. `api.z.ai` reaches Europe through an **Alibaba Global Accelerator** edge (Frankfurt anycast `47.245.x`). The edge location says nothing about where requests are terminated or stored.
5. The bundle also allowlists **Alibaba device-fingerprinting / risk-control endpoints** (`*.device.saf.aliyuncs.com`, `cloudauth-device-*`) for `cn-shanghai` and `ap-southeast-1`.

A prior model-generated self-audit reported no analytics destination; the inspected configuration and bounded RUM captures contradict that narrower finding. They do not demonstrate covert transfer of repository contents, server-side retention or malicious intent.

---

## 1. Observation (Sniffnet + netstat)

Sniffnet's *Network host* view showed sustained connections to Alibaba Hangzhou/Beijing IPs (e.g. `39.97.141.140 – Hangzhou Alibaba, 181 KB`) while ZCode was running. Snapshot from `Get-NetTCPConnection` at 2026-10-28 ~07:40Z:

| Remote | State | Owner |
|---|---|---|
| `155.102.47.5:443` | Established | **ZCode.exe** (pid 13844) |
| `47.245.163.4:443` ×3 | TIME_WAIT | (released; `api.z.ai` edge) |
| `8.130.222.161:443` ×2 | TIME_WAIT | (released) |
| `59.110.96.221:443` ×2 | TIME_WAIT | (released) |

**Wire capture (tshark, reported 180-second invocation; recorded timestamps span at least 171 seconds beyond the originally stated end time, pending raw-capture reconciliation; TLS ClientHello SNI):** the host opened three TLS sessions to the Beijing collector during the window, with ZCode idle in the background:

```
07:52:24Z  59.110.96.221  SNI proj-xtrace-[redacted]-cn-beijing.cn-beijing.log.aliyuncs.com
07:55:12Z  123.57.116.48  SNI proj-xtrace-[redacted]-cn-beijing.cn-beijing.log.aliyuncs.com
07:55:15Z  123.57.116.48  SNI proj-xtrace-[redacted]-cn-beijing.cn-beijing.log.aliyuncs.com
```

Raw data: [`evidence/05-tshark-tls-sni.txt`](evidence/05-tshark-tls-sni.txt). The abbreviated host snapshot cannot exhaustively attribute all connections to every process. Endpoint attribution here combines configuration, DNS/SNI observations and the local-substitution test; detailed process-level claims need independent inspection of restricted captures. Sanitized excerpt: [`evidence/01-live-connections.txt`](evidence/01-live-connections.txt).

## 2. Attribution: the Beijing IPs are ZCode's trace collector

```
proj-xtrace-[redacted]-cn-beijing.cn-beijing.log.aliyuncs.com
  CNAME → …cn-beijing-c.log.aliyuncs.com
  A     → 8.130.222.175, 8.130.222.161, 123.57.116.48, 123.56.37.46,
          59.110.96.221, 59.110.96.118, 39.97.141.140, 8.130.222.211
```

Every mainland IP flagged by Sniffnet is in this set. RDAP confirms all of them are `country=CN`, *Aliyun Computing Co., LTD, Hangzhou* (`ALISOFT` / `ALICLOUD`). See [`evidence/02-dns-resolution.txt`](evidence/02-dns-resolution.txt) and [`evidence/03-rdap-ownership.txt`](evidence/03-rdap-ownership.txt).

## 3. Static analysis: what the app is configured to send

From `resources\app.asar` (version and SHA-256 in [`evidence/04-bundle-endpoints.txt`](evidence/04-bundle-endpoints.txt)). This is the production build config, not dormant library documentation:

```js
OTEL_EXPORTER_OTLP_ENDPOINT: "https://proj-xtrace-…-cn-beijing.cn-beijing.log.aliyuncs.com/apm/trace/opentelemetry",
OTEL_EXPORTER_OTLP_HEADERS:  "x-arms-license-key=[vendor-credential-redacted],x-arms-project=proj-xtrace-…-cn-beijing,
                              x-cms-workspace=default-cms-[redacted]-cn-beijing",
OTEL_SERVICE_NAME:           "zcode-cli-agent",
ZCODE_TELEMETRY_RUNTIME_DISTRIBUTION: "packaged"
```

```js
lI = "https://proj-xtrace-…-cn-beijing.cn-beijing.log.aliyuncs.com/rum/web/v2?workspace=…-cn-beijing&service_id=…",  // ARMS RUM (UI)
uI = "https://zcode.z.ai/api/v1/event/report",                                                                         // product events
function pI(t){ … "prod" : "local" }  // "mapZCodeEnvToArmsRumEnv"
```

**Identity fields propagated to the telemetry runtime** (env keys the app forwards to its agent subprocess):
`ZCODE_TELEMETRY_DEVICE_MID`, `ZCODE_TELEMETRY_USER_ID`, `ZCODE_TELEMETRY_USER_ID_HASH`, `ZCODE_TELEMETRY_USER_SUBJECT_ID`, `ZCODE_TELEMETRY_IDENTITY_STATE`, `ZCODE_MODEL_TELEMETRY_ENABLED`.

**Span attribute names present in the bundle** include `gen_ai.request.model`, `gen_ai.usage.*_tokens`, `gen_ai.tool.name`, `gen_ai.tool.call.result`, `gen_ai.user.message`, `gen_ai.tool.message`, `session.id`, `user.id`, `user.email`.

> ⚠️ **Unverified:** whether prompt/tool *content* (`gen_ai.user.message`, `gen_ai.tool.call.result`) is actually populated in exported spans. The bundled AI-SDK telemetry records inputs and outputs by default unless `recordInputs` / `recordOutputs` is `false`. The traffic is TLS, so confirming this requires TLS interception (e.g. mitmproxy with `NODE_EXTRA_CA_CERTS`). These are potential fields in the statically inspected trace schema, not verified transmitted trace contents. The monitored sessions later found no transmitted OTLP traces (§7.1).

### Other China-side endpoints in the bundle

| Host | Purpose | Region |
|---|---|---|
| `zcode.z.ai` → `155.102.47.x` (`*.initaa.com`, Alibaba CDN) | auth, plan, `/api/v1/event/report` | Alibaba (block registered to "Zhejiang Taobao") |
| `api.z.ai` → `ga-bp1…aliyunga0017.com` → `47.245.x` | GLM model API (all prompts, code context) | Alibaba Global Accelerator; FRA edge, origin not observable |
| `maas-log-prod.cn-wlcb.ufileos.com` → `117.50.161.41-43` | image-related signed tool-call URL (parameters withheld) | **UCloud `cn-wlcb` endpoint; storage and processing not independently verified** |
| `*-sdk.rum.aliyuncs.com`, `sdk.rum.aliyuncs.com` | ARMS RUM SDK / remote config (default region `cn-hangzhou`) | Alibaba CDN |
| `cn-shanghai.device.saf.aliyuncs.com`, `cloudauth-device-dualstack.cn-shanghai…` | Alibaba device fingerprint / risk control | **cn-shanghai** + ap-southeast-1 |
| `open.bigmodel.cn`, `dev.bigmodel.cn` | Zhipu mainland platform | Alibaba |
| `dashscope.aliyuncs.com` | Alibaba Qwen API (bundled) | cn |

An **image-related tool record** referenced a UCloud `cn-wlcb` storage hostname. Signed URL, session path and parameters are withheld. The observed record does not independently establish final image storage or downstream handling.

## 4. Stated policy vs. observed behaviour

Three provider policies are relevant. All were retrieved on 2026-10-28. The two ZCode policies are dated 2026-06-15.

| | Z.ai service policy (`chat.z.ai/legal-agreement/privacy-policy`) | **ZCode, international** (`zcode.z.ai/en/privacy`) | **ZCode, Chinese** (`zcode.z.ai/privacy`) |
|---|---|---|---|
| Controller | JINGSHENG HENGXING TECHNOLOGY PTE. LTD, Singapore | JINGSHENG HENGXING TECHNOLOGY PTE. LTD, Singapore | 北京智谱华章科技股份有限公司 (Beijing Zhipu Huazhang Technology), Beijing |
| Location | "generally processed in Singapore" | "generally processed in Singapore"; data "may be transferred and processed outside the jurisdiction in which you reside" | Personal information from operations in China "stored in China"; no cross-border transfer "at present" |
| China named? | No | No | Yes (as the storage location) |
| Telemetry categories | Not itemised | Device identifiers, OS version, application version, event data ("event name, event region, event type"), usage and log information | OS version, device configuration, MAC address, time zone, language, resolution, app version, device ID, event names, user ID, talk_id/message_id; logs incl. IP, input and output |
| Training on user content | Consumer content may be used to "train and improve our models" | Optimization Program off by default; opt-in | 优化计划 off by default; opt-in |
| Processors named | — | — | Payment (Alipay) only; Alibaba Cloud and UCloud not named |

**Observed behaviour compared with the ZCode international policy**, the one presented to an EU user:

| Observation (§3, §7.1) | Disclosed? |
|---|---|
| Device ID, OS and app version, event names/types, user and message identifiers in RUM payloads | **Yes.** The categories are listed. |
| Windows computer name, and Windows username within file URLs | **Not itemised.** Arguably within "device identifiers" or "log information". |
| Prompts, files and tool output sent to the inference endpoint | **Yes** (conversation content) |
| Prompt or file content in telemetry | **Not observed** in three monitored sessions (§7.1, evidence/10) |
| Telemetry destination: ARMS project hardcoded to `cn-beijing` in the single build used for all markets | **Transparency question, not a logical contradiction.** The policy says "generally" Singapore and explicitly allows transfers abroad; destination and safeguards are not specified. |
| Image-related tool record referring to UCloud `cn-wlcb` | The policy describes content handling; the observed record cannot independently establish downstream processing, storage or retention. |
| Device risk-control (`*.device.saf.aliyuncs.com`, cn-shanghai / ap-southeast-1) | Configured in the bundle, **not contacted** in the observed sessions |

**Reading.** The *categories* of telemetry observed are largely disclosed. The open point is *location and controller*: under the policy shown to international users, telemetry from an EU host reaches infrastructure in mainland China. The domestic policy names a Beijing controller and China storage for the same application. Which policy and controller govern a given account, and which transfer mechanism applies under GDPR Chapter V, cannot be determined from the client. The provider can clarify both. This is a factual comparison, not legal advice.

## 5. Corrections to the GLM (Z.ai) self-audit

| GLM claim | Finding |
|---|---|
| "No Sentry, PostHog… or any analytics destination as an actual network call" | The production config hardcodes Alibaba ARMS OTLP traces + RUM to cn-beijing. |
| "OTLP strings are just OpenTelemetry SDK code… with no third-party collector host" | The collector host, project and license key are set as literals in the shipped bundle. |
| Mainland IPs are "DNS round-robin [that] sometimes hands European clients mainland endpoints" | They are the A-records of the Beijing trace collector (§2). |
| "Logs show the app has never contacted anything outside the z.ai / bigmodel.cn / ufileos family" | App logs don't record the exporter. netstat and Sniffnet do. |

The earlier model-generated self-audit was contradicted on the observed telemetry endpoint. Model-produced audits should remain provisional until checked against independently inspected configuration and network evidence.

## 6. Mitigation

**Telemetry connections were observed while ZCode was idle in the measured window.** This does not establish identical behavior in all versions or environments. Sniffnet showed connections to the collector set (`8.130.222.175`, `8.130.222.211`, …). The exporter batches spans and flushes them on a timer.

The original restricted investigation implemented functional and full-blocking firewall modes. Their administrator-level scripts, commands and rollback procedures are **not included in this text-only distribution**, and are not independently validated as redistributable tools. The following describes historical controls rather than ready-to-run setup guidance.

### Functional mode

- **Sinkholed** in the hosts file (17 names, IPv4 + IPv6): the Beijing ARMS trace/RUM collector, the RUM SDK, all Alibaba device-fingerprint (`*.device.saf`, `cloudauth-device-*`) hosts, the UCloud image bucket, `open.bigmodel.cn`.
- **IP backstop:** the CN geo-block. The collector, the Shanghai fingerprinting service and the UCloud bucket are all CN-allocated, so they stay blocked even if DNS is bypassed.
- **Left open:** `api.z.ai` (model), `zcode.z.ai` (login/plan), `cdn-zcode.z.ai` (updates).
- **Residual:**
  - `zcode.z.ai/api/v1/event/report` shares a host with login, so it can't be split at DNS/IP level.
  - Prompts still reach Zhipu by design.
  - Pasting images will likely fail, since that path depends on the UCloud bucket.
  - Updates can add new hostnames. Re-run `-Verify` after each one.

### Full mode

1. **Program block:** every `.exe` under the ZCode install dir and `~/.zcode`, all destinations.
2. **Observed infra:** `47.235.0.0–47.246.255.255`, `155.102.0.0/16`, `163.181.0.0/16` and the z.ai/bigmodel edges. These Alibaba international ranges carry **no CN country tag**, so a geo-block alone misses `api.z.ai` and `zcode.z.ai`.
3. **Geo-block:** all CN allocations from APNIC `delegated-apnic-latest` (≈8.8k IPv4, ≈2k IPv6 prefixes, chunked into 1000-address rules).

**Side effects:** ZCode stops working (intended). Layer 2 also blocks other customers of Alibaba's international CDN and Global Accelerator, so some non-Chinese sites hosted there may break. Use `-Remove` to undo. A firewall cannot recover data already sent: rotate the Z.ai API key, and consider requesting deletion under GDPR Art. 17 from the Singapore controller.

## 7. Locally instrumented transparency gate (historical experimental setup)

The restricted investigation used a local mitmproxy inspection addon configured through ZCode's own `httpProxy` / `httpProxyCaCertPath` settings. Those settings cover the UI (Chromium session, with ZCode's own certificate verifier) and the model/MCP/tool subprocesses (`HTTPS_PROXY` + `NODE_EXTRA_CA_CERTS`). Nothing is added to the Windows certificate store. The experimental firewall aimed to force selected ZCode traffic through the loopback proxy; child-process and unmonitored egress paths mean this was not a universal isolation guarantee.

For every request, the gate:
- Logs it to `~\ZCodeGate\data\flows.jsonl` (auth headers, cookies and ARMS keys redacted).
- Applies ``gate-policy.json`` (restricted; not distributed): first match wins, the default is block, and edits are picked up live.
- Saves the request bodies sent to `api.z.ai` under `data\bodies\`, so you can read exactly what Zhipu receives.
- Captures telemetry payloads before blocking them, decodes them (gzip/deflate/br/zstd) and scans them for prompt/tool content keys (`gen_ai.user.message`, `gen_ai.tool.call.result`, …). Blocked hosts are answered locally (`connection_strategy=lazy`) and never contacted.

The gate setup and administration commands are withheld because their associated scripts are not distributed. Replication requires a separately reviewed controlled environment.

**First run (2026-10-28, ZCode idle, no prompts):**
- All traffic arrived through the gate. The program-block firewall rule does not stop loopback.
- No direct DNS lookups by ZCode, so no bypass attempts were seen.
- Observed while idle: access-token refresh and pricing on `api.z.ai/api/biz/*` (account calls, no prompt content); `zcode.z.ai/api/v1/client/configs|scenes` (remote config); billing balance; and `zcode.z.ai/api/v1/marketing/touch` every 60 s during that run. Blocked by the gate until 2026-10-30, then allowed: the code shows it delivers campaign banners and popups rather than only a ping, and blocking it could hide provider offers. Responses are now saved under `data/marketing/`. First allowed response: `"deliveries": []`.
- **Highspeed (`zcode.z.ai/api/v1/highspeed/draw`) remains unavailable behind the gate.** It connects directly, so the ZCode firewall rule refuses it (`connect EACCES 155.102.47.x:443`). On ZCode's Node 24 runtime, `HTTPS_PROXY` with `NODE_USE_ENV_PROXY=1` routed a test `fetch` through the gate. The launcher sets both, but a real draw on 2026-10-30 still failed with `EACCES`, so the setting does not reach the process that performs the draw. Why was not established. This corrects commit `eeb0424`. Per the app's strings, a failed draw continues on the original model. No quota link was found.
- **Monitor false positive, 2026-10-30.** A `CONTENT-LEAK` alert matched Z.ai's own `[1310]` limit message, which occurs both in the conversation history and in a RUM `error_message` field. No user-authored text matched. `error_message` is nevertheless a free-text field, so error strings that quote user content could reach this channel.

**Still open:** whether OTLP *trace* exports transmit message or tool content when active. The tested sessions did not observe transmitted traces; any future finding would remain scoped to its monitored configuration.

### 7.1 Local-collector experiment: does the agent export prompt or tool content?

**Why the gate alone is insufficient.** The production bundle builds its trace exporter with `@opentelemetry/exporter-trace-otlp-http` using the Node `http` transport (`sendWithHttp`). I found no proxy agent wired to it. Node's `http` module ignores `HTTPS_PROXY`, so in `-Gate` mode the agent's spans go directly to the collector and are dropped by the ZCode program-block rule. The gate never sees them.

**Design.** ``gate/capture-collector.ps1`` (restricted; not distributed) does three things:
1. It maps the collector hostname to `127.0.0.1` in the hosts file.
2. It runs the gate addon as a reverse-mode TLS endpoint on `127.0.0.1:443`. Certificates come from the gate CA, which ZCode passes to its subprocesses through `httpProxyCaCertPath` → `NODE_EXTRA_CA_CERTS`. Every request is answered locally with `204` and no upstream connection is made.
3. With `-Wire`, it records Npcap loopback `:443` and Wi-Fi traffic to the collector ranges, plus DNS, as independent corroboration.

Two synthetic canaries separate the questions:
- `PROMPTCANARY-…` is typed into the prompt. Its presence in a payload means prompts are exported.
- `TOOLCANARY-…` sits inside a throwaway workspace file the agent is asked to read. Its presence means tool output or file contents are exported.

**Procedure (historical outline; executable tooling withheld):** A loopback replacement collector and local TLS trust root were configured; independent synthetic markers were placed in a prompt and throwaway file; corresponding model and non-inference traffic was captured; loopback and external routes were checked; and host settings were subsequently restored. Reproduction requires separately reviewed scripts and instrumentation.

**Reading the result**

| Observation | Meaning |
|---|---|
| Payloads received, a canary present | That content category is exported to the Beijing collector |
| Payloads received, no canary | Telemetry was sent and decoded, but not that content, *in this session* |
| No payloads, loopback SYNs/SNI present, TLS failures logged | The agent tried to export but rejected the local certificate. The attempt is proven, the content is not |
| No payloads, no loopback traffic | Exporter inactive in this session, or a hostname not covered here. Inconclusive |
| Any packet to the collector ranges on Wi-Fi | Containment failed. Investigate before trusting any other row |

Self-test, 2026-10-28: a TLS client presented the collector SNI to `127.0.0.1:443` and received `204` locally. The receiver flagged `gen_ai.user.message`. The wire capture recorded 1 loopback SYN, 0 packets to the collector ranges, and 0 network DNS queries.

**Run 1, 2026-10-28 11:51–12:02** ([evidence/08](evidence/08-collector-capture.txt)). Figures are final counts from the re-check. Evidence/08 was written mid-run and lists 7.
- *CA trust.* `httpProxyCaCertPath` does not reach the exporting process. The first 15 handshakes to the receiver were aborted by the client. Launching ZCode with `NODE_EXTRA_CA_CERTS` set to the gate CA fixed this, and the procedure now includes it.
- *Captured.* 16 payloads, all `POST /rum/web/v2` (ARMS RUM). Identifiers: `user.id` (Z.ai account), `device.name`/`device.model` (Windows computer name), `properties.device_mid` (also sent as `user.name`), `session.id`, OS build, app version, network type.
- *Events.* `send_click` (model, provider, ask mode), `plan_request` (plan account, model, request ID, status, latency), `perf_ui_tool_call_detail` (tool name, status, duration, session/message/tool-call IDs), plus startup/performance events and exceptions.
- *Content.* Prompt canary 0/16, tool canary 0/16. The session ran outside the canary workspace, so the tool canary was not exercised in this run. The "no username" statement in evidence/08 is superseded by run 2.
- *Containment.* 0 frames to the collector ranges. The wire record shows 4 network DNS lookups of the collector name at 11:35, before the hosts entry was installed. No packets followed them, because the destination IPs are firewalled.
- *Open at the time:* no agent OTLP export, and `Telemetry report failed: network` exceptions indicating a direct-connection attempt. The latter is resolved in run 2.

**Run 2, 2026-10-28 12:02–12:20** ([evidence/09](evidence/09-collector-capture-session2.txt)):
- *Setup.* ZCode was additionally launched with `--proxy-server=http://127.0.0.1:8899`, so every Electron session, including the main process, went through the gate. The session ran inside the canary workspace, the agent read `notes.txt`, and ZCode was quit gracefully.
- *Captured.* 29 payloads in this run, 25 RUM and 4 `zcode-cli-agent` OTLP **metrics**. Across both runs: 45 (41 RUM, 4 metrics). The metrics are duration histograms for turns, steps, model calls, tools and commands, labelled by outcome, tool name, command category, model and error category. They contain no account, device, user or UUID identifiers. **No OTLP traces were sent at any point, including graceful shutdown.**
- *Content.* All 45 payloads decoded fully (41 JSON, 4 uncompressed protobuf). A scan across raw, gzip, deflate and embedded-base64 decodings found prompt canaries ×2, the tool canary, `notes.txt` and the workspace name **0 times**. The Windows username appears only inside RUM page URLs (`file:///C:/Users/<user>/…/app.asar/…`), 10 times.
- *Positive control.* The same canaries occur in the model-API request bodies captured by the gate: prompt canary 1 in 13, prompt canary 2 in 2, tool canary in 1. They therefore passed through the client and are detectable by the method.
- *Network.* 0 frames to the collector ranges and 0 `ERR_NETWORK_ACCESS_DENIED`. Hosts contacted through the gate: `api.z.ai`, `zcode.z.ai`, `cdn-zcode.z.ai`. The gate blocked only `zcode.z.ai/api/v1/marketing/touch` (6×). The `Telemetry report failed` exceptions (20) are consistent with those refusals, though a one-to-one mapping was not established. Also seen: a signed client-authentication call, `api.z.ai/api/paas/<hash>/v2/client`, carrying `{accessToken, nonce, sig, ts}`.

**Assessment.** The locally substituted collector captured telemetry configured for the Beijing endpoint, including pseudonymous account- and device-linked behavioural metadata: model selection, call timing and latency, interaction counts, and tool usage. The intercepted RUM payloads also carried the Windows computer name and a username embedded in a file URL. In two canary-marked sessions **no exact matches to the planted prompt or file-content markers were detected** in locally captured telemetry. The trace exporter, whose schema includes `gen_ai.*.message` fields, did not transmit, so its behaviour when active remains untested.

## 8. Workspace-snapshot upload incident (Sept 2026): exposure check

**Background.** Researcher Ferstar ([write-up](https://blog.ferstar.org/en/posts/zcode-silent-workspace-snapshot-upload/)) found that ZCode packed opened workspaces into a `tar.gz`, encrypted it (AES-256-CTR, key wrapped with RSA-OAEP-SHA256 using a server-supplied public key), and uploaded it via `zcode.z.ai/api/v1/snapshot/upload-credential` to an Aliyun OSS bucket `zcode-prod`.
- The archive included `.git` objects, LFS, reflogs and global app config.
- It was on by default while logged in, with no opt-out.
- Confirmed in 3.12.3. Removed in **3.14.0** (Z.ai also disabled Repo Wiki).
- Z.ai states the bucket was deleted, as confirmed by CAICT and NSFOCUS, whom Z.ai commissioned. Coverage: [InfoWorld](https://www.infoworld.com/article/4225022/), [The Standard](https://www.thestandard.com.hk/innovation/article/343354/ZAI-open-sources-ZCode-after-coding-tool-uploads-local-data-silently), [Silicon UK](https://www.silicon.co.uk/cloud/ai/z-ai-programming-trust-631667).

**This host (check run 2026-10-28; output in [`evidence/06-snapshot-exposure.txt`](evidence/06-snapshot-exposure.txt)):**

| Check | Result |
|---|---|
| Versions run | 3.12.3 (first seen 2026-09-17, **affected**) → 3.14.0 (2026-09-19) → … → 3.16.3. `~\.zcode` exists since 2026-06-19, and earlier versions left no record. |
| Pre-fix ZCode sessions | 2,321 session files, 2026-06-25 … 2026-09-19 (7 sessions in Jun, 12 in Jul, 14 in Aug, 18 in Sep) |
| Folders open in pre-fix sessions | **Git repos (full history in scope):** `[private workspace path withheld]` (851 MB `.git`), `[private workspace path withheld]`, `[private workspace path withheld]`, `[private workspace path withheld]`, `[private workspace path withheld]`, `[private workspace path withheld]`. **Plain folder:** `[private workspace path withheld]` |
| `*.enc` archives / `checkpoints` folders / snapshot state JSON | none |
| Snapshot strings in ZCode logs | none, but logs only reach back to 2026-10-15 |
| ZCode Chromium profile (`%APPDATA%\ZCode`) | recreated 2026-10-26 by the Windows reinstall; connection history lost |
| Upload code in installed 3.16.3 | absent. The only remaining `upload-credential` is `/feedback/attachment/upload-credential` (user-filed tickets). The `browser-use` plugin only carries the settings schema (`repoSnapshotIndexingEnabled` default `false`). |

**Conclusion.** The host was **exposed**: it ran an affected version while working in the folders above. Whether an upload completed **cannot be determined** from the host. Local archives were removed (likely by the 3.14.0 migration), logs rotated, and the OS reinstall erased SRUM per-app network accounting and the ZCode browser profile. Even the researcher could not observe server-side acceptance locally. Recommended:
- Rotate any secret ever committed in those repos (history included).
- File a GDPR Art. 15 access / Art. 17 erasure request with the policy's controller (JINGSHENG HENGXING TECHNOLOGY PTE. LTD), asking specifically about workspace snapshots linked to the account.

## 9. Corollary

*Scope: one Windows 11 host, ZCode 3.16.3, observations on 2026-10-28, re-verified from the raw captures in the same day.*

**Established, with the method that supports each finding**
1. The ZCode 3.16.3 package configures an Alibaba Cloud ARMS project in region `cn-beijing` as the destination for real-user monitoring and OpenTelemetry export (static analysis, §3).
2. During normal use, the client sends RUM payloads to that destination at intervals of seconds to minutes, including while idle (TLS SNI capture, §1; local-collector capture, §7.1).
3. Those payloads contain an account identifier, a persistent device identifier, session identifiers, the Windows computer name, the Windows username (within file URLs), OS and application metadata, and per-interaction usage events: messages sent, model calls with latency, and tool executions (decoded payloads, n = 41).
4. The agent's OTLP metrics, sent to the same destination, contain aggregated durations and categorical labels and no identifiers (decoded payloads, n = 4).
5. In two sessions with canary-marked prompts and file content, 0 of 45 payloads contained the canaries, while the model-API traffic did (positive control). In a third session of real work, 26,869 content fingerprints from 17 model requests matched 0 of 76 non-inference payloads (evidence/10). In these sessions no verbatim canary values or selected exact 40-character fingerprints of captured model inputs were detected in the monitored non-inference payloads; this cannot rule out unobserved, shortened, transformed or encoded exports.
6. The telemetry categories observed are largely itemised in ZCode's international privacy policy. Its reference to processing "generally" in Singapore does not exclude transfers abroad; the specific Beijing destination and safeguards remain insufficiently explained by the reviewed policy (§4).

**Not established**
- Content handling by the OTLP *trace* exporter, which did not transmit in either session.
- Behaviour under other versions, feature flags, remote configurations, operating systems or longer use.
- Any server-side processing, retention, access or onward use of the received data, including use for model training. None of these is observable from the client.
- Transfers that would only occur in an environment unaltered by the instrumentation (see limitations).

**Limitations**
- *Sample.* Two sessions of about 10 and 18 minutes on a single host. Absence of content in this sample does not establish absence in general.
- *Observer effect.* The measurement changed the environment: hosts-file redirection, an injected CA (`NODE_EXTRA_CA_CERTS`), a forced proxy and an outbound firewall. The client's export behaviour, such as trace sampling or remotely configured switches, may differ under these conditions.
- *Detection method.* Canaries detect verbatim inclusion only. Hashed, summarised, tokenised or embedded representations of content would not be detected.
- *Attribution.* RUM was attributed to ZCode by hostname, application metadata and timing. Payload origin within the process tree was not individually traced.

**Interpretation**

Items 1–3 describe a transfer of pseudonymous personal data, in the sense of GDPR Art. 4(1) and Recital 26, from a host in the EU to infrastructure in mainland China, with the transfer continuing during idle periods. The data categories involved are largely itemised in ZCode's international privacy policy. The Windows computer name and username are not itemised. That policy describes processing "generally" in Singapore and does not name China. ZCode's Chinese policy, for the same application, names a Beijing controller and storage in China (§4). In a third monitored work session, selected exact content fingerprints were not detected on observed non-inference routes (evidence/10); unobserved routes or transformed excerpts remain untested. Whether the transfer has an adequate legal basis, transparency and transfer safeguards is a legal question outside the scope of this technical report. The measurements here neither demonstrate nor exclude the export of user content through the untested trace channel.

## Reproduction boundary

Host-side collection scripts, private raw captures, canary commitments and original Git history are excluded from this distribution. An internal record reports separate preservation of source evidence, but **verified encrypted backups and restoration checks have not been demonstrated in this review**. This is a redacted account rather than an independently reproducible package.

## 10. Independent bounded audit note (2026-10-28)

The original forensic result is **bounded**. Tests used one host and modified the client environment (firewall, injected CA, proxy and local collector). Remote acceptance, retention, training use, and unchanged-client payload contents were not verified. The app's international policy allowing overseas processing must not be represented as a Singapore-only data-residency guarantee. The Chinese-language policy may apply to a different account population; the contrasting controllers alone are not proof of contradictory legal terms.

The real-work content monitor uses fixed non-overlapping 40-character text windows, exact byte comparisons, and a limited source-text parser. It is sensitive to representation, source-window alignment and payload encoding. A detection count of zero is not a sensitivity bound or evidence of universal non-exfiltration. Separately launched executables and other networking paths may be outside the ZCode-executable firewall rule. The synthetic tests in [evidence/11](evidence/11-synthetic-monitor-audit.md) are independent logic probes, **not** a rerun of Windows traffic.
