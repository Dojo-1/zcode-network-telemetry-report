# ZCode network behaviour: forensic observations

*Technical investigation of client-side network activity, 28 October 2026. Findings are limited to the documented client versions, sessions and inspection methods. Redacted methodology and evidence summaries: [TECHNICAL-REPORT.md](TECHNICAL-REPORT.md); original raw captures and implementation tooling are not publicly distributed.*

## Scope

The investigation examined an installed ZCode desktop client on Windows using application-bundle inspection, DNS and TLS observations, an intercepting proxy, and a local substitute for the configured telemetry collector. It distinguishes **model-inference traffic**, which necessarily carries submitted context, from **additional client-generated traffic**. No server-side records were available.

## Findings

| Channel | Observation | Limitation |
|---|---|---|
| Model inference | Requests to `api.z.ai` contained submitted prompts and context, as expected for a hosted coding assistant. Alibaba-hosted infrastructure and a European network edge were observed. | Final processing location, retention and subsequent use were not established. |
| Telemetry | The packaged client referenced a Beijing-region Alibaba Cloud OpenTelemetry/RUM collector. TLS connections bearing its SNI were recorded, including during idle periods. Redirected sessions yielded 45 locally decoded payloads containing client, account/session and usage metadata. | The original remote server's acceptance, storage and use of these payloads were not observed. |
| Product events | Requests to a ZCode event/marketing endpoint were observed during proxy tests. | Downstream processing and retention were not observed. |
| Image-handling path | An agent tool-call record referenced a UCloud object-storage URL associated with the `cn-wlcb` region. | This observation does not establish the location or handling of every image. |
| Device risk-control | Alibaba risk-control hostnames were present in the inspected application package. | No corresponding request was observed in the fully proxied test session. |

### Did telemetry include submitted content?

Two instrumented sessions received **45 payloads** at a local replacement collector (**41 RUM/JSON and 4 OpenTelemetry metrics/protobuf**). Synthetic markers placed in submitted prompts and a file read by the agent were present in captured inference requests but had **zero exact matches in the collector payloads**. See [evidence/08](evidence/08-collector-capture.txt) and [evidence/09](evidence/09-collector-capture-session2.txt).

A separate monitored work session produced **17 model requests** and **76 captured non-inference payloads**. The monitor generated **26,869 fixed 40-character fingerprints** from selected model-request text and found **zero byte-exact matches** in those non-inference payloads ([evidence/10](evidence/10-monitored-work-session.txt)). These results are bounded negative observations, **not proof that no content is ever exported**.

The content detector can miss short excerpts, shifted fragments, text transformations, encoded material and traffic outside the monitored routes. A separate [synthetic sensitivity study](evidence/11-synthetic-monitor-audit.md) documents these limitations. The agent's OpenTelemetry *trace* exporter was not observed successfully sending a trace in the instrumented sessions; its potential content-bearing fields therefore remain an **untested path**. A trace-related field name in the package is not evidence that the field was transmitted.

## Policy and interpretation

The international ZCode privacy policy dated 15 June 2026 identifies a Singapore controller, describes processing **generally** in Singapore and allows transfers to other jurisdictions. A separate policy addresses the Chinese market. The observed Beijing-region collector raises a question about destination-specific disclosure and applicable safeguards, but the word *generally* does not establish Singapore-only processing.

The observations support the presence of additional telemetry and pseudonymous, potentially identifying metadata. They **do not establish** undisclosed model training, unauthorized access to source repositories, remote retention periods, legal noncompliance or malicious intent. Those issues require independent records or provider disclosure. A regional hostname identifies a service endpoint, not necessarily every subsequent storage or processing location.

## Separate historical issue: workspace snapshots

An [independent investigation](https://blog.ferstar.org/en/posts/zcode-silent-workspace-snapshot-upload/) reported a workspace-snapshot upload mechanism in earlier ZCode versions. Reporting indicates removal in version 3.14.0. The client-side records examined here do not establish whether any historical workspace upload completed or whether associated data were retained. This question is separate from the October telemetry measurements; see [the technical report](TECHNICAL-REPORT.md#8-workspace-snapshot-upload-incident-sept-2026-exposure-check). The restricted source repository contains an exposure-check script, omitted from this release candidate.

## macOS host (ZCode 3.15.1)

A second, independently running installation was examined read-only on macOS ([evidence/12](evidence/12-macos-host-observations.txt)). The 3.15.1 bundle contains the same Beijing ARMS trace and RUM endpoints. A socket record associated with the main ZCode process showed `8.130.222.161`, an A-record of that collector; the socket was `CLOSED` when inspected, so it was not an active-payload capture. That address is ARIN-registered and is not covered by APNIC's CN list, so the macOS script blocks collector addresses explicitly. A persistent device identifier is stored locally and passed to the renderer. A local workspace-snapshot state record dated 2026-06-24 was found. Its implementation is absent from the installed versions and its writing version could not be determined, so whether anything was transmitted is **inconclusive**. It does not establish an upload outside the publicly reported window.

## Evidence and reproduction boundaries

This text-only release candidate contains the technical account and **12 redacted evidence summaries**. The historical interception, local firewall and evidence-collection scripts are retained in restricted source material; no executable reproduction tooling, unmodified network captures or synthetic canary commitments are included. Their absence limits independent reproducibility.

| Included artifact | Purpose |
|---|---|
| [TECHNICAL-REPORT.md](TECHNICAL-REPORT.md) | Methodology, quantitative observations, attribution and explicit limitations |
| [evidence/](evidence/) | Sanitized network, collector and sensitivity summaries |

**Safety limitation:** local interception, hosts-file redirection and firewall rules can change the system being measured; a process-specific restriction may not cover child processes or alternate routes. Experimental proxy captures can contain confidential prompts and credentials and must stay in access-controlled storage. The original investigation reported owner-only capture controls, but those controls were not independently re-exercised as part of this release review.

### macOS protection: scope and limits

The following summarizes the original, non-distributed script design, **not verified protection for arbitrary installations**.

- **Routing, not isolation.** macOS pf filters by destination address, not by process. The gate and launcher route ZCode through the inspection proxy, but a ZCode or child process that ignores proxy settings can still reach z.ai directly. CN-allocated ranges, the Beijing collector addresses and the sinkholed side-channel hosts stay blocked either way. Enforced per-app egress needs an app firewall rule (for example LuLu or Little Snitch) limiting ZCode to `127.0.0.1:8899`.
- **Fail-safe updates.** At boot the last validated ruleset is loaded before any network access. APNIC refreshes are validated and swapped in atomically, and a failed refresh keeps the previous tables.
- **Private captures.** The gate writes captures owner-only (`umask 077`, data directory `700`). There is no retention limit yet, so delete `~/ZCodeGate/data` when it is no longer needed.
- **Reversible settings.** The first `configure` records ZCode's original proxy settings; `unconfigure` / `setup-macos.sh uninstall` restores them exactly.
- **Not yet tested:** the reboot path on real hardware, and an isolated end-to-end regression suite covering install, boot, firewall failure, bypass attempts and uninstall. `setup-macos.sh` checks are smoke tests, not security acceptance tests.

A limited comparison with OpenCode 1.19.4 is documented separately in [evidence/07](evidence/07-opencode-audit.txt); short tests of another client do not establish absence of telemetry under all configurations.

**Status:** evidence-supported findings are restricted to the listed observations and versions. No claim is made about provider-side training or storage. Corrections should preserve the original measurements and be recorded alongside new evidence.
