# ZCode network telemetry: what we saw, and what we didn't

**A client-side forensic investigation · 28 October 2026 · ZCode 3.16.3 (Windows), with a separate read-only look at 3.15.1 (macOS)**

A coding assistant needs to send prompts to a model. That's expected. The more interesting question is what **else** leaves the client: which endpoints receive telemetry, what fields are present, and what can we actually verify from our side of the connection?

This repository follows that question through application-bundle inspection, DNS and TLS observations, local interception, and bounded content tests. It separates **reported observations** from **configured behavior**, and both from claims about what happens on someone else's servers.

**Evidence provenance.** The network observations and payload counts are reported from the original investigator's records dated 28 October 2026. This public edition contains redacted evidence summaries, not independently inspectable raw packet captures or a separate reproduction of the network experiments. The [synthetic detector checks](evidence/11-synthetic-monitor-audit.md) examine detection logic, not the original network measurements.

**The short answer:** the examined ZCode build configured Alibaba Cloud ARMS telemetry endpoints in the `cn-beijing` region. The investigator recorded TLS connections to the collector hostname and locally captured account/device-linked usage metadata using a substitute receiver. We did **not** detect the planted prompt/file markers in those telemetry samples, and we did **not** observe transmitted OpenTelemetry *traces*. Neither observation proves that content can never leave through another route or configuration.

[Read the technical report](TECHNICAL-REPORT.md) · [Browse the redacted evidence](evidence/)

## At a glance

| Question | What the investigation found |
| --- | --- |
| **Where did the client connect?** | The inspected package configured a Beijing-region ARMS RUM/OpenTelemetry endpoint; TLS SNI observations matched that collector, including during an idle observation window. |
| **What was in the sampled telemetry?** | The local substitute received RUM events with account, device, session, application and interaction metadata, plus aggregated OpenTelemetry metrics. |
| **Was prompt or file content found?** | Not by the specified exact-match tests in the monitored non-inference payloads. That is a bounded negative result, not a universal safety claim. |
| **Did we see exported OTLP traces?** | No. Trace-related schema fields in a bundle are not proof of transmitted trace contents. |
| **Where was data stored or used?** | Not established. We had no server-side access, retention logs or training records. |

### The numbers, without the leap

| Observation window | Sample | Content detection result |
| --- | --- | --- |
| Two instrumented local-collector sessions | **45** non-inference collector payloads: **41 RUM JSON** and **4 OTLP metrics** | **0 exact matches** for the planted prompt/file canaries in the local collector. The file-content canary was exercised **only in session 2**, where it was detected in captured model-inference traffic. |
| A separately monitored work session | **17** model requests, **76** observed non-inference payloads, **26,869** fixed 40-character fingerprints from selected model-request text | **0 byte-exact fingerprint matches** in the observed non-inference payloads |

The distinction matters: a zero in these tests means **nothing matched these particular probes in these particular captures**; it is not a statistical upper bound on other content exports. Short quotations, changed encodings, summaries, altered text boundaries, other routes and different client states could escape detection. The local proxy, host redirection, injected certificate authority and firewall also changed the environment being measured.

[Session 1](evidence/08-collector-capture.txt) · [Session 2](evidence/09-collector-capture-session2.txt) · [Monitored work session](evidence/10-monitored-work-session.txt) · [Detector sensitivity and limits](evidence/11-synthetic-monitor-audit.md)

## Two different flows, two different questions

**1. Model inference.** Requests to `api.z.ai` included the prompts and context supplied to the hosted assistant. That is expected for a cloud model. Observing a European network edge does not tell us where the provider ultimately processes or stores the request.

**2. Client-generated telemetry.** The investigated build configured a separate ARMS collector, with endpoint names identifying a Beijing region. TLS hostname evidence and a locally redirected collector support the identification of a telemetry channel. The replacement receiver decoded operational metadata such as model choice, call timing/latency, tool-use events, device information and account/session identifiers. **Acceptance or retention by the actual remote collector was not directly observed.**

Other observed or configured channels included a ZCode product-event endpoint, an image-related UCloud URL, and device risk-control hostnames. Their appearance in a package or single tool record is not proof that every associated feature transmitted data in the monitored sessions. See [the full endpoint discussion](TECHNICAL-REPORT.md) and [sanitized bundle observations](evidence/04-bundle-endpoints.txt).

## Why destination and disclosure matter

The international ZCode privacy policy reviewed for this investigation described processing **generally** in Singapore and allowed transfers to other jurisdictions. A Beijing-region telemetry endpoint therefore raises legitimate questions about destination-specific disclosure, the applicable controller, data categories and cross-border safeguards—but *generally* is not a promise of Singapore-only processing.

The captured telemetry included pseudonymous but potentially identifying metadata. The record does **not** establish covert source-code exfiltration, undisclosed model training, unlawful processing, malicious intent, server-side storage locations or retention periods. Those stronger conclusions require evidence we did not have.

The technical report compares the policies as reviewed on 28 October 2026. Policy text and service configurations can change; consult the provider's current notices for present-day terms.

## An earlier, separate question: workspace snapshots

A [separate investigator's report](https://blog.ferstar.org/en/posts/zcode-silent-workspace-snapshot-upload/) described a historical ZCode workspace-snapshot upload mechanism in earlier releases, reportedly removed in version 3.14.0. The Windows host examined here had run an affected version, but its remaining local records **could not determine whether an upload completed or whether any associated data were retained**. This is **not** evidence that the October telemetry channel uploaded repositories.

[Read the bounded historical exposure assessment](evidence/06-snapshot-exposure.txt).

## Windows and macOS are not the same experiment

The detailed interception and content tests concerned **ZCode 3.16.3 on Windows**. A second **3.15.1 macOS** installation was examined read-only: its package contained similar collector endpoints, and a socket record associated with ZCode referenced a collector IP. That socket was **closed** when inspected, so it did not reveal payload contents. The macOS observations do not replicate the Windows content experiment.

[Read the macOS notes](evidence/12-macos-host-observations.txt).

## Explore the record

- **[TECHNICAL-REPORT.md](TECHNICAL-REPORT.md)** — attribution, methods, observed values, corrections and limitations.
- **[Network evidence](evidence/)** — sanitized DNS, TLS SNI, host observations, collector summaries and synthetic checks.
- **[Content-monitor limitations](evidence/11-synthetic-monitor-audit.md)** — what exact matching detects and what it can miss.

This publication deliberately **does not include** unredacted packet captures, raw inference bodies, local machine/account identifiers, canary commitments or the original interception/firewall scripts. That protects sensitive material but limits independent reproduction. A successful Git sanitization check is not an external validation of the measurements or an independent privacy/legal review.

## Questions worth answering next

We would welcome verifiable clarification from the provider on the actual destinations and retention of telemetry, the identity fields transmitted, regional routing and safeguards, and whether OTLP traces can carry user or tool content under configurations not exercised here. Independent replication with a clearly documented version, capture route, positive controls and failure cases would be especially useful.

If you spot an error, [open an issue](https://github.com/Dojo-1/zcode-network-telemetry-report/issues) with the exact passage and supporting evidence. **Please do not post credentials, account IDs, private prompts or raw captures in a public issue.** Corrections should narrow or strengthen individual claims without erasing the original observations.

---

*The packets tell us which connections and fields were visible under a particular test. They do not hand us the server's logbook. This report tries to keep that boundary visible.*
