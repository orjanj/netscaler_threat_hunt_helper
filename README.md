# NetScaler CTX697096 Threat Hunt Helper

## Table of contents

- [Quick start](#quick-start)
- [Scope, safety, and limitations](#scope-safety-and-limitations)
- [Requirements](#requirements)
- [Usage modes](#usage-modes)
- [How the script works](#how-the-script-works)
- [Interpreting output](#interpreting-output)
- [Recommended investigation workflow](#recommended-investigation-workflow)
- [Report handling](#report-handling)
- [Coverage summary](#coverage-summary)
- [Indicator reference](#indicator-reference)
- [Versioning policy](#versioning-policy)
- [Primary sources](#primary-sources)

A defensive Bash utility for hunting indicators and post-exploitation artifacts associated with **Citrix NetScaler ADC / NetScaler Gateway CTX697096**, with primary focus on observed exploitation of **CVE-2026-88771** and **CVE-2026-88772**. It also checks the documented SAML configuration precondition for **CVE-2026-88779** (CTX697174).

The script can be used in two ways:

1. **Offline hunting** against an extracted NetScaler support bundle, copied logs, configuration files, or other collected evidence.
2. **Live local hunting** on a NetScaler appliance, using non-remediating checks for files, configuration changes, processes, persistence, network state, and known indicators.

Each run writes a final **Hunt summary** to the terminal and, when report writing is enabled, to the report log. The summary includes how many sections ran, how many `ALERT`, `WARN`, and `ERROR` messages were logged, concrete bullet-list details for those messages when present, and a short assessment reminder. Text-search findings include the hunt section, file path, line number, and matching line. Very large detail lists are capped in the summary. When concrete finding details exceed the findings threshold, interactive runs prompt to write a separate findings file containing the full grouped detail list.

## Quick start

Check syntax before deployment:

```bash
bash -n netscaler_ctx697096_hunt.sh
```

Make the script executable if you want to run it directly:

```bash
chmod +x netscaler_ctx697096_hunt.sh
```

Run a complete offline hunt against copied evidence:

```bash
./netscaler_ctx697096_hunt.sh --offline /path/to/extracted-support-bundle
```

Run all live checks without writing the default local report file:

```bash
NETSCALER_HUNT_NO_REPORT=1 ./netscaler_ctx697096_hunt.sh --live-all
```

Show the built-in IOC set:

```bash
./netscaler_ctx697096_hunt.sh --show-iocs
```

## Scope, safety, and limitations

This script is provided for defensive security operations and incident response. Test it in your environment before relying on it operationally.

This is a threat-hunting helper, not a compromise verdict engine.

- A match is an investigation lead, not proof of compromise.
- No matches do not prove that an appliance is clean.
- If a NetScaler appliance was exposed while vulnerable, patch status alone should not be used to conclude that the appliance was not previously compromised.
- The IOC set is a point-in-time collection of public reporting and is not exhaustive.
- Exact IOC matching can miss intrusions when attackers rotate IPs, filenames, hashes, header names, web-shell locations, or persistence methods.
- Behavioral matches can have false positives and must be correlated with timestamps, configuration history, network telemetry, and known administrative activity.
- Prefer offline mode against copied evidence when forensic preservation matters.
- Live mode has not yet been validated on a live NetScaler appliance. Prefer offline mode for first use, and test live mode in a controlled maintenance window before relying on it operationally.
- Live checks are read-only by intent, but running tooling on an appliance can still alter volatile state or filesystem metadata.
- By default, the script writes a local report file unless `NETSCALER_HUNT_NO_REPORT=1` is set.
- The script does not patch, delete files, kill processes, restart services, reboot, modify NetScaler configuration, exploit vulnerabilities, validate vulnerabilities by sending malicious traffic, or automatically declare a device compromised or clean.
- The tool does not inspect memory/core dumps, automatically unpack every support-bundle/archive format, replace NetScaler Console IOC scanning, or replace a forensic or incident-response engagement.

The indicator set and hunting logic in version **1.3** were reviewed against public reporting available on **2026-10-03**. The campaign is evolving; always compare this repository with the latest Citrix advisory and current incident-response reporting before treating the built-in IOC set as complete.

## Requirements

### Offline requirements

Recommended environment:

- Bash 4.3 or later
- `find`
- `grep`
- `head`
- `tail`
- `awk`
- `sed` is not required by the script itself
- `zgrep` for compressed `.gz` log files
- one of `sha256sum`, `sha256`, or `openssl` for hash hunting

The script uses Bash associative arrays and namerefs, so a POSIX `/bin/sh` interpreter is not sufficient.

### Live requirements

Live mode must be executed in an environment that provides a compatible Bash runtime and sufficient permissions to read the relevant NetScaler files and process/network state.

Live mode has not yet been validated on a live NetScaler appliance. Treat the live checks as best-effort read-only hunting logic until they have been tested against the target appliance version and shell environment.

A NetScaler appliance may not provide Bash in the same way as a general-purpose Linux host. If Bash is not available or if evidence preservation matters, collect a support bundle / forensic copy and use **offline mode** from a separate analysis host instead.

## Usage modes

Files in this repository:

- `netscaler_ctx697096_hunt.sh` - interactive Bash threat-hunting script
- `README.md` - this document

### Installation

```bash
chmod +x netscaler_ctx697096_hunt.sh
```

Check syntax before deployment:

```bash
bash -n netscaler_ctx697096_hunt.sh
```

### Interactive mode

Run without arguments:

```bash
./netscaler_ctx697096_hunt.sh
```

The main menu provides:

```text
1) Complete offline hunt: copied logs/support bundle/local evidence
2) Complete live hunt: this NetScaler appliance (read-only)
3) Individual offline checks
4) Individual live checks
5) Show built-in IOCs and hashes
6) Show help
0) Exit
```

Use the complete offline or complete live options when you want the script to run the full relevant hunt without stepping through individual checks. Use the individual-check menus only when you deliberately want a narrower hunt.

### Offline mode

Analyze an extracted directory directly:

```bash
./netscaler_ctx697096_hunt.sh --offline /path/to/extracted-support-bundle
```

Or start the guided complete hunt:

```bash
./netscaler_ctx697096_hunt.sh --complete
```

The interactive offline menu allows you to run specific hunts:

```text
1) DTLS/NSPPE/pitboss + exploit behavior
2) Historical IOC IPs
3) Web shell/PHP/Apache patterns
4) Known file/path indicators
5) HTTP log pivots (.deb/.sig/.ico/vpn paths)
6) SHA-256 search of candidate files
7) Show IOC list
8) CVE-2026-88779 SAML configuration precondition
0) Back
```

#### Files searched offline

The recursive text search considers common log/configuration formats including:

```text
*.log
*.log.*
*.txt
*.conf
*.out
*.json
*.xml
*.csv
*.gz
messages*
ns.log*
httpaccess*
httperror*
sh.log*
```

`.gz` files are searched with `zgrep` when available.

The tool does not automatically unpack `.tgz`, `.tar.gz`, `.zip`, appliance images, or core dumps. Extract collected bundles before running the hunt if their contents are not already exposed as files.

### Live mode

Run all live checks:

```bash
./netscaler_ctx697096_hunt.sh --live-all
```

The interactive live menu lets you select individual checks:

```text
1) Known file artifacts and staging paths
2) SAML / second-wave pivots
3) Apache/PHP/httpd.conf persistence
4) DTLS / NSPPE / pitboss log findings
5) HTTP access/error log findings
6) /bin/sh SUID/SGID check
7) Processes + WHIPSHOT/SLAPSHOT IPC
8) Cron persistence (.nsmon etc.)
9) Privileged account / ns.conf (sec_monitor etc.)
10) Listeners/active connections + IOC IPs/domains
11) IOC IPs/domains in local logs
12) SHA-256 checks on high-risk paths
13) Show IOC list
14) CVE-2026-88779 SAML configuration precondition
```

The live checks do **not** patch, remove files, terminate processes, restart services, reboot the appliance, or modify NetScaler configuration.

The CVE-2026-88779 check searches readable `ns.conf` files for the Citrix-documented SAML SP/IdP directives `add authentication samlAction` and `add authentication samlIdPProfile`. A match indicates a configuration precondition to investigate, not proof that the appliance is vulnerable or exploited. The check does not determine the running software build; verify it separately with the NetScaler CLI (`show ns version`) and compare against the fixed builds in CTX697174. No specific attack-log signature is documented in the advisory, so the script does not treat generic SAML or DoS log messages as proof of this CVE.

#### Important forensic note about report files

By default, the script writes a timestamped report file in the current working directory:

```text
netscaler_hunt_YYYYMMDD_HHMMSS.log
```

That is a filesystem write. If you are running directly on an appliance and want to suppress the report file, use:

```bash
NETSCALER_HUNT_NO_REPORT=1 ./netscaler_ctx697096_hunt.sh --live-all
```

Or interactively:

```bash
NETSCALER_HUNT_NO_REPORT=1 ./netscaler_ctx697096_hunt.sh
```

You can select a report location explicitly:

```bash
NETSCALER_HUNT_REPORT=/path/to/report.log ./netscaler_ctx697096_hunt.sh --offline /evidence/netscaler
```

When many concrete finding details are collected, the script can write a separate findings file:

```text
netscaler_findings_YYYYMMDD_HHMMSS.txt
```

Interactive runs prompt before creating this file. Non-interactive runs create it automatically when normal report writing is enabled. You can tune or force this behavior:

```bash
NETSCALER_HUNT_FINDINGS_THRESHOLD=50 ./netscaler_ctx697096_hunt.sh --offline /evidence/netscaler
NETSCALER_HUNT_FINDINGS_FILE=/path/to/findings.txt ./netscaler_ctx697096_hunt.sh --offline /evidence/netscaler
NETSCALER_HUNT_FINDINGS_AUTO=1 ./netscaler_ctx697096_hunt.sh --offline /evidence/netscaler
NETSCALER_HUNT_FINDINGS_AUTO=0 ./netscaler_ctx697096_hunt.sh --offline /evidence/netscaler
```

`NETSCALER_HUNT_FINDINGS_AUTO=1` writes the findings file without prompting when the threshold is exceeded. `NETSCALER_HUNT_FINDINGS_AUTO=0` suppresses it.

`NETSCALER_HUNT_NO_REPORT=1` only prevents the script's report-file write. It does **not** make live execution forensically inert. Reading files, spawning processes, or the underlying filesystem's access-time behavior can still alter volatile/system state. For high-assurance evidence preservation, analyze a forensic copy instead of running tooling on the original appliance.

### Show the built-in IOC set

```bash
./netscaler_ctx697096_hunt.sh --show-iocs
```

For no report-file write:

```bash
NETSCALER_HUNT_NO_REPORT=1 ./netscaler_ctx697096_hunt.sh --show-iocs
```

## How the script works

### 1. Text and log search

The tool builds regular expressions from the built-in IOC arrays and behavioral pivots, then recursively searches eligible text/log files. Matches are capped per file/search to prevent a noisy log from flooding the console and report.

### 2. Compressed log search

Files ending in `.gz` are searched using `zgrep` when it is installed.

### 3. File/path hunting

The tool checks for known filenames and paths associated with reported post-exploitation activity.

Offline mode searches by filename inside the collected evidence tree. Live mode checks known absolute paths and also lists recently modified files in several high-risk NetScaler web/client directories.

### 4. Configuration hunting

Live mode reviews available `httpd.conf` and `ns.conf` locations for suspicious PHP handlers, aliases, privileged-account artifacts, and other known pivots.

### 5. Process and IPC hunting

Live mode examines process listings for WHIPSHOT/SLAPSHOT-related behavior and known payload/process names. It also checks for IPC artifacts such as `.uxdport` and `.uxdlock`.

### 6. Persistence hunting

The tool reviews:

- `/bin/sh` permission bits
- `/etc/crontab`
- `/nsconfig/crontab`
- `sec_monitor` references
- known staging/web-shell paths

### 7. Network hunting

Where available, live mode uses `sockstat` or `netstat` to inspect current listeners and connections. It checks active connections against the historical IOC IP set and highlights listeners in the `41000-41999` range associated with reported `nsmon` behavior.

### 8. Hash hunting

The script computes SHA-256 values only for selected candidate files and compares them with the built-in hash set.

## Interpreting output

The script uses three broad log levels:

- `INFO` - context, normal progress, or no match found
- `WARN` - a condition that needs interpretation or a hunt result that is not conclusive
- `ALERT` - a high-value exact artifact, hash, suspicious permission state, or active IOC connection that should be investigated immediately

An `ALERT` is still not an automated forensic conclusion.

## Recommended investigation workflow

A practical workflow is:

1. Preserve logs/support bundles before rotation where possible.
2. Run the offline hunt against a copy of the evidence.
3. Correlate any DTLS/NSPPE events with system crashes, `pitboss` messages, HTTP activity, and later file/configuration changes.
4. Check exact IOC hits against the time the appliance was patched and rebooted.
5. Investigate web-server configuration changes and web-access/error logs.
6. Review outbound network telemetry from NSIP/SNIP addresses.
7. Investigate local account/configuration changes such as `sec_monitor`.
8. If compromise is suspected, expand hunting to connected identity, PAM, StoreFront, Delivery Controller, firewall, SIEM, and other downstream systems.
9. Follow current Citrix and incident-response guidance for containment and remediation.

## Report handling

Reports can contain sensitive information, including:

- internal IP addresses
- usernames
- NetScaler configuration references
- paths and process data
- security telemetry

Store and transmit reports according to your incident-response and evidence-handling procedures.

Do not publish raw reports without reviewing and sanitizing them first.

## Coverage summary

The script combines indicators and behavioral hunting ideas from public reporting available as of **2026-10-04**.

- Citrix / NetScaler: affected product context, vulnerability preconditions, SAML applicability checks, and remediation guidance.
- Citrix CTX697174: read-only search for SAML SP/IdP configuration preconditions for CVE-2026-88779; patch/build verification and exploitation detection remain manual/out of scope.
- GTIG / Mandiant: DTLS/NSPPE log pivots, Apache/PHP manipulation, WHIPSHOT/SLAPSHOT-related pivots, SUID/SGID checks, suspicious VPN paths, and network indicators.
- Palo Alto Networks Unit 42: pre-disclosure infrastructure, web-shell paths, anomalous `GetUserName` activity, `.deb` web-shell filenames, SHA-256 indicators, fingerprinting URLs, log-poisoning pivots, Apache alias pivots, and web-shell command behavior.
- Beazley Security Labs / GreyNoise / Lupovis: exploitation/scanning IPs, DNS callback pivots, public PoC markers, second-wave SAML/log-injection delivery and callback pivots, Sliver payload hashes, and the GreyNoise `.ctxs.receiver` web-shell hash.
- LevelBlue / SpiderLabs: CVE-2026-88771 authentication/log-poisoning pivots, `sec_monitor`, staging artifacts, payload hashes, command-obfuscation pivots, and reverse-shell/payload/exfiltration infrastructure.
- Arctic Wolf Labs: secondary hunting set for `/var/1.py`, `/var/tmp/.nsmon`, `nsmon.pl`, cron persistence, high-port listeners, and payload retrieval/execution behavior.
- PitScaler: public IOC compilation and October 2/3 SAML issue context, including contested `pyrlnk.cc` / `pylrk.cc` spellings and nsaaad crash pivots.

## Indicator reference

See [IOCS.md](IOCS.md) for the built-in IP, domain, file/path, SHA-256, and behavioral hunting indicators.

These are historical hunting indicators, not a complete or permanent blocklist. An exact match needs surrounding context, and the absence of these indicators does not exclude exploitation.

## Versioning policy

Project releases use `x.y.z` versioning from `1.3.1` onward.

- Increment `y` when new IoCs, hunting pivots, or detection coverage are added.
- Increment `z` for documentation-only updates, changelog/README/IOC reference restructuring, wording fixes, and other small repository changes that do not add new IoCs or detection logic.
- Increment `x` only for a major compatibility or usage change.

The script's displayed `VERSION` tracks the built-in hunt logic and IoC set. Documentation-only patch releases may therefore appear in [CHANGELOG.md](CHANGELOG.md) without changing the script `VERSION`.

## Primary sources

The script combines indicators and behavioral hunting ideas from the following sources.

### Citrix / NetScaler

**Citrix CTX697096** - vendor security bulletin covering CVE-2026-88771 through CVE-2026-88778.

https://support.citrix.com/external/article/CTX697096

This is the authoritative source for affected versions, vulnerability preconditions, and vendor remediation guidance.

### Google Threat Intelligence Group / Mandiant

**Defending Against Active Exploitation of Citrix NetScaler ADC and Gateway Appliances**

https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances

The script uses GTIG/Mandiant observations for, among other things:

- DTLS/NSPPE exploitation-related log pivots
- `SSL_HANDSHAKE_FAILURE`
- `DTLSv1.0`
- `Handshake failure-Internal Error`
- NSPPE termination / `pitboss` behavior
- Apache/PHP handler manipulation
- `/tmp/.uxdport`
- `/tmp/.uxdlock`
- WHIPSHOT / SLAPSHOT-related HTTP header pivots
- suspicious `/vpn/media/` and `/vpn/scripts/` activity
- SUID/SGID checks on `/bin/sh`
- network indicators `143.198.7.94` and `157.254.167.12`

### Palo Alto Networks Unit 42

**Threat Brief: NetScaler Zero Days CVE-2026-88771 and CVE-2026-88772 Exploited in the Wild**

https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/

The script uses Unit 42 reporting for pre-disclosure infrastructure, web-shell paths, anomalous `GetUserName` activity, `.deb` web-shell filenames, SHA-256 indicators, fingerprinting URLs, log-poisoning pivots, Apache alias pivots, and web-shell command behavior.

### Beazley Security Labs / GreyNoise / Lupovis

**BSL-A1216: Citrix NetScaler zero-day prompts emergency shutdowns**

https://labs.beazley.security/advisories/BSL-A1216

The script uses Beazley Security Labs' consolidated public indicators for GreyNoise and Lupovis observations, including exploitation sources, DNS callback pivots, public PoC markers, second-wave SAML/log-injection delivery and callback pivots, Sliver payload hashes, and the GreyNoise `.ctxs.receiver` web-shell hash.

### PitScaler

**PitScaler - Citrix NetScaler Zero-Day Crisis**

https://pitscaler.com/

The script uses PitScaler as a public IOC cross-reference and for October 2/3 SAML issue context, including `213.209.159.55`, `/v`, `/t/`, nsaaad crash pivots, and the `pyrlnk.cc` / `pylrk.cc` spelling conflict.

### Citrix SAML guidance

**Security Update: Guidance for NetScaler SAML Authentication Deployments**

https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/

The script uses Citrix's SAML applicability checks for `add authentication samlAction` and `add authentication samlIdPProfile`.

### Citrix CTX697174 - CVE-2026-88779

**Citrix NetScaler ADC and Citrix NetScaler Gateway Security Bulletin for CVE-2026-88779**

https://support.citrix.com/external/article/CTX697174/citrix-netscaler-adc-and-citrix-netscale.html

Citrix states that the issue requires a NetScaler configured as a SAML SP or SAML IdP, and publishes fixed builds. The script checks those SAML configuration directives in readable live `ns.conf` files and collected offline configuration files. It does not determine whether a matching deployment is on an affected build, whether Gateway/AAA context applies, whether virtual patching is enabled, or whether exploitation occurred. Use the vendor bulletin to verify and remediate.

### LevelBlue Threat Hunt Operations & Research / SpiderLabs

**Citrix NetScaler CVE-2026-88771: Observed Exploitation Artifacts and Hunt Indicators**

https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators

The script uses LevelBlue reporting for:

- CVE-2026-88771 authentication/log-poisoning pivots
- `pitboss` / `NSPPE` command-injection strings
- `${IFS}` shell-obfuscation pivot
- `sec_monitor` privileged account
- `/flash/nsconfig` staging behavior
- `/tmp/update_result_3567cs.tgz`
- `.local_journal`
- `insight-new.js`
- `xua.html`
- `main.py`
- `update_c08937.pl`
- `/var/python/bin/customsnmpd` behavioral pivot
- reverse-shell, payload-hosting, exploit, and exfiltration infrastructure

### Arctic Wolf Labs

**Pack Alert - Arctic Wolf Labs observes active exploitation of Citrix NetScaler CVE-2026-88771**

Official Arctic Wolf account summary:

https://www.reddit.com/r/u_ArcticWolf_Official/comments/1wudni7/pack_alert_september_30_2026_arctic_wolf_labs/

The script uses the published observations as a secondary hunting set for:

- `/var/1.py`
- `/var/tmp/.nsmon`
- `nsmon.pl`
- cron persistence in `/etc/crontab` or `/nsconfig/crontab`
- listeners in the `41000-41999` range
- payload retrieval/execution behavior involving Python, Perl, Bash, shell, `curl`, and `wget`

### Additional authoritative context

CISA alert confirming global active exploitation:

https://www.cisa.gov/news-events/alerts/2026/09/27/critical-zero-day-vulnerabilities-exploited-citrix-netscaler-adc-gateway

NetScaler Console IOC documentation:

https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc.html

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history.
