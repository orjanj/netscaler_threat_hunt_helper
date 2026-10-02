# NetScaler CTX697096 Threat Hunt Helper

## Table of contents

- [Files](#files)
- [Intelligence scope and verification date](#intelligence-scope-and-verification-date)
- [Primary sources](#primary-sources)
- [Built-in network indicators](#built-in-network-indicators)
- [Built-in file and path indicators](#built-in-file-and-path-indicators)
- [Built-in SHA-256 indicators](#built-in-sha-256-indicators)
- [Behavioral hunting pivots](#behavioral-hunting-pivots)
- [Requirements](#requirements)
- [Installation](#installation)
- [Interactive mode](#interactive-mode)
- [Offline mode](#offline-mode)
- [Live mode](#live-mode)
- [Show the built-in IOC set](#show-the-built-in-ioc-set)
- [How the script works](#how-the-script-works)
- [Interpreting output](#interpreting-output)
- [Recommended investigation workflow](#recommended-investigation-workflow)
- [What this script does not do](#what-this-script-does-not-do)
- [False positives and false negatives](#false-positives-and-false-negatives)
- [Report handling](#report-handling)
- [Version notes](#version-notes)
- [Disclaimer](#disclaimer)

A defensive Bash utility for hunting indicators and post-exploitation artifacts associated with **Citrix NetScaler ADC / NetScaler Gateway CTX697096**, with primary focus on observed exploitation of **CVE-2026-88771** and **CVE-2026-88772**.

The script can be used in two ways:

1. **Offline hunting** against an extracted NetScaler support bundle, copied logs, configuration files, or other collected evidence.
2. **Live local hunting** on a NetScaler appliance, using non-remediating checks for files, configuration changes, processes, persistence, network state, and known indicators.

Each run writes a final **Hunt summary** to the terminal and, when report writing is enabled, to the report log. The summary includes how many sections ran, how many `ALERT`, `WARN`, and `ERROR` messages were logged, concrete bullet-list details for those messages when present, and a short assessment reminder. Text-search findings include the hunt section, file path, line number, and matching line. Very large detail lists are capped in the summary. When concrete finding details exceed the findings threshold, interactive runs prompt to write a separate findings file containing the full grouped detail list.

> **Important:** This is a threat-hunting helper, not a compromise verdict engine. A match is a lead that needs investigation. No matches do not prove that an appliance is clean.

> **Live testing status:** Live mode has not yet been validated on a live NetScaler appliance. Prefer offline mode for first use, and test live mode in a controlled maintenance window before relying on it operationally.

## Files

- `netscaler_ctx697096_hunt.sh` - interactive Bash threat-hunting script
- `README.md` - this document

## Intelligence scope and verification date

The indicator set and hunting logic in version **1.1** were reviewed against public reporting available on **2026-10-02**.

The campaign is evolving. IP addresses, payload names, hashes, web-shell paths, and techniques can change quickly. Always compare this repository with the latest Citrix advisory and current incident-response reporting before treating the built-in IOC set as complete.

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

The script uses Unit 42 reporting for pre-disclosure infrastructure, web-shell paths, anomalous `GetUserName` activity, `.deb` web-shell filenames, and SHA-256 indicators.

### Beazley Security Labs / GreyNoise / Lupovis

**BSL-A1216: Citrix NetScaler zero-day prompts emergency shutdowns**

https://labs.beazley.security/advisories/BSL-A1216

The script uses Beazley Security Labs' consolidated public indicators for GreyNoise and Lupovis observations, including exploitation sources, DNS callback pivots, public PoC markers, and the GreyNoise `.ctxs.receiver` web-shell hash.

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

## Built-in network indicators

The current script contains the following historical IPv4 indicators.

### GTIG / Mandiant

```text
143.198.7.94
157.254.167.12
```

### Unit 42

```text
45.61.136.143
66.227.183.84
77.83.199.39
104.28.215.137
104.28.215.136
104.248.244.66
104.28.247.136
104.28.247.137
162.33.178.9
193.149.176.207
216.245.184.164
78.47.24.217
66.135.19.18
167.99.111.203
142.93.85.227
104.248.74.206
137.184.91.207
139.180.152.138
```

`104.28.215.136` and `104.28.247.137` are Cloudflare WARP egress addresses reported by Unit 42. Treat them as correlation pivots only, not as standalone blocklist entries.

### LevelBlue

```text
70.172.58.168
45.141.21.130
162.243.36.88
173.40.135.209
47.230.224.154
92.118.204.229
87.224.84.82
31.56.197.72
62.133.62.80
23.27.143.20
64.94.85.67
```

### Beazley / GreyNoise / Lupovis

```text
149.104.78.141
138.28.234.38
82.167.14.7
85.203.46.191
154.217.251.226
```

These are **historical hunting indicators**, not a complete or permanent blocklist. An IP hit needs surrounding context, and the absence of these IPs does not exclude exploitation.

## Built-in file and path indicators

```text
/vpn/scripts/linux/nsgclient18.deb
/vpn/scripts/linux/nsgser18.deb
/vpn/scripts/linux/nsg64.deb
/vpn/scripts/linux/nsgsupport.deb
/vpn/scripts/linux/nsgpackage64.deb
/vpn/scripts/linux/nsgbuild.deb
/logon/LogonPoint/Authentication/GetUserName
/var/netscaler/logon/LogonPoint/custom/.ctxs.receiver
/var/netscaler/gui/vpn/scripts/linux/nsgclient.sig
/var/netscaler/gui/vpn/scripts/linux/e6ee7c85.sig
/netscaler/ns_gui/vpn/scripts/linux/nsgclient.sig
/netscaler/ns_gui/vpn/scripts/linux/e6ee7c85.sig
/vpn/media/nsgclient.ico
/var/netscaler/logon/LogonPoint/.local_journal
/tmp/.uxdport
/tmp/.uxdlock
/tmp/update_result_3567cs.tgz
/var/netscaler/logon/insight-new.js
/var/netscaler/logon/LogonPoint/xua.html
/var/tmp/.nsmon
/var/1.py
```

Some of these may be short-lived because observed payloads included cleanup behavior. Missing files therefore do not prove that execution did not occur.

## Built-in SHA-256 indicators

```text
ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec
  Unit 42 - nsg64.deb web shell

1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d
  Unit 42 - encoded payload text

79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186
  Unit 42 - decoded shell-script text

e9fe43968c6c0955300e3bc4d7fb0b05a18570b4733aaf4f5c6f7f09be5a242c
  LevelBlue - main.py

974b69782fdf5d67b97cfd508465939e44ee10798dbcc1e82b92d78776bad938
  LevelBlue - update_c08937.pl

6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7
  GreyNoise / Beazley - .ctxs.receiver web shell
```

Hash hunting is deliberately limited to plausible payload/configuration file types and selected high-risk paths so that the tool does not hash an entire large appliance image unless necessary.

## Behavioral hunting pivots

The script also searches for behavior that can be more durable than exact IOCs.

Examples include:

- DTLS handshake failures correlated with NSPPE termination
- `pitboss PPE unexpectedly died`
- `pitboss PPE missed too many heartbeats`
- `NOT restarting NSPPE`
- `orphan rings`
- `${IFS}` in attacker-controlled command strings
- unexpected PHP execution for `.deb`, `.sig`, `.tgz`, `.rpm`, or other non-PHP resources
- suspicious `AddHandler`, `AddType`, `AliasMatch`, and `php_flag` directives
- web-shell functions such as `eval()`, `passthru()`, `shell_exec()`, and `base64_decode()`
- `HTTP_NSC_LDAP`
- `HTTP_NSC_CLIENTTYPE`
- `HTTP_X_UX*`
- `INDEX:` User-Agent payload staging
- `ns-88771-poc`
- `NX-CVE-OK`
- `httpworkbench.com`
- `NSC_TASS`
- `CsrfToken`
- `e826d7ddf3c85920`
- `7489a0f93c67fa5cdaeb4b921d90594d`
- suspicious activity involving `/vpn/media/` and `/vpn/scripts/`
- suspicious activity involving `/nf/auth/doAuthentication.do` and `/logon/LogonPoint/Authentication/GetUserName`
- `sec_monitor`
- `customsnmpd`
- SUID/SGID permissions on `/bin/sh`
- cron references to `.nsmon`, `curl`, `wget`, Python, Perl, or known staging paths
- unexpected listeners in TCP/UDP port range `41000-41999`

Behavioral matches can have false positives. They must be correlated with timestamps, configuration history, network telemetry, and known administrative activity.

## Requirements

### Offline mode

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

### Live mode

Live mode must be executed in an environment that provides a compatible Bash runtime and sufficient permissions to read the relevant NetScaler files and process/network state.

Live mode has not yet been validated on a live NetScaler appliance. Treat the live checks as best-effort read-only hunting logic until they have been tested against the target appliance version and shell environment.

A NetScaler appliance may not provide Bash in the same way as a general-purpose Linux host. If Bash is not available or if evidence preservation matters, collect a support bundle / forensic copy and use **offline mode** from a separate analysis host instead.

## Installation

```bash
chmod +x netscaler_ctx697096_hunt.sh
```

Check syntax before deployment:

```bash
bash -n netscaler_ctx697096_hunt.sh
```

## Interactive mode

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

## Offline mode

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
8) Show IOC list
```

### Files searched offline

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

## Live mode

Run all live checks:

```bash
./netscaler_ctx697096_hunt.sh --live-all
```

The interactive live menu lets you select individual checks:

```text
1) Known file artifacts and staging paths
2) Apache/PHP/httpd.conf persistence
3) DTLS / NSPPE / pitboss log findings
4) HTTP access/error log findings
5) /bin/sh SUID/SGID check
6) Processes + WHIPSHOT/SLAPSHOT IPC
7) Cron persistence (.nsmon etc.)
8) Privileged account / ns.conf (sec_monitor etc.)
9) Listeners/active connections + IOC IPs
10) IOC IPs in local logs
11) SHA-256 checks on high-risk paths
12) Show IOC list
```

The live checks do **not** patch, remove files, terminate processes, restart services, reboot the appliance, or modify NetScaler configuration.

### Important forensic note about report files

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

## Show the built-in IOC set

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

## What this script does not do

The tool intentionally does not:

- exploit or validate the vulnerabilities by sending malicious traffic
- generate exploit payloads
- patch NetScaler
- modify configuration
- remove suspected malware
- kill suspicious processes
- restart services or reboot appliances
- automatically declare a device compromised or clean
- inspect memory/core dumps
- automatically unpack every support-bundle/archive format
- replace NetScaler Console IOC scanning
- replace a forensic or incident-response engagement

## False positives and false negatives

Some strings used by this tool are deliberately broad hunting pivots. For example, `AddHandler`, `AliasMatch`, `/vpn/media/`, Python processes, or isolated DTLS failures can occur legitimately.

Conversely, exact IOC matching can miss an intrusion because attackers can rotate:

- IP addresses
- filenames
- hashes
- header names
- web-shell locations
- persistence methods

Behavioral correlation is therefore more important than treating the IOC list as a signature database.

## Report handling

Reports can contain sensitive information, including:

- internal IP addresses
- usernames
- NetScaler configuration references
- paths and process data
- security telemetry

Store and transmit reports according to your incident-response and evidence-handling procedures.

Do not publish raw reports without reviewing and sanitizing them first.

## Version notes

### 1.1 - 2026-10-02

- Added Unit 42 September 30 indicators: additional pre-disclosure IPs, Cloudflare WARP correlation IPs, `.deb` web-shell filenames, `GetUserName` activity, `.sig` filenames, and related web paths.
- Added Beazley/GreyNoise/Lupovis public indicators: exploitation/scanning IPs, `httpworkbench.com`, `NX-CVE-OK`, `ns-88771-poc`, and the GreyNoise `.ctxs.receiver` SHA-256.
- Added web-shell/payload pivots for `INDEX:`, `e826d7ddf3c85920`, and `7489a0f93c67fa5cdaeb4b921d90594d`.
- Bumped script version to 1.1.

### 1.0 - 2026-10-01

- Converted all user-facing script text to English.
- Added complete LevelBlue IPv4 set used by the current hunt logic.
- Added `45.141.21.130` reverse-shell C2 hunting.
- Added `${IFS}` and `customsnmpd` behavioral pivots.
- Added `NETSCALER_HUNT_NO_REPORT=1` for report-file suppression.
- Added `NETSCALER_HUNT_REPORT` for choosing a report path.
- Clarified that live checks are non-remediating but a report file is written by default.
- Added documentation and source provenance.

## Disclaimer

This script is provided for defensive security operations and incident response. Test it in your environment before relying on it operationally. The IOC set is a point-in-time collection of public reporting and is not exhaustive.

If a NetScaler appliance was exposed while vulnerable, patch status alone should not be used to conclude that the appliance was not previously compromised.
