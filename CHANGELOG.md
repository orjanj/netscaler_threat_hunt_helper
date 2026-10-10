# Changelog

## 1.11 - 2026-10-10

- Reviewed Huntback's CVE-2026-88771 analysis, using Thomas Poppelgaard's timeline article only as supporting context.
- Added Huntback network indicators for OOB proving, config theft, direct POST exfiltration, ns_helper staging, tunnel-fronted droppers, Perl droppers, PHP webshell delivery, and log-channel C2 activity.
- Added Huntback tunnel-fronted dropper domains `pinggy.net` and `serveousercontent.com`.
- Added Huntback log-channel C2 and staging pivots for `fefypa:`, `fdylo9:`, `c88771_<ip>.txt`, `/tmp/.p`, and `/var/tmp/.p`.
- Bumped script version to 1.11.

## 1.10 - 2026-10-09

- Reviewed the NetScaler Console CVE-2026-107406 remediation guidance and noted that it publishes Console CVE Detection / upgrade workflow guidance, not standalone exact IOCs.
- Added Citrix NetScaler security bulletin blog / IOC guidance source coverage.
- Added community-observed file/path pivot `/vpn/scripts/linux/nsgclient18_32.deb` adjacent to the existing `nsgclient18.deb` indicator.
- Bumped script version to 1.10.

## 1.9 - 2026-10-08

- Added watchTowr post-exploitation IOC source coverage and the watchTowr Labs public IOC repository.
- Added watchTowr source IPs, OAST callback domains, Sliver C2/staging pivots, dropped file paths, webshell markers, backdoor account/key pivots, and SSH backdoor artifacts.
- Added watchTowr SHA-256 IOCs for `ns_helper`, `update_c08937.pl`, embedded `.local_journal` webshell, `/var/1`, and `walk` SSH backdoor binaries.
- Expanded live checks for `ns_helper`, `walk`, `gw_health`, and related cron/hash candidates.
- Bumped script version to 1.9.

## 1.8 - 2026-10-07

- Added Censys log-context pivots `AAAD API: sending login req` and `process_kernel_socket` for CVE-2026-88771 detection artifacts.
- Added Decryption Digest CVE-2026-88779 SAML hunting pivots for `/saml/logout` and unusually large `Content-Length` values on `/saml/login`, `/saml/logout`, or `/cgi/samlauth` requests.
- Excluded source-branded watchTowr/`wtw*` artifact strings from active detection coverage.
- Bumped script version to 1.8.

## 1.7 - 2026-10-07

- Added SOCRadar NetScaler C2 source coverage for CVE-2026-88771 exploitation automation.
- Added SOCRadar network IOC `45.143.130.195` for NetScaler C2 HTTP on TCP/8899 and DNS OOB beaconing on port 53.
- Added SOCRadar toolkit SHA-256 IOCs for `run.sh`, `targets.py`, `probe.py`, `exploit.py`, `c2_server.py`, and `pollctl.py`.
- Added SOCRadar behavioral/file pivots including `/tmp/.nsagent`, `/s/<bid>`, `/a/<bid>`, `/p/<bid>?h=<hex_hostname>&u=<hex_username>&src=agent`, `/c/<bid>`, `/r/<bid>?d=<hex>`, `pitboss NSPPE-00;`, `/s/<bid>|sh`, and `;# unexpectedly died`.
- Added SOCRadar injection endpoint coverage for `/nitro/v1/config/login`, `/nitro/v1/config/login?action=login`, `/nf/auth/getAuthenticationRequirements.do`, `/vpn/index.html`, and `/logon/LogonPoint/index.html`.
- Bumped script version to 1.7.

## 1.6 - 2026-10-07

- Added source coverage for CERT-EU, Elastic detection rules, GreyNoise, TENEX, and Thomas Poppelgaard's NetScaler timeline/checker notes.
- Added network IOCs: `78.128.113.10`, `194.26.29.88`, `138.199.200.90`, `158.94.209.12`, `68.178.160.183`, `5.188.206.226`, `instances.httpworkbench.com`, `echvista.com`, and `gsocket.io`.
- Added web/probe path IOCs: `/logon/LogonPoint/tmindex.html`, `/epa/scripts/linux/nsepa.deb`, and `vp_probe_nonexist`; expanded script/log coverage for the existing `/nf/auth/doAuthentication.do` pivot.
- Added exploit marker and artifact file IOCs: `/var/vpn/bookmark/nx_verify.html`, `/netscaler/ns_gui/vpn/nx_verify.html`, `/netscaler/ns_gui/vpn/id009.txt`, `/netscaler/ns_gui/vpn/rce.txt`, `/tmp/v`, `/var/tmp/v`, `/tmp/watchTowr`, `/var/tmp/wtw888`, `/var/tmp/boom`, `/var/tmp/sh`, `/netscaler/ns_gui/admin_ui/e.txt`, `/netscaler/ns_gui/admin_ui/log.txt`, and `/lula`.
- Added Platypus post-exploitation IOCs: `/var/core/.ns-cache/client.crt`, `/var/core/.ns-cache/client.key`, `system-health`, `health-monitor`, `healthd`, `gs-netcat`, `_platypus-mesh._tcp`, and `platypus-ingress`; expanded script/file-path coverage for the existing `/var/python/bin/customsnmpd` and `application/x-protobuf-platypus-v2` pivots.
- Added log-pattern IOCs for generic `pitboss` shell metacharacters or URL-encoded shell syntax, `NSPPE-00`, `NO_AUTH`, generalized `update_result_*.tgz` matching, `admin_ui/(e|log).txt`, `nx_verify.html`, `wtw*`, `watchTowr`, `uid=0(root)`, `PD9...` PHP payload prefixes, `eval(gzinflate|base64_decode|$_*)`, and `gzinflate(`.
- Added explicit Corelight/PitScaler/Poppelgaard notes for `194.26.29.88` reverse-shell activity and `138.199.200.90` exfiltration activity.

## 1.5 - 2026-10-07

- Checked eSentire TRU, Nextron Systems, Fortra Emerging Threats, PitScaler, Unit 42, and watchTowr reporting for additional public indicators.
- Added eSentire cluster indicators for `nsgtrust.deb`, `entretiensol.com`, Platypus behavior, related IPs, and SHA-256 values.
- Added PitScaler/Rapid7 public IOC pivots including `149.104.78.208`, `/vpn/c`, `.ctxs.receiver` hash `ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1`, and Sliver delivery markers.
- Added PitScaler/Poppelgaard pivots for CVE-2026-88779 SAML probing/crash activity and the reported config/private-key dump to `81.94.239.8:8877`.
- Added Fortra Core Impact context for `/p/u/doAuthentication.do`, delayed `ns_monuploadd_err.pl` execution, and root agent deployment behavior.
- Added additional Unit42, TENEX, CERT-EU, Elastic, GreyNoise, Lupovis, Corelight/PitScaler, and Poppelgaard pivots including generic `pitboss` shell-token detection, `echvista.com`, `gsocket.io`, `194.26.29.88`, `138.199.200.90`, `nsepa.deb`, `vp_probe_nonexist`, Platypus artifacts, and exploit marker files.
- Bumped script version to 1.5.

## 1.4 - 2026-10-04

- Added live and offline read-only checks for the Citrix-documented SAML SP/IdP configuration precondition for CVE-2026-88779 (CTX697174).
- Clarified that configuration matches are applicability leads only; build/patch status and exploitation are not determined by this check.
- Added CTX697174 source and usage guidance.
- Bumped script version to 1.4.

## 1.3.2 - 2026-10-03
- Added source URLs to `IOCS.md` so the standalone indicator reference includes provenance.
- Bumped script `VERSION` to `1.3.2` for the documentation-only patch.

## 1.3.1 - 2026-10-03

- Added the project versioning policy: `y` increments for new IoCs or detection coverage, and `z` increments for documentation-only or other small repository changes without new IoCs.
- Moved the changelog out of README into `CHANGELOG.md`.
- Moved the detailed indicator reference out of README into `IOCS.md`.

## 1.3 - 2026-10-03

- Added Beazley/PitScaler October 2/3 second-wave indicators: `213.209.159.55`, `51.158.203.95`, `185.244.213.112`, `158.94.211.205`, `pyrlnk.cc`, `pylrk.cc`, `f.pylrk.cc`, `webhook.site`, and `dnshook.site`.
- Added SAML applicability and crash pivots for `add authentication samlAction`, `add authentication samlIdPProfile`, `proc nsaaad`, and appliance reboot/restart log patterns.
- Added Sliver/SAML-kit hashes and staging paths, including `/v`, `.slap` paths, `/var/tmp/.ux`, and related `.slap` log/staging files.
- Added a live read-only `SAML / second-wave pivots` check and extended network IOC matching to domains.
- Bumped script version to 1.3.

## 1.2 - 2026-10-02

- Added Unit 42 analysis pivots for fingerprinting URLs: `/admin_ui/common/css/ns/ui.css` and `/vpn/js/rdx/core/lang/rdx_en.json.gz`.
- Added Unit 42 CVE-2026-88771 log-poisoning and execution pivots: `pitboss PPE unexpectedly died NSPPE`, `pitboss PPE missed too many heartbeats NSPPE`, `ns_monuploadd_err.pl`, `chmod 6555 /bin/sh`, `/var/netscaler/.ns_suidcmd`, and `/var/run/httpd.pid`.
- Added Unit 42 web-shell pivots for `receiver.min.<hex>.css`, `Rhfajaf1H992`, `exec()`, `system()`, `popen()`, and `wc -c <` behavior.
- Bumped script version to 1.2.

## 1.1 - 2026-10-02

- Added Unit 42 September 30 indicators: additional pre-disclosure IPs, Cloudflare WARP correlation IPs, `.deb` web-shell filenames, `GetUserName` activity, `.sig` filenames, and related web paths.
- Added Beazley/GreyNoise/Lupovis public indicators: exploitation/scanning IPs, `httpworkbench.com`, `NX-CVE-OK`, `ns-88771-poc`, and the GreyNoise `.ctxs.receiver` SHA-256.
- Added web-shell/payload pivots for `INDEX:`, `e826d7ddf3c85920`, and `7489a0f93c67fa5cdaeb4b921d90594d`.
- Bumped script version to 1.1.

## 1.0 - 2026-10-01

- Converted all user-facing script text to English.
- Added complete LevelBlue IPv4 set used by the current hunt logic.
- Added `45.141.21.130` reverse-shell C2 hunting.
- Added `${IFS}` and `customsnmpd` behavioral pivots.
- Added `NETSCALER_HUNT_NO_REPORT=1` for report-file suppression.
- Added `NETSCALER_HUNT_REPORT` for choosing the report path.
- Clarified that live checks are non-remediating but a report file is written by default.
- Added documentation and source provenance.