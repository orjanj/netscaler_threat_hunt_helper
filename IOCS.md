# Indicator Reference

These are **historical hunting indicators**, not a complete or permanent blocklist. An exact match needs surrounding context, and the absence of these indicators does not exclude exploitation.

## Source URLs

The source labels in this file refer to the public reporting below.

- Citrix CTX697096: https://support.citrix.com/external/article/CTX697096
- Citrix CTX697174 (CVE-2026-88779): https://support.citrix.com/external/article/CTX697174/citrix-netscaler-adc-and-citrix-netscale.html
- Citrix SAML guidance: https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/
- GTIG / Mandiant: https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
- Palo Alto Networks Unit 42: https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
- eSentire TRU: https://www.esentire.com/blog/more-shells-than-a-seafood-buffet-tracking-citrix-netscaler-exploitation-activities-cve-2026-88771
- Nextron Systems: https://www.nextron-systems.com/2026/10/06/update-on-citrix-netscaler-cve-2026-88771-and-cve-2026-88772-expanded-thor-detection-coverage/
- Fortra Emerging Threats: https://www.fortra.com/security/emerging-threats/netscaler-cve-2026-88771-improper-input-validation-and-cve-2026-88772
- Beazley Security Labs BSL-A1216: https://labs.beazley.security/advisories/BSL-A1216
- PitScaler public briefing / IOC compilation: https://pitscaler.com/
- PitScaler public IOC table: https://pitscaler.com/netscaler-iocs/
- watchTowr CVE-2026-88779 rapid reaction: https://watchtowr.com/intelligence/citrix-netscaler-denial-of-service-memory-overflow-cve-2026-88779/
- watchTowr CVE-2026-88779 FAQ: https://watchtowr.com/intelligence/citrix-netscaler-cve-2026-88779-faq/
- LevelBlue SpiderLabs: https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators
- Arctic Wolf Labs Pack Alert: https://www.reddit.com/r/u_ArcticWolf_Official/comments/1wudni7/pack_alert_september_30_2026_arctic_wolf_labs/
- Wolf Tools Pack Alert: https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771
- GreyNoise: https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation
- watchTowr Labs: https://labs.watchtowr.com/

## Network Indicators

The current script contains the following historical IPv4 indicators.

### GTIG / Mandiant

Source: https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances

```text
143.198.7.94
157.254.167.12
```

### Unit 42

Source: https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/

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

Source: https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators

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

Sources:

- https://labs.beazley.security/advisories/BSL-A1216
- https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation
- https://pitscaler.com/

```text
149.104.78.141
138.28.234.38
82.167.14.7
85.203.46.191
154.217.251.226
213.209.159.55
51.158.203.95
185.244.213.112
158.94.211.205
149.104.78.208
34.90.151.231
144.172.108.78
185.156.46.162
153.75.82.220
216.203.21.233
185.243.41.247
81.94.239.8
138.199.60.5
```

`81.94.239.8` is reported by PitScaler/Poppelgaard as a config/private-key exfiltration receiver on TCP/8877. `138.199.60.5` is reported as a CVE-2026-88779 SAML crash-payload source. Treat both as hunting pivots and validate direction, timing, and appliance role before acting.

## Domain Indicators

Sources:

- https://labs.beazley.security/advisories/BSL-A1216
- https://pitscaler.com/

```text
httpworkbench.com
webhook.site
dnshook.site
pyrlnk.cc
www.pyrlnk.cc
pylrk.cc
f.pylrk.cc
entretiensol.com
```

## File And Path Indicators

Sources:

- https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
- https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
- https://labs.beazley.security/advisories/BSL-A1216
- https://pitscaler.com/
- https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771
- https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators

```text
/vpn/scripts/linux/nsgclient18.deb
/vpn/scripts/linux/nsgser18.deb
/vpn/scripts/linux/nsg64.deb
/vpn/scripts/linux/nsgsupport.deb
/vpn/scripts/linux/nsgpackage64.deb
/vpn/scripts/linux/nsgbuild.deb
/vpn/scripts/linux/nsgtrust.deb
/logon/LogonPoint/Authentication/GetUserName
/var/netscaler/logon/LogonPoint/custom/.ctxs.receiver
/var/netscaler/logon/LogonPoint/custom/.slap.receiver
/var/netscaler/logon/LogonPoint/custom/receiver.deb
/var/netscaler/gui/vpn/scripts/linux/nsgclient.sig
/var/netscaler/gui/vpn/scripts/linux/e6ee7c85.sig
/var/netscaler/gui/vpn/scripts/linux/1bd8a664.sig
/netscaler/ns_gui/vpn/scripts/linux/nsgclient.sig
/netscaler/ns_gui/vpn/scripts/linux/e6ee7c85.sig
/netscaler/ns_gui/vpn/c88771.json
/vpn/media/nsgclient.ico
/var/netscaler/logon/LogonPoint/.local_journal
/tmp/.uxdport
/tmp/.uxdlock
/tmp/update_result_3567cs.tgz
/var/netscaler/logon/insight-new.js
/var/netscaler/logon/LogonPoint/xua.html
/var/tmp/.nsmon
/var/1.py
/v
/nsconfig/.slap
/flash/nsconfig/.slap
/var/tmp/.ux
/var/tmp/.slap-agent.log
/var/tmp/.slap-httpd-test.log
/var/tmp/.slap-diag.txt
/var/tmp/.s2loot
/tmp/.slap.cron
/var/tmp/.host
/private/var/tmp/.host
/nsconfig/.nsl
/var/nslog/.nsl
/var/core/.ns-cache
/netscaler.local
/.x
/vpn/c
/var/tmp/.nsmon/nsmon.pl
/var/tmp/.nsmon/.cfg
/var/tmp/.nsmon/.state
/var/tmp/.s
```

Some of these may be short-lived because observed payloads included cleanup behavior. Missing files therefore do not prove that execution did not occur.

## SHA-256 Indicators

Sources:

- https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
- https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators
- https://labs.beazley.security/advisories/BSL-A1216
- https://pitscaler.com/

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

c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34
  Beazley - Sliver download script

0188b0eba4b01c4fb838df9d1d76c76d7f1dc22897e25161975b606c134c1027
  Beazley / PitScaler - Sliver C2 implant

b9b0a4380db462c706597bd3e6a08d4d99fcbbf0919d63eb99b488d396c8ce63
  PitScaler - second-wave Perl payload

72cff13fcba75504485e94fa6bfc5e9363e860f49efdba68feb583148eec38f2
  Poppelgaard / PitScaler - SAML-attack kit dropper

5ea5ea61e9062822bee3f66ef5ff47c217178d9e31936ad6daf10c5dfae44d12
  eSentire - PHP web shell .ico variant

7add390ceee4a1373211b3e340451b34f08965fc4d805f94c9b8cebdc0775774
  eSentire - nsgtrust.deb PHP web shell

57f9f30c50240fd48d761de7961a430cdebf2c084a36bc76d376a1ce8e6dfa9d
  eSentire / Arctic Wolf - Platypus x stager shell script

927c7fbef2e620c1ce482c3ed67ebf53da97693c1d6c7552c77aec84ba982cf8
  eSentire / Arctic Wolf - Platypus bootstrap script

c98aee75c5e199c9b5527984ce48675d665963f7cab8ce9f2e82465de6b58727
  eSentire / TENEX - Platypus agent, FreeBSD amd64 build

ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1
  Rapid7 / PitScaler - .ctxs.receiver web shell sample
```

Hash hunting is deliberately limited to plausible payload/configuration file types and selected high-risk paths so that the tool does not hash an entire large appliance image unless necessary.

## Behavioral Hunting Pivots

### CVE-2026-88779 applicability check

Citrix CTX697174 identifies these configuration entries as the SAML precondition to check:

```text
add authentication samlAction
add authentication samlIdPProfile
```

The script searches for those directives in readable live `ns.conf` files and offline configuration files. A match is not proof of exploitability: check the Gateway/AAA deployment context and running build against CTX697174. The advisory does not provide a distinct log signature that can reliably identify exploitation, so generic SAML or service-denial log entries are not presented as CVE-specific indicators.

Sources:

- https://support.citrix.com/external/article/CTX697096
- https://community.citrix.com/techzone-blogs/110_security-updates/security-update-guidance-for-netscaler-saml-authentication-deployments/
- https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
- https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
- https://labs.beazley.security/advisories/BSL-A1216
- https://pitscaler.com/
- https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators
- https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771

The script also searches for behavior that can be more durable than exact IOCs.

Examples include:

- DTLS handshake failures correlated with NSPPE termination
- `pitboss PPE unexpectedly died`
- `pitboss PPE missed too many heartbeats`
- `pitboss PPE unexpectedly died NSPPE`
- `pitboss PPE missed too many heartbeats NSPPE`
- `NOT restarting NSPPE`
- `orphan rings`
- `${IFS}` in attacker-controlled command strings
- unexpected PHP execution for `.deb`, `.sig`, `.tgz`, `.rpm`, or other non-PHP resources
- suspicious `AddHandler`, `AddType`, `AliasMatch`, and `php_flag` directives
- web-shell functions such as `eval()`, `passthru()`, `shell_exec()`, `exec()`, `system()`, `popen()`, and `base64_decode()`
- `wc -c <` web-shell file-size command behavior
- `HTTP_NSC_LDAP`
- `HTTP_NSC_CLIENTTYPE`
- `HTTP_X_UX*`
- `INDEX:` User-Agent payload staging
- `ns-88771-poc`
- `NX-CVE-OK`
- `httpworkbench.com`
- `webhook.site`
- `dnshook.site`
- `pyrlnk.cc`
- `pylrk.cc`
- `213.209.159.55:443/t/`
- `158.94.211.205:8080`
- `81.94.239.8:8877`
- `NSC_TASS`
- `CsrfToken`
- `e826d7ddf3c85920`
- `7489a0f93c67fa5cdaeb4b921d90594d`
- `Rhfajaf1H992`
- `/admin_ui/common/css/ns/ui.css`
- `/vpn/js/rdx/core/lang/rdx_en.json.gz`
- `/saml/login`
- `/cgi/samlauth`
- `/cgi/login`
- `/p/u/doAuthentication.do`
- `/p/u/doLogon.do`
- `receiver.min.<hex>.css`
- `LogonUISimple.html.style.min.css`
- `ns_monuploadd_err.pl`
- `/var/netscaler/.ns_suidcmd`
- `chmod 6555 /bin/sh`
- `/var/run/httpd.pid`
- suspicious activity involving `/vpn/media/` and `/vpn/scripts/`
- suspicious activity involving `/nf/auth/doAuthentication.do` and `/logon/LogonPoint/Authentication/GetUserName`
- `sec_monitor`
- `customsnmpd`
- SUID/SGID permissions on `/bin/sh`
- cron references to `.nsmon`, `curl`, `wget`, Python, Perl, or known staging paths
- unexpected listeners in TCP/UDP port range `41000-41999`
- SAML configuration lines `add authentication samlAction` or `add authentication samlIdPProfile`
- nsaaad crash/restart lines such as `proc nsaaad`, `maximum number of restarts`, and `All monitored processes have exited, rebooting`
- second-wave fetch/callback pivots involving `/v`, `f.pylrk.cc`, `webhook.site`, and `dnshook.site`
- Sliver delivery pivots involving `/HaKi2ufpiQ8AeVTZ/host`, `citrix3.bad`, and `IMPLANT_CAPABILITY_TUNNEL_TERMINAL_V1`
- eSentire cluster pivots including `nsgtrust.deb`, `entretiensol.com`, Platypus enrollment paths, `platypus-agent/public-ip-probe`, and `application/x-protobuf-platypus-v2`
- config/private-key dump pivots including `===CONF:`, `===KEY:`, private-key markers, random `.css` files under `LogonPoint`, and `curl --data-binary` to TCP/8877
- SAML/CVE-2026-88779 hunting pivots including `/saml/login`, `/cgi/samlauth`, `probe/1`, `scanner-probe`, and `nsaaad` crash artifacts