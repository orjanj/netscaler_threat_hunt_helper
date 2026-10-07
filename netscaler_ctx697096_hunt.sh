#!/usr/bin/env bash
# NetScaler CTX697096 Threat Hunt Helper
# Defensive/read-only hunting for CVE-2026-88771 / CVE-2026-88772 / CVE-2026-88779 activity and related post-exploitation.
#
# Sources used for indicators and hunt logic (verified 2026-10-07):
#   - Citrix CTX697096 security bulletin:
#     https://support.citrix.com/external/article/CTX697096
#   - Citrix CTX697174 security bulletin (CVE-2026-88779):
#     https://support.citrix.com/external/article/CTX697174/citrix-netscaler-adc-and-citrix-netscale.html
#   - Google Threat Intelligence Group / Mandiant:
#     https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
#   - Palo Alto Networks Unit 42:
#     https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
#   - CERT-EU:
#     https://cert.europa.eu/blog/taking-execute-logging-a-bit-too-literally-cve-2026-88771
#   - Elastic detection rules:
#     https://github.com/elastic/detection-rules/blob/main/rules/network/initial_access_netscaler_log_poisoning_command_injection.toml
#   - GreyNoise:
#     https://www.greynoise.io/blog/swarming-against-citrix-0-day-exploitation
#   - TENEX:
#     https://tenex.ai/blog/what-tenex-observed-inside-active-exploitation-of-netscaler-zero-day/
#   - eSentire TRU:
#     https://www.esentire.com/blog/more-shells-than-a-seafood-buffet-tracking-citrix-netscaler-exploitation-activities-cve-2026-88771
#   - Nextron Systems:
#     https://www.nextron-systems.com/2026/10/06/update-on-citrix-netscaler-cve-2026-88771-and-cve-2026-88772-expanded-thor-detection-coverage/
#   - Fortra Emerging Threats:
#     https://www.fortra.com/security/emerging-threats/netscaler-cve-2026-88771-improper-input-validation-and-cve-2026-88772
#   - SOCRadar:
#     https://socradar.io/blog/netscaler-c2-cve-2026-88771-exploitation/
#   - Beazley Security Labs BSL-A1216:
#     https://labs.beazley.security/advisories/BSL-A1216
#   - PitScaler public briefing / IOC compilation:
#     https://pitscaler.com/
#     https://pitscaler.com/netscaler-iocs/
#   - Thomas Poppelgaard NetScaler timeline / checker notes:
#     https://www.poppelgaard.com/cve-2026-88771-through-cve-2026-88778-what-you-should-know-and-how-to-fix-your-netscaler-adc-netscaler-gateway
#   - watchTowr Labs technical analysis:
#     https://labs.watchtowr.com/
#     https://watchtowr.com/intelligence/citrix-netscaler-denial-of-service-memory-overflow-cve-2026-88779/
#     https://watchtowr.com/intelligence/citrix-netscaler-cve-2026-88779-faq/
#   - LevelBlue SpiderLabs:
#     https://www.levelblue.com/blogs/spiderlabs-blog/citrix-netscaler-cve-2026-88771-observed-exploitation-artifacts-and-hunt-indicators
#   - Arctic Wolf Labs Pack Alert (observed post-exploitation indicators, secondary set):
#     https://www.reddit.com/r/u_ArcticWolf_Official/comments/1wudni7/pack_alert_september_30_2026_arctic_wolf_labs/
#   - Wolf Tools Pack Alert (observed post-exploitation indicators, secondary set):
#     https://github.com/rtkwlf/wolf-tools/tree/main/pack_alerts/202609-citrix-netscaler-active-exploitation-cve-2026-88771
#
# IMPORTANT:
#   * A hit is a hunting lead, not proof of compromise.
#   * No hits do NOT prove the appliance is clean.
#   * Prefer hunting on copied logs/support bundles when forensic preservation matters.
#   * Live hunt checks do not patch, delete, kill, restart, or change NetScaler configuration/services.
#   * By default the script writes a local report file. Set NETSCALER_HUNT_NO_REPORT=1 to suppress it.

set -u
set -o pipefail

if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  printf 'ERROR: %s requires Bash 4.3 or later. FreeBSD/NetScaler systems may need bash from packages/ports or offline hunting from another host.\n' "${0##*/}" >&2
  exit 2
fi

VERSION="1.7"
SCRIPT_NAME="NetScaler CTX697096 Threat Hunt Helper"
REPORT="${NETSCALER_HUNT_REPORT:-$(pwd -P)/netscaler_hunt_$(date +%Y%m%d_%H%M%S).log}"
FINDINGS_FILE="${NETSCALER_HUNT_FINDINGS_FILE:-$(pwd -P)/netscaler_findings_$(date +%Y%m%d_%H%M%S).txt}"
NO_REPORT="${NETSCALER_HUNT_NO_REPORT:-0}"
ROOT=""
SECTION_COUNT=0
ALERT_COUNT=0
WARN_COUNT=0
ERROR_COUNT=0
SUMMARY_DETAIL_LIMIT=100
FINDINGS_DETAIL_THRESHOLD="${NETSCALER_HUNT_FINDINGS_THRESHOLD:-100}"
ALERT_MESSAGES=()
WARN_MESSAGES=()
ERROR_MESSAGES=()
ALL_ALERT_MESSAGES=()
ALL_WARN_MESSAGES=()
ALL_ERROR_MESSAGES=()
ALERT_DETAIL_OMITTED=0
WARN_DETAIL_OMITTED=0
ERROR_DETAIL_OMITTED=0
FINDINGS_WRITTEN=0

# -----------------------------
# IOC DATA
# -----------------------------

# Formal / high-value network indicators from GTIG, Unit 42 and LevelBlue.
IOC_IPS=(
  "143.198.7.94"       # GTIG scanning/staging
  "157.254.167.12"     # GTIG exploitation / webshell install
  "45.61.136.143"      # Unit 42
  "66.227.183.84"      # Unit 42
  "77.83.199.39"       # Unit 42
  "104.28.215.137"     # Unit 42
  "104.28.215.136"     # Unit 42 Cloudflare WARP correlation only
  "104.248.244.66"     # Unit 42
  "104.28.247.136"     # Unit 42
  "104.28.247.137"     # Unit 42 Cloudflare WARP correlation only
  "162.33.178.9"       # Unit 42
  "193.149.176.207"    # Unit 42
  "216.245.184.164"    # Unit 42
  "78.47.24.217"       # Unit 42 fingerprinting / webshell drop activity
  "66.135.19.18"       # Unit 42 .deb webshell requests
  "167.99.111.203"     # Unit 42 .deb webshell requests
  "142.93.85.227"      # Unit 42 .deb webshell requests
  "104.248.74.206"     # Unit 42 .deb webshell requests
  "137.184.91.207"     # Unit 42 .deb webshell requests
  "139.180.152.138"    # Unit 42 webshell drop activity / eSentire
  "70.172.58.168"      # LevelBlue exploitation source
  "45.141.21.130"       # LevelBlue reverse-shell C2
  "162.243.36.88"       # LevelBlue exploitation source
  "173.40.135.209"      # LevelBlue exploitation source
  "47.230.224.154"      # LevelBlue exploitation source
  "92.118.204.229"     # LevelBlue command-execution testing source
  "87.224.84.82"       # LevelBlue configuration-staging source
  "31.56.197.72"       # LevelBlue payload hosting
  "62.133.62.80"       # LevelBlue payload hosting
  "23.27.143.20"       # LevelBlue exploit source / Python payload host
  "64.94.85.67"        # LevelBlue exploit / payload / exfil infrastructure
  "149.104.78.141"     # GreyNoise / Beazley exploitation source
  "138.28.234.38"      # Lupovis / Beazley DNS exfil attempt
  "82.167.14.7"        # Lupovis / Beazley exploitation check source
  "85.203.46.191"      # Lupovis / Beazley reconnaissance source
  "154.217.251.226"    # Lupovis / Beazley CVE-2026-88772 scanning
  "213.209.159.55"     # Beazley / PitScaler second-wave SAML/log-injection payload delivery
  "51.158.203.95"      # Beazley exploit delivery
  "185.244.213.112"    # Beazley exploit delivery
  "158.94.211.205"     # Beazley exfil receiver
  "149.104.78.208"     # Rapid7 / PitScaler earliest observed config-archive exploitation source
  "34.90.151.231"      # eSentire reconnaissance / webshell delivery
  "144.172.108.78"     # eSentire exploitation source
  "185.156.46.162"     # eSentire exploitation source / GreyNoise tagged
  "153.75.82.220"      # eSentire / Arctic Wolf shell payload host
  "216.203.21.233"     # eSentire exploitation source / GreyNoise tagged
  "185.243.41.247"     # eSentire campaign infrastructure
  "81.94.239.8"        # PitScaler / Poppelgaard config and private-key exfil receiver on TCP/8877
  "138.199.60.5"       # PitScaler / Poppelgaard CVE-2026-88779 SAML crash-payload source
  "78.128.113.10"      # Lupovis / Poppelgaard fetch-based next-stage attempt
  "194.26.29.88"       # Corelight / Poppelgaard reverse-shell host
  "138.199.200.90"     # PitScaler / Poppelgaard exfiltration destination
  "158.94.209.12"      # Poppelgaard community IOC compilation
  "68.178.160.183"     # Poppelgaard community IOC compilation
  "5.188.206.226"      # Poppelgaard community IOC compilation
  "45.143.130.195"     # SOCRadar NetScaler C2 HTTP/DNS listener
)

IOC_DOMAINS=(
  "httpworkbench.com"  # Lupovis / Beazley out-of-band callback service
  "webhook.site"       # Beazley observed callback service
  "dnshook.site"       # Beazley observed DNS callback service
  "pyrlnk.cc"          # Beazley/PitScaler reported second-wave payload delivery spelling
  "www.pyrlnk.cc"      # Beazley hardcoded Sliver C2
  "pylrk.cc"           # Beazley/Poppelgaard reported second-wave payload delivery spelling
  "f.pylrk.cc"         # Beazley Sliver payload delivery
  "entretiensol.com"   # eSentire / Arctic Wolf Platypus C2 and artifact host
  "instances.httpworkbench.com" # Lupovis / Poppelgaard DNS exfiltration subdomain pattern
  "echvista.com"       # PitScaler / Poppelgaard public IOC compilation
  "gsocket.io"         # Poppelgaard second-wave reverse-shell/C2 pivot
)

# Host/file indicators.
IOC_PATHS=(
  "/vpn/scripts/linux/nsgclient18.deb"
  "/vpn/scripts/linux/nsgser18.deb"
  "/vpn/scripts/linux/nsg64.deb"
  "/vpn/scripts/linux/nsgsupport.deb"
  "/vpn/scripts/linux/nsgpackage64.deb"
  "/vpn/scripts/linux/nsgbuild.deb"
  "/vpn/scripts/linux/nsgtrust.deb"
  "/logon/LogonPoint/Authentication/GetUserName"
  "/logon/LogonPoint/tmindex.html"
  "/nf/auth/doAuthentication.do"
  "/var/netscaler/logon/LogonPoint/custom/.ctxs.receiver"
  "/var/netscaler/logon/LogonPoint/custom/.slap.receiver"
  "/var/netscaler/logon/LogonPoint/custom/receiver.deb"
  "/var/netscaler/gui/vpn/scripts/linux/nsgclient.sig"
  "/var/netscaler/gui/vpn/scripts/linux/e6ee7c85.sig"
  "/var/netscaler/gui/vpn/scripts/linux/1bd8a664.sig"
  "/netscaler/ns_gui/vpn/scripts/linux/nsgclient.sig"
  "/netscaler/ns_gui/vpn/scripts/linux/e6ee7c85.sig"
  "/netscaler/ns_gui/vpn/c88771.json"
  "/vpn/media/nsgclient.ico"
  "/var/netscaler/logon/LogonPoint/.local_journal"
  "/tmp/.uxdport"
  "/tmp/.uxdlock"
  "/tmp/update_result_3567cs.tgz"
  "/var/netscaler/logon/insight-new.js"
  "/var/netscaler/logon/LogonPoint/xua.html"
  "/var/vpn/bookmark/nx_verify.html"
  "/netscaler/ns_gui/vpn/nx_verify.html"
  "/netscaler/ns_gui/vpn/id009.txt"
  "/netscaler/ns_gui/vpn/rce.txt"
  "/var/tmp/.nsmon"
  "/var/1.py"
  "/v"
  "/tmp/v"
  "/var/tmp/v"
  "/tmp/watchTowr"
  "/var/tmp/wtw888"
  "/var/tmp/boom"
  "/var/tmp/sh"
  "/nsconfig/.slap"
  "/flash/nsconfig/.slap"
  "/var/tmp/.ux"
  "/var/tmp/.slap-agent.log"
  "/var/tmp/.slap-httpd-test.log"
  "/var/tmp/.slap-diag.txt"
  "/var/tmp/.s2loot"
  "/tmp/.slap.cron"
  "/var/tmp/.host"
  "/private/var/tmp/.host"
  "/nsconfig/.nsl"
  "/var/nslog/.nsl"
  "/var/core/.ns-cache"
  "/var/core/.ns-cache/client.crt"
  "/var/core/.ns-cache/client.key"
  "/netscaler.local"
  "/var/python/bin/customsnmpd"
  "/netscaler/ns_gui/admin_ui/e.txt"
  "/netscaler/ns_gui/admin_ui/log.txt"
  "/.x"
  "/lula"
  "/vpn/c"
  "/epa/scripts/linux/nsepa.deb"
  "/tmp/.nsagent"
  "/var/tmp/.nsmon/nsmon.pl"
  "/var/tmp/.nsmon/.cfg"
  "/var/tmp/.nsmon/.state"
  "/var/tmp/.s"
)

# Known hashes from Unit 42 / LevelBlue.
declare -A IOC_HASHES
IOC_HASHES["ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec"]="Unit42 nsg64.deb webshell"
IOC_HASHES["1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d"]="Unit42 encoded payload text"
IOC_HASHES["79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186"]="Unit42 decoded shell-script text"
IOC_HASHES["e9fe43968c6c0955300e3bc4d7fb0b05a18570b4733aaf4f5c6f7f09be5a242c"]="LevelBlue main.py"
IOC_HASHES["974b69782fdf5d67b97cfd508465939e44ee10798dbcc1e82b92d78776bad938"]="LevelBlue update_c08937.pl"
IOC_HASHES["6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"]="GreyNoise .ctxs.receiver webshell"
IOC_HASHES["c2f5532f3209dce0bd30ead47a2616a74ce8170324ef68dfd59acac3f5f1da34"]="Beazley Sliver download script"
IOC_HASHES["0188b0eba4b01c4fb838df9d1d76c76d7f1dc22897e25161975b606c134c1027"]="Beazley/PitScaler Sliver C2 implant"
IOC_HASHES["b9b0a4380db462c706597bd3e6a08d4d99fcbbf0919d63eb99b488d396c8ce63"]="PitScaler second-wave Perl payload"
IOC_HASHES["72cff13fcba75504485e94fa6bfc5e9363e860f49efdba68feb583148eec38f2"]="Poppelgaard SAML-attack kit dropper"
IOC_HASHES["5ea5ea61e9062822bee3f66ef5ff47c217178d9e31936ad6daf10c5dfae44d12"]="eSentire PHP webshell .ico variant"
IOC_HASHES["7add390ceee4a1373211b3e340451b34f08965fc4d805f94c9b8cebdc0775774"]="eSentire nsgtrust.deb PHP webshell"
IOC_HASHES["57f9f30c50240fd48d761de7961a430cdebf2c084a36bc76d376a1ce8e6dfa9d"]="eSentire / Arctic Wolf Platypus x stager"
IOC_HASHES["927c7fbef2e620c1ce482c3ed67ebf53da97693c1d6c7552c77aec84ba982cf8"]="eSentire / Arctic Wolf Platypus bootstrap script"
IOC_HASHES["c98aee75c5e199c9b5527984ce48675d665963f7cab8ce9f2e82465de6b58727"]="eSentire / TENEX Platypus agent FreeBSD amd64"
IOC_HASHES["ed082f744f035035900f67edf438f2f7d0528ac501234f63d476d65273cdb9a1"]="Rapid7 / PitScaler .ctxs.receiver webshell sample"
IOC_HASHES["8588d11874ab52a1637953dc5538984647023d00b529f695fbd0e40cf8e5e852"]="SOCRadar NetScaler C2 run.sh"
IOC_HASHES["4992f575f3f1fc448cf54a4a0ce13cf6548790777abe0af1f935663498ea5639"]="SOCRadar NetScaler C2 targets.py"
IOC_HASHES["69a34c591eaaa2cbecaeed10c303b8dcf04c846b8408491da5452b9cfc93f686"]="SOCRadar NetScaler C2 probe.py"
IOC_HASHES["a3e26053975daa0a12a4848ce9533e5c439617cd7f69851347be2061999b4cd4"]="SOCRadar NetScaler C2 exploit.py"
IOC_HASHES["a9142989d912098856e58f2c74c2266e39150d50bc59722f915dade1ddfddf4a"]="SOCRadar NetScaler C2 c2_server.py"
IOC_HASHES["f9e06d412dee96d98db4d4588f0012af859cc11caaae3e130697f282447cf07f"]="SOCRadar NetScaler C2 pollctl.py"

# Strings / behavior pivots. These are intentionally broader than exact IOCs.
LOG_PATTERNS=(
  "SSL_HANDSHAKE_FAILURE"
  "DTLSv1.0"
  "Handshake failure-Internal Error"
  "NOT restarting NSPPE"
  "NSPPE.*exit"
  "orphan rings"
  "pitboss PPE unexpectedly died"
  "pitboss PPE unexpectedly died NSPPE"
  "pitboss NSPPE-00;"
  'pitboss.*(;|`|\$\(|&&|\|\||\||>|<|%3[bB]|%60|%7[cC]|%24%28|%26%26|%3[eE]|%3[cC])'
  "pitboss PPE missed too many heartbeats"
  "pitboss PPE missed too many heartbeats[[:space:]]?NSPPE"
  "NSPPE-00"
  "HTTP_NSC_LDAP"
  "HTTP_NSC_CLIENTTYPE"
  "HTTP_X_UX"
  "INDEX:"
  "ns-88771-poc"
  "NX-CVE-OK"
  "httpworkbench\.com"
  "instances\.httpworkbench\.com"
  "webhook\.site"
  "dnshook\.site"
  "echvista\.com"
  "gsocket\.io"
  "pyrlnk\.cc"
  "pylrk\.cc"
  "213\.209\.159\.55:443/t/"
  "158\.94\.211\.205:8080"
  "/admin_ui/common/css/ns/ui\.css"
  "/vpn/js/rdx/core/lang/rdx_en\.json\.gz"
  "/nitro/v1/config/login(\?action=login)?"
  "/vpn/media/"
  "/vpn/scripts/"
  "/nf/auth/doAuthentication\.do"
  "/nf/auth/getAuthenticationRequirements\.do"
  "/logon/LogonPoint/tmindex\.html"
  "/logon/LogonPoint/index\.html"
  "/vpn/index\.html"
  "/epa/scripts/linux/nsepa\.deb"
  "vp_probe_nonexist"
  "/p/u/doAuthentication\.do"
  "/p/u/doLogon\.do"
  "/cgi/login"
  "/cgi/samlauth"
  "/saml/login"
  "/logon/LogonPoint/Authentication/GetUserName"
  "GetUserName"
  "receiver.min.css"
  "receiver\.min\.[[:xdigit:]]+\.css"
  "LogonUISimple.html.style.min.css"
  "LogonUISimple\.html\.style\.min\.[[:xdigit:]]+\.css"
  "sec_monitor"
  "NO_AUTH"
  '\$\{IFS\}'
  "customsnmpd"
  "system-health"
  "health-monitor"
  "healthd"
  "gs-netcat"
  "_platypus-mesh\._tcp"
  "platypus-ingress"
  "ns_monuploadd_err\.pl"
  "/var/netscaler/\.ns_suidcmd"
  "chmod[[:space:]]+6555[[:space:]]+/bin/sh"
  "/var/run/httpd\.pid"
  "update_result_3567cs.tgz"
  "update_result_[^[:space:]/]*\.tgz"
  "\.ctxs\.receiver"
  "\.local_journal"
  "\.uxdport"
  "\.uxdlock"
  "nsmon.pl"
  "/var/tmp/\.nsmon"
  "/var/1.py"
  "admin_ui/(e|log)\.txt"
  "nx_verify\.html"
  "wtw[[:alnum:]_.-]*"
  "watchTowr"
  "uid=0\(root\)"
  "/tmp/v"
  "/var/tmp/v"
  "/var/tmp/sh"
  "fetch\$\{IFS\}-qo\$\{IFS\}/v"
  "fetch\$\{IFS\}-qo-\$\{IFS\}https://f\.pylrk\.cc"
  "nohup\$\{IFS\}fetch"
  "nslookup[[:space:]]+PWNED\..*\.dnshook\.site"
  "id>/netscaler/ns_gui/vpn/id009\.txt"
  "id>/netscaler/ns_gui/vpn/rce\.txt"
  "add authentication samlAction"
  "add authentication samlIdPProfile"
  "proc nsaaad.*(SIGNALED|EXITED)"
  "maximum number of restarts"
  "Pitboss declaring system failure"
  "All monitored processes have exited, rebooting"
  "nsaaad-.*\.gz"
  "Pylrkfbsd"
  "nsgtrust\.deb"
  "entretiensol\.com"
  "platypus-agent/public-ip-probe"
  "application/x-protobuf-platypus-v2"
  "PLATYPUS_INSTALL_TOKEN"
  "plt_wqmnjp5jusrcpzicqa2t\.gg3s7yppdptle5dyefxj"
  "/v1/artifacts/freebsd/amd64/latest"
  "/api/v1/agents/enroll"
  "/api/v1/agent/link"
  "/xd7h/x"
  "/xd7h/nsmon\.pl"
  "/download/x\.sh"
  "45\.141\.21\.130/443"
  "81\.94\.239\.8:8877"
  "194\.26\.29\.88"
  "138\.199\.200\.90"
  "45\.143\.130\.195"
  "45\.143\.130\.195:8899"
  'curl\$\{IFS\}-sk\$\{IFS\}45\.143\.130\.195:8899/s/[[:xdigit:]]{8}\|sh'
  'nslookup\$\{IFS\}[[:xdigit:]]{8}\.p1\.oob\.45\.143\.130\.195'
  'p1\.oob\.45\.143\.130\.195'
  '/s/[[:xdigit:]]{8}(\|sh)?'
  '/a/[[:xdigit:]]{8}'
  '/p/[[:xdigit:]]{8}\?h=[[:xdigit:]]+&u=[[:xdigit:]]+&src=agent'
  '/c/[[:xdigit:]]{8}'
  '/r/[[:xdigit:]]{8}\?d=[[:xdigit:]]+'
  ";# unexpectedly died"
  "/tmp/\.nsagent"
  "curl[[:space:]].*--data-binary.*:8877"
  "===CONF:"
  "===KEY:"
  "BEGIN[[:space:]]+(RSA |EC |OPENSSH )?PRIVATE KEY"
  "/vpn/c"
  "scanner-probe"
  "probe/1"
  "PoCbit"
  "PD9[A-Za-z0-9+/=]{8,}"
  "/HaKi2ufpiQ8AeVTZ/host"
  "citrix3\.bad"
  "IMPLANT_CAPABILITY_TUNNEL_TERMINAL_V1"
)

WEBSHELL_PATTERNS=(
  "application/x-httpd-php"
  "php_flag[[:space:]]+engine[[:space:]]+on"
  "AliasMatch"
  "AddHandler"
  "AddType"
  "<\\?php"
  "base64_decode[[:space:]]*\\("
  "shell_exec[[:space:]]*\\("
  "exec[[:space:]]*\\("
  "passthru[[:space:]]*\\("
  "system[[:space:]]*\\("
  "popen[[:space:]]*\\("
  "eval[[:space:]]*\\("
  "wc[[:space:]]+-c[[:space:]]*<"
  "HTTP_NSC_LDAP"
  "HTTP_NSC_CLIENTTYPE"
  "HTTP_X_UX"
  "NSC_TASS"
  "CsrfToken"
  "e826d7ddf3c85920"
  "7489a0f93c67fa5cdaeb4b921d90594d"
  "Rhfajaf1H992"
  "\.slap\.receiver"
  "receiver\.deb"
  "receiver\.v2\.min"
  "LogonUISimple\.html\.style\.min\.css"
  "LogonUISimple\.html\.style\.min\.[[:xdigit:]]+\.css"
  "httpd\.conf\.slap\.bak"
  "Pylrkfbsd"
  "HTTP_NSC_CLI"
  "eval[[:space:]]*\([[:space:]]*(gzinflate|base64_decode|\$_(GET|POST|REQUEST|COOKIE|SERVER))"
  "gzinflate[[:space:]]*\("
  "application/x-protobuf-platypus-v2"
)

emit_stream() {
  if [[ "$NO_REPORT" == "1" ]]; then
    cat
  else
    tee -a "$REPORT"
  fi
}

banner() {
  printf '\n============================================================\n'
  printf '%s v%s\n' "$SCRIPT_NAME" "$VERSION"
  if [[ "$NO_REPORT" == "1" ]]; then
    printf 'Report: disabled (NETSCALER_HUNT_NO_REPORT=1)\n'
  else
    printf 'Report: %s\n' "$REPORT"
  fi
  printf '============================================================\n\n'
}

log() {
  local level="$1"; shift
  local message="$*"
  case "$level" in
    ALERT) ((ALERT_COUNT+=1)); add_summary_detail ALERT "$message" ;;
    WARN)
      ((WARN_COUNT+=1))
      [[ "$message" == "Matches found. Investigate context and timeline; a match alone is not proof of compromise." ]] || add_summary_detail WARN "$message"
      ;;
    ERROR) ((ERROR_COUNT+=1)); add_summary_detail ERROR "$message" ;;
  esac
  printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" | emit_stream
}

section() {
  ((SECTION_COUNT+=1))
  printf '\n---- %s ----\n' "$*" | emit_stream
}

add_summary_detail() {
  local level="$1"
  local message="$2"

  case "$level" in
    ALERT)
      ALL_ALERT_MESSAGES+=("$message")
      if (( ${#ALERT_MESSAGES[@]} < SUMMARY_DETAIL_LIMIT )); then
        ALERT_MESSAGES+=("$message")
      else
        ((ALERT_DETAIL_OMITTED+=1))
      fi
      ;;
    WARN)
      ALL_WARN_MESSAGES+=("$message")
      if (( ${#WARN_MESSAGES[@]} < SUMMARY_DETAIL_LIMIT )); then
        WARN_MESSAGES+=("$message")
      else
        ((WARN_DETAIL_OMITTED+=1))
      fi
      ;;
    ERROR)
      ALL_ERROR_MESSAGES+=("$message")
      if (( ${#ERROR_MESSAGES[@]} < SUMMARY_DETAIL_LIMIT )); then
        ERROR_MESSAGES+=("$message")
      else
        ((ERROR_DETAIL_OMITTED+=1))
      fi
      ;;
  esac
}

add_match_summary_details() {
  local level="$1"
  local label="$2"
  local file="$3"
  local matches="$4"
  local line

  while IFS= read -r line; do
    [[ -n "$line" ]] && add_summary_detail "$level" "$label: $file:$line"
  done <<< "$matches"
}

findings_detail_count() {
  printf '%s' "$(( ${#ALL_ALERT_MESSAGES[@]} + ${#ALL_WARN_MESSAGES[@]} + ${#ALL_ERROR_MESSAGES[@]} ))"
}

print_findings_file_items() {
  local heading="$1"; shift
  local items=("$@")
  local item
  (( ${#items[@]} == 0 )) && return

  printf '\n%s:\n' "$heading"
  for item in "${items[@]}"; do
    printf '  - %s\n' "$item"
  done
}

write_findings_file() {
  {
    printf '%s v%s\n' "$SCRIPT_NAME" "$VERSION"
    printf 'Findings generated: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')"
    if [[ "$NO_REPORT" == "1" ]]; then
      printf 'Report file: disabled (NETSCALER_HUNT_NO_REPORT=1)\n'
    else
      printf 'Report file: %s\n' "$REPORT"
    fi
    printf '\nSummary counts:\n'
    printf '  ALERT findings: %s\n' "$ALERT_COUNT"
    printf '  WARN messages: %s\n' "$WARN_COUNT"
    printf '  ERROR messages: %s\n' "$ERROR_COUNT"
    print_findings_file_items "ALERT details" "${ALL_ALERT_MESSAGES[@]}"
    print_findings_file_items "WARN details" "${ALL_WARN_MESSAGES[@]}"
    print_findings_file_items "ERROR details" "${ALL_ERROR_MESSAGES[@]}"
  } > "$FINDINGS_FILE"
}

maybe_write_findings_file() {
  local total
  total=$(findings_detail_count)
  (( total > FINDINGS_DETAIL_THRESHOLD )) || return 0
  (( FINDINGS_WRITTEN == 0 )) || return 0

  local answer=""
  local auto_mode="${NETSCALER_HUNT_FINDINGS_AUTO:-prompt}"
  if [[ "$auto_mode" == "0" ]]; then
    printf '\nFindings file: not created because NETSCALER_HUNT_FINDINGS_AUTO=0.\n' | emit_stream
    return 0
  elif [[ "$auto_mode" != "1" && -t 0 ]]; then
    printf '\n%s concrete finding details were collected. Write full findings to %s? [Y/n]: ' "$total" "$FINDINGS_FILE" > /dev/tty
    read -r answer < /dev/tty
    if [[ -n "$answer" && ! "$answer" =~ ^[Yy]$ ]]; then
      printf '\nFindings file: not created by operator choice.\n' | emit_stream
      return 0
    fi
  elif [[ "$auto_mode" != "1" && "$NO_REPORT" == "1" ]]; then
    printf '\nFindings file: not created because non-interactive no-report mode is enabled. Set NETSCALER_HUNT_FINDINGS_FILE and run interactively to approve it.\n' | emit_stream
    return 0
  fi

  if write_findings_file; then
    FINDINGS_WRITTEN=1
    printf '\nFindings file: %s\n' "$FINDINGS_FILE" | emit_stream
  else
    printf '\nFindings file: failed to write %s\n' "$FINDINGS_FILE" | emit_stream
  fi
  return 0
}

print_summary_items() {
  local heading="$1"
  local omitted="$2"
  shift 2
  local items=("$@")
  local item
  (( ${#items[@]} == 0 && omitted == 0 )) && return

  printf '\n%s:\n' "$heading"
  for item in "${items[@]}"; do
    printf '  - %s\n' "$item"
  done
  if (( omitted > 0 )); then
    printf '  - ... %s additional detail(s) omitted from summary; review the full report above.\n' "$omitted"
  fi
}

print_summary() {
  {
    printf '\n---- Hunt summary ----\n'
    printf 'Sections run: %s\n' "$SECTION_COUNT"
    printf 'ALERT findings: %s\n' "$ALERT_COUNT"
    printf 'WARN messages: %s\n' "$WARN_COUNT"
    printf 'ERROR messages: %s\n' "$ERROR_COUNT"
    print_summary_items "ALERT details" "$ALERT_DETAIL_OMITTED" "${ALERT_MESSAGES[@]}"
    print_summary_items "WARN details" "$WARN_DETAIL_OMITTED" "${WARN_MESSAGES[@]}"
    print_summary_items "ERROR details" "$ERROR_DETAIL_OMITTED" "${ERROR_MESSAGES[@]}"
    if (( ALERT_COUNT > 0 )); then
      printf 'Assessment: ALERT-level findings were logged. Treat them as investigation leads and preserve relevant evidence before remediation.\n'
    else
      printf 'Assessment: No ALERT-level findings were logged by the executed checks. This does not prove the appliance or bundle is clean.\n'
    fi
    if [[ "$NO_REPORT" == "1" ]]; then
      printf 'Report file: disabled (NETSCALER_HUNT_NO_REPORT=1)\n'
    else
      printf 'Report file: %s\n' "$REPORT"
    fi
  } | emit_stream
  maybe_write_findings_file
}

pause() {
  printf '\nPress Enter to continue...'
  read -r _
}

have() { command -v "$1" >/dev/null 2>&1; }

# Grep both normal and gzipped text files beneath a directory.
search_tree_regex() {
  local base="$1"
  local regex="$2"
  local label="$3"
  local found=0

  section "$label"
  log INFO "Searching under: $base"

  while IFS= read -r -d '' f; do
    [[ "$NO_REPORT" != "1" && "$f" == "$REPORT" ]] && continue
    case "$f" in
      *.gz)
        if have zgrep; then
          local out
          out=$(zgrep -Ein -- "$regex" "$f" 2>/dev/null | head -n 200 || true)
          if [[ -n "$out" ]]; then
            printf '%s\n' "$out" | emit_stream
            add_match_summary_details WARN "$label" "$f" "$out"
            found=1
          fi
        fi
        ;;
      *)
        local out
        out=$(grep -Ein -- "$regex" "$f" 2>/dev/null | head -n 200 || true)
        if [[ -n "$out" ]]; then
          printf '%s\n' "$out" | emit_stream
          add_match_summary_details WARN "$label" "$f" "$out"
          found=1
        fi
        ;;
    esac
  done < <(find "$base" -type f \( \
      -name '*.log' -o -name '*.log.*' -o -name '*.txt' -o -name '*.conf' -o \
      -name '*.out' -o -name '*.json' -o -name '*.xml' -o -name '*.csv' -o \
      -name '*.gz' -o -name 'messages*' -o -name 'ns.log*' -o -name 'httpaccess*' -o \
      -name 'httperror*' -o -name 'sh.log*' \
    \) -print0 2>/dev/null)

  if (( found == 0 )); then
    log INFO "No matches in the selected text/log files."
  else
    log WARN "Matches found. Investigate context and timeline; a match alone is not proof of compromise."
  fi
}

build_regex_from_array() {
  local -n arr=$1
  local out=""
  local item
  for item in "${arr[@]}"; do
    [[ -n "$out" ]] && out+="|"
    out+="$item"
  done
  printf '%s' "$out"
}

build_network_ioc_regex() {
  local regex="" item escaped
  for item in "${IOC_IPS[@]}"; do
    [[ -n "$regex" ]] && regex+="|"
    regex+="${item//./\.}"
  done
  for item in "${IOC_DOMAINS[@]}"; do
    escaped="${item//./\.}"
    [[ -n "$regex" ]] && regex+="|"
    regex+="$escaped"
  done
  printf '%s' "$regex"
}

hunt_log_behavior_offline() {
  local regex
  regex=$(build_regex_from_array LOG_PATTERNS)
  search_tree_regex "$ROOT" "$regex" "Log and exploit behavior"
}

hunt_ip_iocs_offline() {
  local regex
  regex=$(build_network_ioc_regex)
  search_tree_regex "$ROOT" "$regex" "Historical network IOCs"
}

hunt_webshell_patterns_offline() {
  local regex
  regex=$(build_regex_from_array WEBSHELL_PATTERNS)
  search_tree_regex "$ROOT" "$regex" "Web shell / PHP / Apache indicators"
}

report_saml_config_file() {
  local f="$1"
  local matches
  matches=$(grep -Ein '^[[:space:]]*add[[:space:]]+authentication[[:space:]]+(samlAction|samlIdPProfile)([[:space:]]|$)' "$f" 2>/dev/null || true)
  if [[ -n "$matches" ]]; then
    printf '%s\n' "$matches" | emit_stream
    add_match_summary_details WARN "CVE-2026-88779 SAML precondition" "$f" "$matches"
    log WARN "CVE-2026-88779 precondition found in $f (SAML SP/IdP configuration). This is applicability evidence, not proof of exploit or vulnerability; verify build and Gateway/AAA use."
    return 0
  fi
  return 1
}

hunt_cve_2026_88779_offline() {
  section "OFFLINE: CVE-2026-88779 SAML configuration precondition"
  local f checked=0 found=0
  while IFS= read -r -d '' f; do
    ((checked+=1))
    if report_saml_config_file "$f"; then
      found=1
    fi
  done < <(find "$ROOT" -type f \( -name '*.conf' -o -name 'ns.conf' -o -name 'ns.conf.*' \) -print0 2>/dev/null)

  if (( checked == 0 )); then
    log WARN "No NetScaler configuration files were found in the evidence tree; CVE-2026-88779 applicability could not be assessed."
  elif (( found == 0 )); then
    log INFO "No SAML SP/IdP precondition directives found in $checked scanned configuration file(s); this does not establish that the appliance is unaffected."
  fi
  log INFO "This offline check does not establish the appliance build/patch status or detect exploitation; compare the appliance version with Citrix CTX697174."
}

hunt_named_artifacts_offline() {
  section "Known file/path indicators in collected material"
  local p base found=0
  for p in "${IOC_PATHS[@]}"; do
    base=$(basename "$p")
    while IFS= read -r -d '' f; do
      log ALERT "File/path match: $p -> $f"
      found=1
    done < <(find "$ROOT" -type f -name "$base" -print0 2>/dev/null)
  done
  (( found == 0 )) && log INFO "No known artifact filenames found in the material."
}

hash_file() {
  local f="$1"
  if have sha256sum; then
    sha256sum "$f" 2>/dev/null | awk '{print $1}'
  elif have sha256; then
    sha256 -q "$f" 2>/dev/null
  elif have openssl; then
    openssl dgst -sha256 "$f" 2>/dev/null | awk '{print $NF}'
  else
    return 1
  fi
}

list_recent_files() {
  local d="$1"
  find "$d" -type f -mtime -45 -print 2>/dev/null | head -n 200 | while IFS= read -r f; do
    ls -ld "$f" 2>/dev/null
  done
}

list_processes() {
  if ps axww -o user,pid,ppid,stat,command >/dev/null 2>&1; then
    ps axww -o user,pid,ppid,stat,command 2>/dev/null
  else
    ps auxww 2>/dev/null
  fi
}

list_ipv4_network() {
  if have sockstat; then
    sockstat -4 2>/dev/null
  elif have netstat; then
    netstat -an -f inet 2>/dev/null || netstat -ant 2>/dev/null || netstat -an 2>/dev/null
  else
    return 1
  fi
}

hunt_hashes_offline() {
  local prompt_mode="${1:-prompt}"
  section "SHA-256 IOC search"
  if ! have sha256sum && ! have sha256 && ! have openssl; then
    log ERROR "No SHA-256 tool is available. Skipping."
    return
  fi

  if [[ "$prompt_mode" == "prompt" ]]; then
    printf 'Hashing can be slow on large support bundles. Continue? [y/N]: '
    read -r ans
    [[ "$ans" =~ ^[Yy]$ ]] || { log INFO "Hash search cancelled."; return; }
  else
    log WARN "Complete hunt selected; running SHA-256 search of candidate files. This can be slow on large support bundles."
  fi

  local f h found=0 count=0
  while IFS= read -r -d '' f; do
    [[ "$NO_REPORT" != "1" && "$f" == "$REPORT" ]] && continue
    # Limit to plausible payload/config artifacts to avoid hashing gigantic dumps.
    case "$f" in
      *.deb|*.sig|*.php|*.pl|*.py|*.sh|*.tgz|*.html|*.js|*.txt|*.conf|*/.x|*/x|*/.host|*/host|*/nsmon.pl)
        h=$(hash_file "$f" || true)
        ((count+=1))
        if [[ -n "$h" && -n "${IOC_HASHES[$h]+x}" ]]; then
          log ALERT "SHA256 MATCH: $h | ${IOC_HASHES[$h]} | $f"
          found=1
        fi
        ;;
    esac
  done < <(find "$ROOT" -type f -print0 2>/dev/null)

  log INFO "Hashed $count candidate files."
  (( found == 0 )) && log INFO "No known SHA-256 IOCs found."
}

offline_all() {
  hunt_cve_2026_88779_offline
  hunt_log_behavior_offline
  hunt_ip_iocs_offline
  hunt_webshell_patterns_offline
  hunt_named_artifacts_offline
  hunt_timeline_gaps_offline
  hunt_hashes_offline no-prompt
}

hunt_timeline_gaps_offline() {
  section "HTTP logs: suspicious paths / errors / large 404 responses"
  local f
  while IFS= read -r -d '' f; do
    case "$f" in
      *.gz)
        have zgrep && zgrep -Ein '/vpn/(media|scripts|theme)/|\.deb|\.sig|\.ico' "$f" 2>/dev/null | head -n 200 | emit_stream || true
        ;;
      *)
        grep -Ein '/vpn/(media|scripts|theme)/|\.deb|\.sig|\.ico' "$f" 2>/dev/null | head -n 200 | emit_stream || true
        ;;
    esac
  done < <(find "$ROOT" -type f \( -name 'httpaccess*' -o -name 'httperror*' \) -print0 2>/dev/null)
  log INFO "Pay special attention to 404 responses with unusually large response bodies or long processing times, and to gaps/truncated lines."
}

show_iocs() {
  section "Built-in IOCs and hunting pivots"
  printf 'Network indicators:\n' | emit_stream
  printf '  %s\n' "${IOC_IPS[@]}" | emit_stream
  printf '\nDomain indicators:\n' | emit_stream
  printf '  %s\n' "${IOC_DOMAINS[@]}" | emit_stream
  printf '\nFile/path indicators:\n' | emit_stream
  printf '  %s\n' "${IOC_PATHS[@]}" | emit_stream
  printf '\nKnown SHA-256 hashes:\n' | emit_stream
  local h
  for h in "${!IOC_HASHES[@]}"; do
    printf '  %s  %s\n' "$h" "${IOC_HASHES[$h]}" | emit_stream
  done
}

# -----------------------------
# LIVE NETSCALER READ-ONLY HUNTS
# -----------------------------

live_artifacts() {
  section "LIVE: known file artifacts"
  local p found=0
  for p in "${IOC_PATHS[@]}"; do
    if [[ -e "$p" ]]; then
      log ALERT "Found IOC/hunting path: $p"
      ls -ald "$p" 2>&1 | emit_stream
      found=1
    fi
  done
  (( found == 0 )) && log INFO "None of the built-in IOC paths currently exist."

  for d in /var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux /var/netscaler/logon/LogonPoint/custom /var/netscaler/logon/LogonPoint; do
    if [[ -d "$d" ]]; then
      log INFO "Listing recently modified files in $d (last 45 days)."
      list_recent_files "$d" | emit_stream || true
    fi
  done
}

live_saml_second_wave() {
  section "LIVE: SAML / second-wave pivots"
  local f found=0
  for f in /flash/nsconfig/ns.conf /nsconfig/ns.conf; do
    [[ -r "$f" ]] || continue
    log INFO "Checking SAML applicability in $f"
    grep -Ein '^add authentication saml(Action|IdPProfile)' "$f" 2>/dev/null | emit_stream || true
    if grep -Eiq '^add authentication saml(Action|IdPProfile)' "$f" 2>/dev/null; then
      log WARN "SAML authentication action/profile present in $f. Citrix says SAML Gateway/AAA deployments are in scope for the separate October 2 issue."
      found=1
    fi
  done

  for f in /var/log/ns.log /var/log/ns.log.* /var/log/messages /var/log/messages.*; do
    [[ -r "$f" ]] || continue
    grep -Ein 'proc nsaaad.*(SIGNALED|EXITED)|maximum number of restarts|Pitboss declaring system failure|All monitored processes have exited, rebooting|213\.209\.159\.55:443/t/|pyrlnk\.cc|pylrk\.cc|fetch\$\{IFS\}-qo\$\{IFS\}/v|fetch\$\{IFS\}-qo-\$\{IFS\}https://f\.pylrk\.cc' "$f" 2>/dev/null | tail -n 250 | emit_stream || true
  done

  if [[ -e /v ]]; then
    log ALERT "Found /v payload path reported in second-wave SAML/log-injection activity."
    ls -la /v 2>&1 | emit_stream
  fi
  if [[ -d /var/core ]]; then
    find /var/core -maxdepth 2 -name 'nsaaad-*.gz' -print 2>/dev/null | while IFS= read -r core; do
      log WARN "Found nsaaad core file: $core"
      ls -la "$core" 2>&1 | emit_stream
    done
  fi

  (( found == 0 )) && log INFO "No SAML action/profile lines found in the checked NetScaler config files."
}

live_cve_2026_88779() {
  section "LIVE: CVE-2026-88779 applicability (SAML configuration)"
  local f checked=0 found=0
  for f in /flash/nsconfig/ns.conf /nsconfig/ns.conf; do
    [[ -r "$f" ]] || continue
    ((checked+=1))
    log INFO "Checking CVE-2026-88779 SAML preconditions in $f"
    if report_saml_config_file "$f"; then
      found=1
    fi
  done

  if (( checked == 0 )); then
    log WARN "No readable ns.conf found in the checked locations; CVE-2026-88779 applicability could not be assessed."
  elif (( found == 0 )); then
    log INFO "No SAML SP/IdP precondition directives found in the checked ns.conf file(s); this does not establish that the appliance is unaffected."
  fi
  log INFO "Read-only configuration check only: it does not query the running build or detect exploitation. Verify the version separately with the NetScaler CLI (show ns version) and compare with Citrix CTX697174."
}

live_web_config() {
  section "LIVE: Apache/PHP configuration"
  local f found=0
  for f in /etc/httpd.conf /nsconfig/httpd.conf /flash/nsconfig/httpd.conf; do
    [[ -r "$f" ]] || continue
    log INFO "Checking $f"
    grep -Ein 'application/x-httpd-php|php_flag|AliasMatch|AddHandler|AddType|\.deb|\.sig|\.tgz|\.rpm|receiver\.min|\.ctxs\.receiver|LogonUISimple\.html\.style' "$f" 2>/dev/null | emit_stream || true
    if grep -Eiq 'application/x-httpd-php.*\.(deb|sig|tgz|rpm)|AliasMatch.*(/vpn/media|/vpn/theme|/vpn/images)|receiver\.min|\.ctxs\.receiver|LogonUISimple\.html\.style' "$f" 2>/dev/null; then
      log ALERT "Suspicious web server configuration in $f."
      found=1
    fi
  done
  (( found == 0 )) && log INFO "None of the most specific configuration pivots matched."
}

live_dtls_nsppe() {
  section "LIVE: DTLS / NSPPE / pitboss"
  local files=(/var/log/messages /var/log/messages.* /var/log/ns.log /var/log/ns.log.*)
  local f
  for f in "${files[@]}"; do
    [[ -r "$f" ]] || continue
    log INFO "Searching $f"
    grep -Ein 'SSL_HANDSHAKE_FAILURE|DTLSv1\.0|Handshake failure-Internal Error|NOT restarting NSPPE|NSPPE.*exit|orphan rings|pitboss PPE unexpectedly died' "$f" 2>/dev/null | tail -n 250 | emit_stream || true
  done
  log WARN "DTLS/NSPPE hits require timeline correlation. A crash or handshake failure alone is not proof of compromise."
}

live_http_logs() {
  section "LIVE: HTTP access/error logs"
  local f
  for f in /var/log/httpaccess.log /var/log/httpaccess.log.* /var/log/httpaccess-vpn.log /var/log/httpaccess-vpn.log.* /var/log/httperror*; do
    [[ -r "$f" ]] || continue
    grep -Ein '/admin_ui/common/css/ns/ui\.css|/vpn/js/rdx/core/lang/rdx_en\.json\.gz|/vpn/(media|scripts|theme)/|GetUserName|nsgclient|nsginstaller|\.deb|\.sig|receiver\.min|LogonUISimple\.html\.style|HTTP_NSC_|HTTP_X_UX' "$f" 2>/dev/null | tail -n 300 | emit_stream || true
  done
  log INFO "Investigate 404 responses with large bodies/long processing times and chronological gaps in access logs."
}

live_shell_permissions() {
  section "LIVE: /bin/sh permissions"
  if [[ -e /bin/sh ]]; then
    ls -l /bin/sh | emit_stream
    local perm
    perm=$(ls -ld /bin/sh 2>/dev/null | awk '{print $1}')
    if [[ "$perm" == *s* ]]; then
      log ALERT "/bin/sh has the SUID/SGID bit set ($perm). This is known post-exploitation behavior and must be investigated."
    else
      log INFO "No visible SUID/SGID bit on /bin/sh."
    fi
  fi
}

live_processes() {
  section "LIVE: processes and IPC artifacts"
  list_processes | grep -Ei 'python.*(uxdport|uxdlock|base64)|nohup|nsmon|update_c08937|main\.py|customsnmpd|\.local_journal|nsg(client|installer)' | grep -v grep | emit_stream || true
  for p in /tmp/.uxdport /tmp/.uxdlock /var/tmp/.nsmon; do
    if [[ -e "$p" ]]; then
      log ALERT "Found IPC/persistence artifact: $p"
      ls -la "$p" 2>&1 | emit_stream
      [[ "$p" == "/tmp/.uxdport" && -r "$p" ]] && { printf 'Contents of .uxdport: '; cat "$p" 2>/dev/null | emit_stream; printf '\n'; }
    fi
  done
}

live_cron() {
  section "LIVE: cron persistence"
  local f
  for f in /etc/crontab /nsconfig/crontab; do
    [[ -r "$f" ]] || continue
    log INFO "Checking $f"
    nl -ba "$f" 2>/dev/null | grep -Ei 'nsmon|/var/tmp/\.nsmon|curl|wget|python|perl|/vpn/scripts|/var/1\.py' | emit_stream || true
  done
}

live_accounts_config() {
  section "LIVE: privileged account / ns.conf pivots"
  for f in /flash/nsconfig/ns.conf /nsconfig/ns.conf; do
    [[ -r "$f" ]] || continue
    log INFO "Checking $f"
    grep -Ein 'sec_monitor|add system user|bind system user.*superuser|update_result_3567cs|\.local_journal|receiver\.min' "$f" 2>/dev/null | emit_stream || true
    if grep -Eiq 'sec_monitor' "$f" 2>/dev/null; then
      log ALERT "Found sec_monitor in $f."
    fi
  done
}

live_network() {
  section "LIVE: listeners and connections"
  if have sockstat; then
    log INFO "sockstat output (IPv4):"
    list_ipv4_network | emit_stream || true
    log INFO "Listeners on 41000-41999 (Arctic Wolf nsmon observation):"
    sockstat -4 -l 2>/dev/null | grep -E ':(41[0-9]{3})([[:space:]]|$)' | emit_stream || true
  elif have netstat; then
    list_ipv4_network | emit_stream || true
  else
    log WARN "Neither sockstat nor netstat is available."
  fi

  local regex
  regex=$(build_network_ioc_regex)

  local conn_hits=""
  conn_hits=$(list_ipv4_network 2>/dev/null | grep -E "$regex" || true)
  if [[ -n "$conn_hits" ]]; then
    printf '%s\n' "$conn_hits" | emit_stream
    log ALERT "Active connection matches a historical IOC IP."
  fi
}

live_ioc_logs() {
  section "LIVE: historical IOC IPs/domains in local logs"
  local regex f
  regex=$(build_network_ioc_regex)
  for f in /var/log/messages* /var/log/ns.log* /var/log/httpaccess* /var/log/httperror* /var/log/sh.log*; do
    [[ -r "$f" ]] || continue
    grep -Ein "$regex" "$f" 2>/dev/null | tail -n 250 | emit_stream || true
  done
}

live_hash_candidates() {
  section "LIVE: known hashes in high-risk paths"
  if ! have sha256sum && ! have sha256 && ! have openssl; then
    log WARN "No SHA-256 tool is available."
    return
  fi
  local d f h found=0
  for d in /var/netscaler/gui/vpn/scripts/linux /netscaler/ns_gui/vpn/scripts/linux /var/netscaler/logon/LogonPoint /tmp /var/tmp; do
    [[ -d "$d" ]] || continue
    while IFS= read -r -d '' f; do
      case "$f" in
        *.deb|*.sig|*.php|*.pl|*.py|*.sh|*.tgz|*.html|*.js|*/.ctxs.receiver|*/.local_journal)
          h=$(hash_file "$f" || true)
          if [[ -n "$h" && -n "${IOC_HASHES[$h]+x}" ]]; then
            log ALERT "SHA256 MATCH: $h | ${IOC_HASHES[$h]} | $f"
            found=1
          fi
          ;;
      esac
    done < <(find "$d" -type f -print0 2>/dev/null)
  done
  (( found == 0 )) && log INFO "No known hashes found in the selected paths."
}

live_all() {
  live_artifacts
  live_cve_2026_88779
  live_saml_second_wave
  live_web_config
  live_dtls_nsppe
  live_http_logs
  live_shell_permissions
  live_processes
  live_cron
  live_accounts_config
  live_network
  live_ioc_logs
  live_hash_candidates
}

# -----------------------------
# MENUS
# -----------------------------

offline_menu() {
  printf 'Path to exported logs/support bundle: '
  read -r ROOT
  if [[ ! -d "$ROOT" ]]; then
    log ERROR "Not a directory: $ROOT"
    return
  fi
  ROOT=$(cd "$ROOT" 2>/dev/null && pwd -P) || return
  log INFO "Offline root set to $ROOT"

  while true; do
    cat <<'MENU'

Offline threat hunt - individual checks:
  1) DTLS/NSPPE/pitboss + exploit behavior
  2) Historical IOC IPs
  3) Web shell/PHP/Apache patterns
  4) Known file/path indicators
  5) HTTP log pivots (.deb/.sig/.ico/vpn paths)
  6) SHA-256 search of candidate files
  7) Show IOC list
  8) CVE-2026-88779 SAML configuration precondition
  0) Back
MENU
    printf 'Choice: '
    read -r choice
    case "$choice" in
      1) hunt_log_behavior_offline ;;
      2) hunt_ip_iocs_offline ;;
      3) hunt_webshell_patterns_offline ;;
      4) hunt_named_artifacts_offline ;;
      5) hunt_timeline_gaps_offline ;;
      6) hunt_hashes_offline ;;
      7) show_iocs ;;
      8) hunt_cve_2026_88779_offline ;;
      0) return ;;
      *) printf 'Invalid choice.\n' ;;
    esac
    pause
  done
}

live_menu() {
  log WARN "LIVE checks do not patch, delete, kill, restart, or change NetScaler configuration/services."
  if [[ "$NO_REPORT" == "1" ]]; then
    log INFO "Strict no-report mode is enabled; the script will not create its report file."
  else
    log WARN "The script WILL write its report file locally: $REPORT"
  fi
  log WARN "For strict forensic preservation, prefer a copied support bundle or use NETSCALER_HUNT_NO_REPORT=1."
  while true; do
    cat <<'MENU'

Live NetScaler threat hunt (read-only):
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
  0) Back
MENU
    printf 'Choice: '
    read -r choice
    case "$choice" in
      1) live_artifacts ;;
      2) live_saml_second_wave ;;
      3) live_web_config ;;
      4) live_dtls_nsppe ;;
      5) live_http_logs ;;
      6) live_shell_permissions ;;
      7) live_processes ;;
      8) live_cron ;;
      9) live_accounts_config ;;
      10) live_network ;;
      11) live_ioc_logs ;;
      12) live_hash_candidates ;;
      13) show_iocs ;;
      14) live_cve_2026_88779 ;;
      0) return ;;
      *) printf 'Invalid choice.\n' ;;
    esac
    pause
  done
}

usage() {
  cat <<EOF2
Usage:
  $0                  Interactive menu
  $0 --complete       Guided complete hunt: choose offline bundle or live appliance
  $0 --offline DIR    Run the complete offline hunt against DIR
  $0 --live-all       Run all read-only live checks
  $0 --show-iocs      Show built-in IOCs
  $0 --help           Show help

Report is written to: $REPORT
Set NETSCALER_HUNT_NO_REPORT=1 to disable report-file writes.
Set NETSCALER_HUNT_REPORT=/path/file.log to choose the report path.
EOF2
}

complete_offline_hunt() {
  printf 'Path to exported logs/support bundle: '
  read -r ROOT
  if [[ ! -d "$ROOT" ]]; then
    log ERROR "Not a directory: $ROOT"
    return
  fi
  ROOT=$(cd "$ROOT" 2>/dev/null && pwd -P) || return
  log INFO "Offline root set to $ROOT"
  offline_all
  print_summary
}

complete_live_hunt() {
  log WARN "LIVE checks do not patch, delete, kill, restart, or change NetScaler configuration/services."
  if [[ "$NO_REPORT" == "1" ]]; then
    log INFO "Strict no-report mode is enabled; the script will not create its report file."
  else
    log WARN "The script WILL write its report file locally: $REPORT"
  fi
  log WARN "For strict forensic preservation, prefer a copied support bundle or use NETSCALER_HUNT_NO_REPORT=1."
  live_all
  print_summary
}

complete_guided_hunt() {
  while true; do
    cat <<'MENU'

Complete guided hunt:
  1) Offline: copied logs/support bundle/local evidence
  2) Live: this NetScaler appliance (read-only)
  0) Back
MENU
    printf 'Choice: '
    read -r choice
    case "$choice" in
      1) complete_offline_hunt; return ;;
      2) complete_live_hunt; return ;;
      0) return ;;
      *) printf 'Invalid choice.\n' ;;
    esac
  done
}

main_menu() {
  banner
  while true; do
    cat <<'MENU'
Main menu:
  1) Complete offline hunt: copied logs/support bundle/local evidence
  2) Complete live hunt: this NetScaler appliance (read-only)
  3) Individual offline checks
  4) Individual live checks
  5) Show built-in IOCs and hashes
  6) Show help
  0) Exit
MENU
    printf 'Choice: '
    read -r choice
    case "$choice" in
      1) complete_offline_hunt; pause ;;
      2) complete_live_hunt; pause ;;
      3) offline_menu ;;
      4) live_menu ;;
      5) show_iocs; pause ;;
      6) usage; pause ;;
      0) print_summary; if [[ "$NO_REPORT" == "1" ]]; then log INFO "Exiting. Report disabled."; else log INFO "Exiting. Report: $REPORT"; fi; exit 0 ;;
      *) printf 'Invalid choice.\n' ;;
    esac
  done
}

case "${1:-}" in
  --complete)
    banner
    complete_guided_hunt
    ;;
  --offline)
    [[ $# -ge 2 ]] || { usage; exit 2; }
    ROOT="$2"
    [[ -d "$ROOT" ]] || { echo "Not a directory: $ROOT" >&2; exit 2; }
    ROOT=$(cd "$ROOT" && pwd -P)
    banner
    offline_all
    print_summary
    ;;
  --live-all)
    banner
    live_all
    print_summary
    ;;
  --show-iocs)
    banner
    show_iocs
    print_summary
    ;;
  --help|-h)
    usage
    ;;
  "")
    main_menu
    ;;
  *)
    usage
    exit 2
    ;;
esac
