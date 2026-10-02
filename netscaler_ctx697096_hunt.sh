#!/usr/bin/env bash
# NetScaler CTX697096 Threat Hunt Helper
# Defensive/read-only hunting for CVE-2026-88771 / CVE-2026-88772 activity and related post-exploitation.
#
# Sources used for indicators and hunt logic (verified 2026-10-02):
#   - Citrix CTX697096 security bulletin:
#     https://support.citrix.com/external/article/CTX697096
#   - Google Threat Intelligence Group / Mandiant:
#     https://cloud.google.com/blog/topics/threat-intelligence/defending-against-active-exploitation-of-citrix-netscaler-adc-and-gateway-appliances
#   - Palo Alto Networks Unit 42:
#     https://unit42.paloaltonetworks.com/netscaler-zero-days-exploited/
#   - Beazley Security Labs BSL-A1216:
#     https://labs.beazley.security/advisories/BSL-A1216
#   - PitScaler public briefing / IOC compilation:
#     https://pitscaler.com/
#   - watchTowr Labs technical analysis:
#     https://labs.watchtowr.com/
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

VERSION="1.1"
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
)

# Host/file indicators.
IOC_PATHS=(
  "/vpn/scripts/linux/nsgclient18.deb"
  "/vpn/scripts/linux/nsgser18.deb"
  "/vpn/scripts/linux/nsg64.deb"
  "/vpn/scripts/linux/nsgsupport.deb"
  "/vpn/scripts/linux/nsgpackage64.deb"
  "/vpn/scripts/linux/nsgbuild.deb"
  "/logon/LogonPoint/Authentication/GetUserName"
  "/var/netscaler/logon/LogonPoint/custom/.ctxs.receiver"
  "/var/netscaler/gui/vpn/scripts/linux/nsgclient.sig"
  "/var/netscaler/gui/vpn/scripts/linux/e6ee7c85.sig"
  "/netscaler/ns_gui/vpn/scripts/linux/nsgclient.sig"
  "/netscaler/ns_gui/vpn/scripts/linux/e6ee7c85.sig"
  "/vpn/media/nsgclient.ico"
  "/var/netscaler/logon/LogonPoint/.local_journal"
  "/tmp/.uxdport"
  "/tmp/.uxdlock"
  "/tmp/update_result_3567cs.tgz"
  "/var/netscaler/logon/insight-new.js"
  "/var/netscaler/logon/LogonPoint/xua.html"
  "/var/tmp/.nsmon"
  "/var/1.py"
)

# Known hashes from Unit 42 / LevelBlue.
declare -A IOC_HASHES
IOC_HASHES["ae22ef2517b5c0fb47f78745b9cb5260acee0e751b89bcd354640ff8bc8d29ec"]="Unit42 nsg64.deb webshell"
IOC_HASHES["1bd314b661396c7086f6367fbbb48025e03ca2de69c073d53a8b0a38aa5fbb7d"]="Unit42 encoded payload text"
IOC_HASHES["79c65fa04541032e251fa4796b97800374b63c7982593dd1a2e0db605d429186"]="Unit42 decoded shell-script text"
IOC_HASHES["e9fe43968c6c0955300e3bc4d7fb0b05a18570b4733aaf4f5c6f7f09be5a242c"]="LevelBlue main.py"
IOC_HASHES["974b69782fdf5d67b97cfd508465939e44ee10798dbcc1e82b92d78776bad938"]="LevelBlue update_c08937.pl"
IOC_HASHES["6f5a2a452a7901323abd21879c6cecccb47c06aeeaccb1b467212f3b11e4b1e7"]="GreyNoise .ctxs.receiver webshell"

# Strings / behavior pivots. These are intentionally broader than exact IOCs.
LOG_PATTERNS=(
  "SSL_HANDSHAKE_FAILURE"
  "DTLSv1.0"
  "Handshake failure-Internal Error"
  "NOT restarting NSPPE"
  "NSPPE.*exit"
  "orphan rings"
  "pitboss PPE unexpectedly died"
  "pitboss PPE missed too many heartbeats"
  "HTTP_NSC_LDAP"
  "HTTP_NSC_CLIENTTYPE"
  "HTTP_X_UX"
  "INDEX:"
  "ns-88771-poc"
  "NX-CVE-OK"
  "httpworkbench\.com"
  "/vpn/media/"
  "/vpn/scripts/"
  "/nf/auth/doAuthentication\.do"
  "/logon/LogonPoint/Authentication/GetUserName"
  "GetUserName"
  "receiver.min.css"
  "LogonUISimple.html.style.min.css"
  "sec_monitor"
  '\$\{IFS\}'
  "customsnmpd"
  "update_result_3567cs.tgz"
  "\.ctxs\.receiver"
  "\.local_journal"
  "\.uxdport"
  "\.uxdlock"
  "nsmon.pl"
  "/var/tmp/\.nsmon"
  "/var/1.py"
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
  "passthru[[:space:]]*\\("
  "eval[[:space:]]*\\("
  "HTTP_NSC_LDAP"
  "HTTP_NSC_CLIENTTYPE"
  "HTTP_X_UX"
  "NSC_TASS"
  "CsrfToken"
  "e826d7ddf3c85920"
  "7489a0f93c67fa5cdaeb4b921d90594d"
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

hunt_log_behavior_offline() {
  local regex
  regex=$(build_regex_from_array LOG_PATTERNS)
  search_tree_regex "$ROOT" "$regex" "Log and exploit behavior"
}

hunt_ip_iocs_offline() {
  local regex=""
  local ip
  for ip in "${IOC_IPS[@]}"; do
    [[ -n "$regex" ]] && regex+="|"
    regex+="${ip//./\\.}"
  done
  search_tree_regex "$ROOT" "$regex" "Historical network IOCs"
}

hunt_webshell_patterns_offline() {
  local regex
  regex=$(build_regex_from_array WEBSHELL_PATTERNS)
  search_tree_regex "$ROOT" "$regex" "Web shell / PHP / Apache indicators"
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
      *.deb|*.sig|*.php|*.pl|*.py|*.sh|*.tgz|*.html|*.js|*.txt|*.conf)
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

live_web_config() {
  section "LIVE: Apache/PHP configuration"
  local f found=0
  for f in /etc/httpd.conf /nsconfig/httpd.conf /flash/nsconfig/httpd.conf; do
    [[ -r "$f" ]] || continue
    log INFO "Checking $f"
    grep -Ein 'application/x-httpd-php|php_flag|AliasMatch|AddHandler|AddType|\.deb|\.sig|\.tgz|\.rpm|receiver\.min|LogonUISimple\.html\.style' "$f" 2>/dev/null | emit_stream || true
    if grep -Eiq 'application/x-httpd-php.*\.(deb|sig|tgz|rpm)|AliasMatch.*(/vpn/media|/vpn/theme|/vpn/images)|receiver\.min|LogonUISimple\.html\.style' "$f" 2>/dev/null; then
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
    grep -Ein '/vpn/(media|scripts|theme)/|GetUserName|nsgclient|nsginstaller|\.deb|\.sig|receiver\.min|LogonUISimple\.html\.style|HTTP_NSC_|HTTP_X_UX' "$f" 2>/dev/null | tail -n 300 | emit_stream || true
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

  local regex="" ip
  for ip in "${IOC_IPS[@]}"; do
    [[ -n "$regex" ]] && regex+="|"
    regex+="${ip//./\\.}"
  done

  local conn_hits=""
  conn_hits=$(list_ipv4_network 2>/dev/null | grep -E "$regex" || true)
  if [[ -n "$conn_hits" ]]; then
    printf '%s\n' "$conn_hits" | emit_stream
    log ALERT "Active connection matches a historical IOC IP."
  fi
}

live_ioc_logs() {
  section "LIVE: historical IOC IPs in local logs"
  local regex="" ip f
  for ip in "${IOC_IPS[@]}"; do
    [[ -n "$regex" ]] && regex+="|"
    regex+="${ip//./\\.}"
  done
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
  0) Back
MENU
    printf 'Choice: '
    read -r choice
    case "$choice" in
      1) live_artifacts ;;
      2) live_web_config ;;
      3) live_dtls_nsppe ;;
      4) live_http_logs ;;
      5) live_shell_permissions ;;
      6) live_processes ;;
      7) live_cron ;;
      8) live_accounts_config ;;
      9) live_network ;;
      10) live_ioc_logs ;;
      11) live_hash_candidates ;;
      12) show_iocs ;;
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
