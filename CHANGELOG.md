# Changelog

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