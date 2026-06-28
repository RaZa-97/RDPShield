# RDPShield - Dissertation Evidence

Single home for every screenshot, table, and raw data file behind Chapter 6.
Capture once, file it here with the right name, and it drops straight into the
dissertation figures/tables. Tick the checklist as you go.

## Folder map

```
evidence/
  screenshots/
    fig04_dashboard_home/      Figure 4  - dashboard home (dark, cards+charts+map)
    fig05_auth_flow/           Figure 5  - /login, /mfa (QR), /unlock
    fig06_attack_in_action/    Figure 6  - attacker terminal + dashboard alert + SMS
    fig07_alert_breakdown/     Figure 7  - Alert Breakdown chart
    fig08_attack_map/          Figure 8  - live attack map
    fig09_failed_login_trend/  Figure 9  - daily failed-login trend chart
    tests/
      T1_fast_bruteforce/      T1 evidence (attacker output + dashboard + SMS)
      T2_slow_low/             T2 evidence
      T3_password_spray/       T3 evidence
      T4_persistent/           T4 evidence
      T5_geo_whitelist/        T5 evidence
      T6_legit_login/          T6 evidence (false-positive check)
      T7_reputation/           T7 evidence (reputation alert/auto-block + SMS)
      T8_campaign/             T8 evidence (campaigns tracker + alert/auto-block)
    hardening/                 Table 8  - security hardening pass/fail output
  data/                        Auto-generated tables (collect_evidence.py output)
  logs/                        Daily JSON reports + agent log slices per test
```

## Naming convention

`<slot>__<what>__<YYYY-MM-DD>.png`  (double underscore between fields)

- **slot**  = `figNN` or `TN` (matches the folder it lives in)
- **what**  = short, lower-case, hyphenated description
- **date**  = capture date, ISO so files sort chronologically

Examples:
```
fig06_attack_in_action/  T1__attacker-terminal__2026-06-27.png
fig06_attack_in_action/  T1__dashboard-alert__2026-06-27.png
fig06_attack_in_action/  T1__sms-screenshot__2026-06-27.png
tests/T5_geo_whitelist/  T5__geo-block-event__2026-06-27.png
hardening/               table8__hardening-pass__2026-06-27.png
```

Blur or crop any secret (TOTP seed, phone number, real source IPs you don't want
published) before saving. Keep the *original* uncropped copy out of the repo if
it shows anything sensitive.

## Generating the data tables (4-7)

Run on the **server** (live honeypot DB) after a `git pull`, or locally against a
copied-down snapshot:

```
python tools/collect_evidence.py                 # uses rdpshield.db
python tools/collect_evidence.py --db rdpshield_train.db   # a local snapshot
```

Output lands in `evidence/data/<timestamp>/`:
- `tables.md`        - Tables 4-7 as Markdown (paste into Word)
- `table4..7 .csv`   - same data for Excel / re-charting
- `raw_rows.json`    - the raw DB rows behind every number (bring to the viva)

> Timestamps are UTC. A negative latency means two time sources disagree on the
> clock - on the all-UTC server this won't happen; it only shows in mixed
> local+server snapshots.

## Capture checklist

### Figures (Phase 2)
- [ ] Fig 4  - dashboard home (desktop, dark theme)
- [ ] Fig 5  - auth flow: /login + /mfa (QR) + /unlock
- [ ] Fig 6  - attack in action: terminal + dashboard alert + SMS (capture during T1)
- [ ] Fig 7  - Alert Breakdown chart
- [ ] Fig 8  - live attack map
- [ ] Fig 9  - daily failed-login trend chart

### Controlled tests T1-T6 (Phase 1.1) - record Detected / Blocked / SMS for each
- [ ] T1 - fast brute force        (`slow_attack_test.py --mode fast`)
- [ ] T2 - slow-and-low            (`--mode slow`)
- [ ] T3 - password spray          (`--mode spray`)
- [ ] T4 - persistent / low-and-slow (`--mode persistent`)
- [ ] T5 - geo / whitelist block   (set restrictive mode, single connect, then reset)
- [ ] T6 - legitimate login w/ 1-2 typos (must NOT alert - false-positive check)
- [ ] T7 - reputation / threat-intel (low-volume known-bad IP -> alert/auto-block)
- [ ] T8 - campaign / coordinated-attack (7-day rollup -> tracker + SMS + auto-block)

### Data + hardening
- [ ] Ran `collect_evidence.py` on the server -> Tables 4-7 in `data/`
- [ ] Table 8 - security hardening pass/fail output saved in `hardening/`
- [ ] Daily JSON reports copied from server `logs/` into `evidence/logs/`

See `tools/TEST_RUNBOOK.md` for the exact command and expected result per test.
