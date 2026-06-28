# RDPShield — Test Runbook (T1–T8) for Dissertation Chapter 6

> All eight controlled tests in one place. Run each, watch the dashboard, and fill
> Table 6 (detected/blocked/SMS) and the latency table in the dissertation.
>
> ⚠ **Authorisation:** only against YOUR own server, and **from a different
> network than you administer it from** (e.g. a phone hotspot) so RDPShield
> blocks the attacker IP, not your admin IP. Have the dashboard open on your
> admin network while testing.

Set your target once:

```bash
TARGET=16.170.232.91        # your honeypot IP
USER=administrator
```

Before each test note the exact **start time** (first attempt) so you can compute
detection-to-block latency.

---

## T1 — Fast brute force  *(trips 5 failures / 60 s)*
```bash
python3 slow_attack_test.py -t $TARGET -u $USER --mode fast
```
*Alternative (Hydra):*
```bash
printf 'Winter2024!\nPassword1\nAdmin@123\nLetmein2024\nQwerty123!\nSummer2024\n' > pw.txt
hydra -t 4 -V -l $USER -P pw.txt rdp://$TARGET
```
**Expect:** a `brute_force` alert, the IP blocked, and an SMS within seconds.
**Record:** Detected? Blocked? SMS? + time-to-block.

## T2 — Slow-and-low  *(trips 10 failures / 600 s)*
```bash
python3 slow_attack_test.py -t $TARGET -u $USER --mode slow
```
**Expect:** a `slow_attack` alert after ~10 paced attempts (~10 min).
**Record:** did the timing-aware detector catch what a fast-only rule would miss?

## T3 — Password spraying  *(trips 4 usernames / 300 s)*
```bash
python3 slow_attack_test.py -t $TARGET --mode spray
```
*Alternative (Hydra):*
```bash
printf 'admin\nadministrator\nuser\nguest\ntest\n' > users.txt
hydra -t 1 -L users.txt -p 'Password123!' rdp://$TARGET
```
**Expect:** a `password_spray` alert naming multiple usernames.

## T4 — Persistent / low-and-slow  *(cumulative catch-all, 15 failures / 24 h)*
```bash
python3 slow_attack_test.py -t $TARGET -u $USER --mode persistent
```
(17 attempts @75 s, ~21 min — paced to stay under brute force *and* slow-and-low.)
**Expect:** a `persistent_attack` alert once the cumulative count crosses **15**,
with no short window ever reaching its threshold. This is your strongest evidence
that layering detectors catches paced attackers.
> Note: the threshold is `PERSISTENT_MAX_FAILURES` (now 15, was 5). Confirm the
> server `config.py` has 15 (it's gitignored — `git pull` won't change it).

## T5 — Geo / whitelist block  *(access control, not behaviour)*
1. On the dashboard → **Advanced Security**, set a restrictive mode:
   - *Country list:* add only a country you are NOT connecting from, **or**
   - *Whitelist only:* add a different IP (NOT your current one).
   - (Add your admin IP first if needed so you don’t lock yourself out.)
2. From the attacker box, attempt a single RDP connection:
   ```bash
   xfreerdp /v:$TARGET /u:$USER /p:whatever /cert:ignore +auth-only
   ```
**Expect:** a `geo_block` or `whitelist_block` event and an immediate block.
3. **Reset the mode back to allow-anywhere afterwards.**

## T6 — Legitimate traffic  *(FALSE-POSITIVE check — must NOT alert)*
From a **whitelisted/allowed** machine, do a NORMAL RDP login: mistype the
password once or twice, then enter the correct one and log in successfully.
```bash
# from your admin machine, just use the normal Remote Desktop client (mstsc)
```
**Expect:** **no** alert and **no** block — a legitimate user with a typo should
not be punished. Record this as your false-positive result.

## T7 — Reputation / threat-intel  *(low-volume, reputation-driven)*
Catches a known-bad IP that trips **no** count rule. The hard part is a
reputable-bad source IP — use a Tor/known-bad VPN exit, **or** temporarily lower
the bar to exercise the path: set `REPUTATION_ALERT_SCORE = 1` (keep
`REPUTATION_MIN_ATTEMPTS = 3`) in the server `config.py`, restart the agent.
```bash
for i in 1 2 3 4; do hydra -t 1 -l $USER -p "x$i" rdp://$TARGET; sleep 30; done
python3 window_check.py $ATTACKER_IP   # shows brute<5/60s and slow<10/600s — count rules miss it
```
**Expect:** a `reputation_alert` + SMS to the SOC. If AbuseIPDB ≥ 85% (or ≥ 50%
and VirusTotal flags it) the IP is **blocked** too; otherwise it's **alert-only**.
Re-running within 24 h won't re-text (dedup). **Reset `REPUTATION_ALERT_SCORE` to 50.**

## T8 — Campaign / coordinated-attack  *(long-horizon, 7-day correlation)*
Catches sustained multi-day campaigns: one IP over many days, many IPs from one
country, or attempts recurring in the same time-of-day band. This is a rollup of
the honeypot's own data, so it's best demonstrated against accumulated traffic.
```bash
# Dry run on the server shows what it would flag right now (no SMS/block):
python campaign_detector.py
```
To force a demo without a week of data, temporarily lower the bar in the server
`config.py` (e.g. `CAMPAIGN_COUNTRY_MIN_FAILS = 10`, `CAMPAIGN_IP_MIN_FAILS = 8`,
`CAMPAIGN_IP_MIN_DAYS = 1`), restart the agent, generate a couple of dozen fails
across two sessions, then check the **Campaigns (7-day)** panel. Put the values back.
**Expect:** a `campaign_alert` + SMS to the SOC and a row in the Campaigns tracker;
the worst single-IP campaigns are **auto-blocked**, countries are **alert-only**.
A campaign clustered in one daily time-band shows a **Scheduled** badge + the window.

---

## After all eight tests
- Fill **Table 6** (Detected / Blocked / SMS, Yes/No for T1–T8).
- Fill **Table 4** (latency): read timestamps from the agent log and the
  `alerts` / `blocked_ips` rows; latency = block time − first-attempt time.
- Capture **Figure 6** (attacker terminal + dashboard alert + SMS) during T1.
- **Unblock** the test IPs from the dashboard between runs if the same IP is
  reused (a blocked IP can’t reach the server again).

> Tip: to demo multiple attack types from the same IP, unblock between tests, or
> temporarily set `AUTO_BLOCK_ENABLED = False` to collect alerts without blocking.
