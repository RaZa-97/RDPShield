# RDPShield — Test Runbook (T1–T6) for Dissertation Chapter 6

> All six controlled tests in one place. Run each, watch the dashboard, and fill
> Table 3 (detected/blocked/SMS) and Table 4 (latency) in the dissertation.
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

## T4 — Persistent / low-and-slow  *(cumulative catch-all)*
```bash
python3 slow_attack_test.py -t $TARGET -u $USER --mode persistent
```
**Expect:** a `persistent_attack` alert from the cumulative detector after the
others’ short windows have lapsed (~20 min). This is your strongest evidence
that layering detectors catches paced attackers.

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

---

## After all six tests
- Fill **Table 3** (Detected / Blocked / SMS, Yes/No for T1–T6).
- Fill **Table 4** (latency): read timestamps from the agent log and the
  `alerts` / `blocked_ips` rows; latency = block time − first-attempt time.
- Capture **Figure 6** (attacker terminal + dashboard alert + SMS) during T1.
- **Unblock** the test IPs from the dashboard between runs if the same IP is
  reused (a blocked IP can’t reach the server again).

> Tip: to demo multiple attack types from the same IP, unblock between tests, or
> temporarily set `AUTO_BLOCK_ENABLED = False` to collect alerts without blocking.
