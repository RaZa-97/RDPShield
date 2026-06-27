# RDPShield — Attack Test Plan & System Validation

> Authorized testing only: run against your own EC2 instance from your own
> Kali Linux VM. Target in examples: `16.170.232.91:3389`.

This plan drives every detection path and every response component, and gives a
checklist to confirm the full system works end-to-end.

---

## 0. Test Setup

### Network isolation (avoid locking yourself out)
- **Attacker** = Kali VM on **ProtonVPN** (the VPN exit IP gets blocked, not your
  real IP). A mobile hotspot works too — either way the attacker just needs a
  public IP different from your admin IP.
- **Observer/Admin** = a machine on your **home wifi**, RDP'd into the EC2 box,
  watching `http://localhost:5000` *inside* the RDP session.
- Because the observer is on a different public IP, blocking the attacker never
  kills your dashboard/RDP access.
- Bonus: pick the ProtonVPN exit **country** to drive real `geo_block` events
  (T5) and a wider country spread for Table 7.

### Confirm the basics (on Kali)
```bash
curl ifconfig.me                 # note this as ATTACKER_IP
nc -zv 16.170.232.91 3389        # must say succeeded/open
```

### Baseline
On the dashboard, note the current values: Failed Logins, Alerts, IPs Blocked.

### Reset procedure (run BETWEEN tests)
A block drops **all** traffic from the attacker IP, so the next test can't reach
the server until you unblock. After each test:
1. On the dashboard → **Blocked IPs** → **Unblock** the ATTACKER_IP, **or**
2. Note that the hotspot may hand you a new IP (CGNAT) — then it's a fresh attacker.

### Wordlists (on Kali — all fake, nothing is actually compromised)
```bash
printf 'Winter2024\nPassword1\nadmin123\nLetmein1\nQwerty123\nSummer2024\nWelcome1\nP@ssw0rd\n' > /tmp/pw.txt
printf 'administrator\nadmin\nuser\nguest\ntest\noperator\nsql\nbackup\n' > /tmp/users.txt
```

---

## 1. Test Matrix (quick reference)

| # | Attack | Tool / pattern | Expected alert | Auto-block | SMS |
|---|--------|----------------|----------------|-----------|-----|
| 1 | Fast brute force | 1 user, many passwords, fast | `brute_force` | yes | yes |
| 2 | Password spray | many users, 1 password | `password_spray` | yes | yes |
| 3 | Slow & low / persistent | 1 user, paced ~30s apart | `persistent_attack` | yes | yes |
| 4 | Geo-block (advanced) | any login from blocked geo | `geo_block` | yes | yes |
| 5 | Manual block | dashboard Block button | `manual_block` | yes | **no** |
| 6 | Already-blocked (negative) | attack a blocked IP | none (dropped) | n/a | no |

---

## 2. Detailed Tests

### Test 1 — Fast Brute Force  → `brute_force`
**Goal:** ≥5 failed logins in 60s from one IP.
```bash
hydra -t 4 -V -l administrator -P /tmp/pw.txt rdp://16.170.232.91
```
_(If hydra's RDP module misbehaves, fall back to:_
`ncrack --user administrator -P /tmp/pw.txt rdp://16.170.232.91`_)_

**Verify:** see the per-test checklist in §3. Expected alert badge: **BRUTE FORCE**.
**Reset:** unblock ATTACKER_IP.

---

### Test 2 — Password Spray  → `password_spray`
**Goal:** ≥4 distinct usernames from one IP within 300s.
```bash
hydra -t 1 -V -L /tmp/users.txt -p 'Password123' rdp://16.170.232.91
```
**Verify:** alert badge **PASSWORD SPRAY**; description lists the usernames tried.
**Reset:** unblock ATTACKER_IP.

---

### Test 3 — Slow & Low / Persistent  → `persistent_attack`
**Goal:** accumulate **15** failures (the `PERSISTENT_MAX_FAILURES` threshold)
while pacing **>60s apart** so you stay under brute force (5/60s) AND slow-and-low
(10/600s) — only the cumulative persistent detector should trip.
```bash
# Easiest: the paced generator (17 attempts @75s, ~21 min)
python3 slow_attack_test.py -t 16.170.232.91 -u administrator --mode persistent
# Or by hand: 17 single attempts, 75s apart
for i in $(seq 1 17); do
  hydra -t 1 -l administrator -p "wrongpass$i" rdp://16.170.232.91
  sleep 75
done
```
**Verify:** alert badge **PERSISTENT ATTACK**; this proves low-and-slow bots that
pace themselves under the rate detectors are still caught.
**Reset:** unblock ATTACKER_IP.

---

### Test 4 — Geo-Block (advanced, optional)  → `geo_block`
> ⚠️ This uses a lockout-capable mode. Add your admin path to the allow list
> FIRST. If you get locked out: AWS Console → Security Group fix, or connect
> from a different IP, then unblock.

1. Dashboard → **Geolocation** → add your **home-wifi public IP** to Allowed IPs.
2. Switch mode to **whitelist-only** (`private_and_allowed`) and Apply (confirm modal).
3. From the Kali VM (ProtonVPN/hotspot IP — NOT whitelisted), attempt any login:
   ```bash
   hydra -t 1 -l administrator -p 'x' rdp://16.170.232.91
   ```
**Verify:** alert badge **GEO BLOCK**; geo event logged on the Geolocation page.
**Reset:** switch mode back to **allow_anywhere**, unblock ATTACKER_IP.

---

### Test 5 — Manual Block  → `manual_block` (no SMS)
**Goal:** confirm operator-initiated blocks work and do NOT send SMS.
1. Dashboard → Recent Failed Logins → **Block** on an attacker row
   (or type an IP into the **Block IP** field).
**Verify:** appears in Blocked IPs; **MANUAL BLOCK** alert; its country shows in
Top Attacker Countries; a YARA scan runs; **no SMS** is sent.

---

### Test 6 — Already-Blocked IP (negative test)
**Goal:** confirm the firewall block actually stops traffic.
1. With ATTACKER_IP still blocked, run any attack again from it.
**Verify:** no new failed logins appear (packets are dropped at the firewall).
This proves the block is effective. Unblock afterwards.

---

## 3. Per-Test Verification Checklist

After each blocking test, confirm on the dashboard / phone:

- [ ] **Failed Logins** counter increased
- [ ] **Alert** appears with the correct **type badge**
- [ ] Attacker IP listed in **Blocked IPs** with an **Attempts** count
- [ ] **Country** resolved (Recent Alerts, Recent Failed Logins, Top Countries)
- [ ] **Abuse Score** populated (AbuseIPDB enrichment)
- [ ] **YARA scan** logged: YARA Controller → Scan History shows a `post_block:<ip>` scan
- [ ] **SMS** received (auto-block tests only) containing IP, country, reason,
      attempt count, and YARA result
- [ ] Manual block test: **no SMS** received

---

## 4. Full-System Validation

- [ ] Top Attacker Countries lists every blocked country, **highest→lowest**
- [ ] Dashboard auto-refreshes (~10s)
- [ ] `python daily_report.py` writes `logs/rdpshield_report_<date>.json` with a
      populated `attackers` array (country, attempts, detections, block, YARA)
- [ ] Scheduled tasks survive RDP disconnect (blocks/agent keep running)
- [ ] No self-lockout: your admin/home-wifi IP retained access throughout

---

## 5. Notes & Cautions
- **SMS volume:** every distinct attacker that reaches `PERSISTENT_MAX_FAILURES`
  (now 15/24h) triggers an SMS. Raising it from 5 → 15 also cuts SMS noise on a
  public honeypot (fewer one-off scanners cross the bar); lower it again if you
  want more sensitivity.
- **Persistent no longer shadows the others:** at the old value of 5, almost
  every attacker hit persistent first and the brute/slow/spray detectors rarely
  got to claim their own attacks. At 15/24h, persistent only fires for genuinely
  determined low-and-slow attackers, so a 10-in-600s paced attack now correctly
  registers as `slow_attack` and a 5-in-60s burst as `brute_force`.
- **Recon (nmap) is not detected:** RDPShield watches failed logons (Event 4625),
  not port scans. `nmap -p 3389 16.170.232.91` won't raise an alert.
