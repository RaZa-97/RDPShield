"""
RDPShield — link this instance to RDPShield Central
===================================================
Writes the CENTRAL_* block into this instance's `config.py` for you.

Enrolment is otherwise a manual copy-paste of five settings plus a ~500-character
public key, into the right one of two similarly-named config files. That is
error-prone in a console over RDP: a key pasted with a line break, a block
collapsed onto one line, or an edit saved into `central/central_config.py`
instead of `config.py` all fail later, in confusing ways and far from the cause.

This script takes the two values Central shows you once at enrolment, reads the
public key straight off disk (so it can never be mistyped), validates the lot,
and appends a correctly-formatted block.

Run it from the project root, on the protected server:

    python tools/link_central.py --agent-id ag_... --api-key rdps_...

Common options:
    --central-url URL     where the agent should reach Central
                          (default https://localhost:6100 — correct when Central
                          runs on this same host; a cloud instance generally
                          cannot reach its own public address)
    --verify-tls PATH     pin verification to a certificate file, which is what
                          a self-signed Central needs
    --jwk PATH            Central's public JWK (default: ../central/…)
    --managed             also set CENTRAL_MANAGED = True (disables local login;
                          do this only AFTER check-ins are working)
    --force               append again even if CENTRAL_* is already present

Nothing is overwritten: the block is appended, and Python takes the last
assignment, so re-running with --force cleanly supersedes an earlier attempt.
"""

import argparse
import json
import os
import re
import shutil
import sys
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

DEFAULT_JWK = os.path.join(_ROOT, "central", "central_sso_public.jwk.json")
CONFIG_PATH = os.path.join(_ROOT, "config.py")


def fail(msg):
    sys.exit(f"\n[LINK] ERROR: {msg}\n")


def load_jwk(path):
    """Read Central's public JWK and return it as a compact one-line string."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            jwk = json.load(fh)
    except FileNotFoundError:
        fail(f"No public key at {path}.\n"
             "       On the Central host run:  python central_keygen.py --show\n"
             "       then pass the file with --jwk, or copy it to that path.")
    except ValueError as exc:
        fail(f"{path} is not valid JSON: {exc}")

    if jwk.get("kty") != "RSA" or "n" not in jwk or "e" not in jwk:
        fail(f"{path} does not look like an RSA public JWK.")
    # separators=(",",":") keeps it on one line — a line break inside the string
    # is the classic way this value gets corrupted by hand.
    return json.dumps(jwk, separators=(",", ":"))


def main():
    ap = argparse.ArgumentParser(
        description="Write the CENTRAL_* block into this instance's config.py.")
    ap.add_argument("--agent-id", required=True, help="ag_... from enrolment")
    ap.add_argument("--api-key", required=True, help="rdps_... from enrolment")
    ap.add_argument("--central-url", default="https://localhost:6100",
                    help="where this agent reaches Central (default: %(default)s)")
    ap.add_argument("--verify-tls", default="",
                    help="path to Central's certificate, to pin verification")
    ap.add_argument("--jwk", default=DEFAULT_JWK, help="Central's public JWK file")
    ap.add_argument("--managed", action="store_true",
                    help="also set CENTRAL_MANAGED = True (disables local login)")
    ap.add_argument("--force", action="store_true",
                    help="append even if CENTRAL_* settings already exist")
    args = ap.parse_args()

    # --- validate the arguments before touching anything ---
    if not args.agent_id.startswith("ag_"):
        fail(f"--agent-id should start with 'ag_' (got {args.agent_id!r}).")
    if not args.api_key.startswith("rdps_"):
        fail(f"--api-key should start with 'rdps_' (got {args.api_key[:12]!r}…).")
    if not args.central_url.startswith(("https://", "http://")):
        fail("--central-url must start with https:// or http://")
    if args.central_url.startswith("http://"):
        print("[LINK] WARNING: an http:// Central sends the API key in clear text.\n"
              "       The reporter will refuse unless CENTRAL_ALLOW_INSECURE_HTTP\n"
              "       is also set. Use https:// on anything but a local test.")
    if args.verify_tls and not os.path.exists(args.verify_tls):
        fail(f"--verify-tls file not found: {args.verify_tls}")

    if not os.path.exists(CONFIG_PATH):
        fail(f"No config.py at {CONFIG_PATH}.\n"
             "       Run this from the project root on the protected server.")

    jwk = load_jwk(args.jwk)

    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        existing = fh.read()

    if re.search(r"^\s*CENTRAL_\w+\s*=", existing, re.M) and not args.force:
        fail("config.py already contains CENTRAL_* settings.\n"
             "       Re-run with --force to append a fresh block (the later\n"
             "       assignments win), or edit the existing ones by hand.")

    # --- back up, then append ---
    backup = CONFIG_PATH + datetime.now().strftime(".%Y%m%d-%H%M%S.bak")
    shutil.copy2(CONFIG_PATH, backup)

    lines = [
        "",
        "",
        f"# --- RDPShield Central (written by tools/link_central.py"
        f" on {datetime.now().strftime('%Y-%m-%d %H:%M')}) ---",
        "CENTRAL_ENABLED  = True",
        f'CENTRAL_URL      = "{args.central_url}"',
        f'CENTRAL_AGENT_ID = "{args.agent_id}"',
        f'CENTRAL_API_KEY  = "{args.api_key}"',
    ]
    if args.verify_tls:
        lines.append(f'CENTRAL_VERIFY_TLS = r"{args.verify_tls}"')
    lines.append(f"CENTRAL_SSO_PUBLIC_KEY = {jwk!r}")
    lines.append(f"CENTRAL_MANAGED  = {bool(args.managed)}")
    lines.append("")

    if not existing.endswith("\n"):
        lines.insert(0, "")

    with open(CONFIG_PATH, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines))

    # --- verify by loading it the way the dashboard will ---
    sys.path.insert(0, _ROOT)
    try:
        import config
    except Exception as exc:
        shutil.copy2(backup, CONFIG_PATH)
        fail(f"config.py failed to load after the edit, so it has been RESTORED\n"
             f"       from {backup}.\n       {type(exc).__name__}: {exc}")

    try:
        written = json.loads(config.CENTRAL_SSO_PUBLIC_KEY)
        source = json.loads(jwk)
        key_ok = written.get("n") == source.get("n")
    except Exception:
        key_ok = False

    print()
    print("[LINK] config.py updated. Loaded values:")
    print(f"         CENTRAL_ENABLED  = {config.CENTRAL_ENABLED}")
    print(f"         CENTRAL_URL      = {config.CENTRAL_URL}")
    print(f"         CENTRAL_AGENT_ID = {config.CENTRAL_AGENT_ID}")
    print(f"         CENTRAL_MANAGED  = {config.CENTRAL_MANAGED}")
    if args.verify_tls:
        print(f"         CENTRAL_VERIFY_TLS = {config.CENTRAL_VERIFY_TLS}")
    print(f"         public key       = {'MATCHES Central' if key_ok else '*** MISMATCH ***'}")
    print(f"         backup           = {backup}")
    if not key_ok:
        fail("the public key did not round-trip; restore the backup and retry.")

    print()
    print("[LINK] Next: restart the dashboard so it picks this up.")
    print('         schtasks /end /tn "RDPShield-Dashboard"')
    print('         schtasks /run /tn "RDPShield-Dashboard"')
    print("       Then look for a line like:")
    print(f"         [CENTRAL] Reporting to {config.CENTRAL_URL} as "
          f"{config.CENTRAL_AGENT_ID} every 60s.")
    print()


if __name__ == "__main__":
    main()
