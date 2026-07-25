"""
RDPShield Central — SSO token issuance (RS256)
==============================================
Mints the short-lived, single-use, signed token that lets an operator click
"Open Dashboard" on an agent row and land inside that instance's own dashboard
without a second login.

Signing happens HERE and only here, with the private key that never leaves
Central. Verification happens on the instance, in the pure-stdlib
`central_sso_verify.py` at the repo root — see that module for why the two
halves are implemented differently.

What the token carries
----------------------
    iss   "rdpshield-central"      who minted it
    aud   the agent's agent_uid    WHICH BOX may accept it — an instance
                                   rejects a token whose aud is not its own
                                   configured agent id, so a token for one
                                   customer's server is useless against another
    sub   the Central username     recorded in the instance's audit log
    role  the mapped LOCAL role    superadmin/customer_admin -> "admin"
    cid   the customer id          for the instance's audit detail
    jti   a random id              the instance records it to enforce single use
    iat / nbf / exp                ~60-second window

The token is a bearer credential for a dashboard session, so it is deliberately
useless almost immediately: 60 seconds, one use, one named agent.
"""

import base64
import json
import os
import secrets
import sys
import time

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding
except ImportError:  # pragma: no cover - Central refuses to start without it
    hashes = serialization = padding = None

import central_config as cfg

# The shared verifier lives at the repo root (it ships to customer boxes).
# Importing it here lets Central self-check that what it signs is exactly what
# an instance will accept — the two halves can never silently drift.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import central_sso_verify  # noqa: E402

_HERE = os.path.dirname(os.path.abspath(__file__))

# Central -> instance role mapping. Central's tenancy roles both map to the
# instance's "admin"; the instance has no concept of tenants, so this is the
# whole mapping. Anything unrecognised degrades to the least-privileged local
# role rather than failing open.
ROLE_MAP = {
    "superadmin": "admin",
    "customer_admin": "admin",
}
DEFAULT_LOCAL_ROLE = "guest"

_private_key = None


class SSOIssueError(Exception):
    """Central could not mint a token (missing/unusable signing key)."""


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def private_key_path():
    return os.path.join(_HERE, getattr(cfg, "CENTRAL_SSO_PRIVATE_KEY_PATH",
                                       "central_sso_private.pem"))


def public_jwk_path():
    return os.path.join(_HERE, getattr(cfg, "CENTRAL_SSO_PUBLIC_JWK_PATH",
                                       "central_sso_public.jwk.json"))


def keys_present():
    return os.path.exists(private_key_path()) and os.path.exists(public_jwk_path())


def load_public_jwk():
    with open(public_jwk_path(), "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_private_key():
    global _private_key
    if _private_key is not None:
        return _private_key
    if serialization is None:
        raise SSOIssueError(
            "The 'cryptography' package is required on Central to sign SSO "
            "tokens.  pip install cryptography")
    path = private_key_path()
    try:
        with open(path, "rb") as fh:
            _private_key = serialization.load_pem_private_key(fh.read(), password=None)
    except FileNotFoundError:
        raise SSOIssueError(
            f"No SSO signing key at {path}. Run:  python central_keygen.py")
    except Exception as exc:
        raise SSOIssueError(f"Could not load the SSO signing key: {exc}")
    return _private_key


def map_role(central_role):
    """Central role -> the equivalent role inside the instance dashboard."""
    return ROLE_MAP.get(central_role, DEFAULT_LOCAL_ROLE)


def issue_token(agent_uid, username, central_role, customer_id=None, ttl=None):
    """Mint a signed, short-lived, single-use SSO token for one agent.

    `agent_uid` becomes the audience, so the token is bound to exactly one box.
    Returns (token_string, claims_dict)."""
    key = _load_private_key()

    ttl = int(ttl or getattr(cfg, "CENTRAL_SSO_TOKEN_TTL", 60))
    max_ttl = int(getattr(cfg, "CENTRAL_SSO_MAX_TTL", 300))
    # Keep issuance under the ceiling the instance independently enforces, so a
    # misconfigured TTL fails here (visibly) rather than at the instance.
    ttl = max(10, min(ttl, max_ttl))

    now = int(time.time())
    claims = {
        "iss": getattr(cfg, "CENTRAL_SSO_ISSUER", "rdpshield-central"),
        "aud": agent_uid,
        "sub": username,
        "role": map_role(central_role),
        "cid": customer_id,
        "jti": secrets.token_urlsafe(18),
        "iat": now,
        "nbf": now,
        "exp": now + ttl,
    }
    header = {"alg": "RS256", "typ": "JWT", "kid": "rdpshield-central-sso"}

    def seg(obj):
        return _b64url(json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    signing_input = (seg(header) + "." + seg(claims)).encode("ascii")
    signature = key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    token = signing_input.decode("ascii") + "." + _b64url(signature)
    return token, claims


def self_check():
    """Sign a throwaway token and verify it with the SAME pure-stdlib code the
    instances run. Called at startup so a broken/mismatched keypair is caught on
    Central's console, not by a customer clicking "Open Dashboard".

    Returns (ok: bool, message: str)."""
    try:
        token, claims = issue_token("selfcheck-agent", "selfcheck",
                                    "superadmin", customer_id=0, ttl=30)
        got = central_sso_verify.verify_token(
            token,
            load_public_jwk(),
            expected_audience="selfcheck-agent",
            expected_issuer=claims["iss"],
        )
        if got.get("jti") != claims["jti"]:
            return False, "self-check token verified but claims did not match"
        # A token for a different agent must NOT verify.
        try:
            central_sso_verify.verify_token(
                token, load_public_jwk(), expected_audience="some-other-agent",
                expected_issuer=claims["iss"])
        except central_sso_verify.SSOError:
            pass
        else:
            return False, "audience binding is not being enforced"
        return True, "SSO keypair OK (signed and verified via the instance code path)"
    except SSOIssueError as exc:
        return False, str(exc)
    except Exception as exc:
        return False, f"SSO self-check failed: {exc}"


if __name__ == "__main__":
    ok, msg = self_check()
    print(("[SSO] OK  — " if ok else "[SSO] FAIL — ") + msg)
    sys.exit(0 if ok else 1)
