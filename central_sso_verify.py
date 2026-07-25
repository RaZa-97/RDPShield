"""
RDPShield — SSO token verification (pure standard library)
==========================================================
Verifies the short-lived RS256 JWTs that RDPShield Central issues when an
operator clicks "Open Dashboard" on an agent. This module runs on the CUSTOMER
BOX, inside the ordinary per-instance dashboard, so it deliberately imports
NOTHING outside the Python standard library.

Why hand-rolled instead of PyJWT + cryptography
-----------------------------------------------
The customer servers run **32-bit Python 3.11**, where native wheels are a
recurring problem (see PROGRESS.md: psutil 7.x and scikit-learn both had to be
worked around). `cryptography` is exactly that class of dependency. Rather than
risk a customer box being unable to install it, we use the same train/serve
split the ML layer already uses: the heavy, well-audited library does the hard
half on a machine we control, and the box runs a small pure-stdlib routine.

Concretely: **Central signs** with PyJWT + `cryptography` (audited code, a
64-bit host we choose) and **the instance verifies** here. Verification is the
safe half to implement by hand -- it uses only PUBLIC key material and a single
modular exponentiation (`pow`, which Python provides), so there is no secret to
leak through a side channel and no decryption to build a padding oracle from.

The one classic pitfall in a hand-written RSA verifier is *parsing* the padded
block leniently, which enables Bleichenbacher's e=3 signature forgery. This
implementation never parses: it rebuilds the entire expected block and does a
single constant-time comparison of the whole thing (`_pkcs1_v15_encode` +
`hmac.compare_digest`). Anything that is not a byte-for-byte match is rejected.

Threat model note: a valid token proves only that Central minted it. All the
authorisation decisions -- which agent, which local role, how long it lives --
are Central's, and are re-checked here against the instance's own configured
agent id (the `aud` claim) so a token minted for one customer's box cannot be
replayed against another.
"""

import base64
import hashlib
import hmac
import json
import time

# DigestInfo prefix for SHA-256, from RFC 8017 §9.2 notes. The full PKCS#1 v1.5
# signature block is:  0x00 0x01 <0xFF padding> 0x00 <this prefix> <sha256>
_SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")

# Reject absurd clock skew but tolerate a little; Central issues ~60s tokens.
DEFAULT_LEEWAY = 30


class SSOError(Exception):
    """A token was missing, malformed, expired, or failed verification."""


# --- base64url -----------------------------------------------------------
def b64url_decode(data):
    """Decode base64url without padding (JWT segments omit '=')."""
    if isinstance(data, str):
        data = data.encode("ascii")
    pad = -len(data) % 4
    return base64.urlsafe_b64decode(data + b"=" * pad)


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


# --- RSA PKCS#1 v1.5 / SHA-256 verification ------------------------------
def _pkcs1_v15_encode(message, key_len_bytes):
    """Build the complete expected PKCS#1 v1.5 signature block for `message`.

    We construct the block rather than parsing the one recovered from the
    signature, so a forged block with short padding or trailing garbage can
    never match. Returns None if the key is too small to hold the block."""
    digest = hashlib.sha256(message).digest()
    suffix = _SHA256_DIGEST_INFO + digest
    # 0x00 0x01 | PS (>= 8 bytes of 0xFF) | 0x00 | suffix
    ps_len = key_len_bytes - len(suffix) - 3
    if ps_len < 8:
        return None
    return b"\x00\x01" + b"\xff" * ps_len + b"\x00" + suffix


def rsa_verify_sha256(message, signature, n, e):
    """True if `signature` is a valid RS256 signature over `message`.

    `n` and `e` are the public modulus and exponent as Python ints. Only public
    operations are performed."""
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    sig_int = int.from_bytes(signature, "big")
    if sig_int >= n:
        return False
    recovered = pow(sig_int, e, n).to_bytes(k, "big")
    expected = _pkcs1_v15_encode(message, k)
    if expected is None:
        return False
    return hmac.compare_digest(recovered, expected)


# --- public key handling -------------------------------------------------
def load_public_jwk(jwk):
    """Accept a JWK dict (or its JSON string) and return (n, e) as ints.

    The instance stores Central's public key in its config as this JWK JSON.
    A public key is not a secret -- it can only verify, never sign."""
    if isinstance(jwk, str):
        jwk = jwk.strip()
        if not jwk:
            raise SSOError("No Central SSO public key configured.")
        try:
            jwk = json.loads(jwk)
        except ValueError as exc:
            raise SSOError(f"Central SSO public key is not valid JSON: {exc}")
    if not isinstance(jwk, dict):
        raise SSOError("Central SSO public key must be a JWK object.")
    if jwk.get("kty") != "RSA":
        raise SSOError("Central SSO public key must be an RSA JWK.")
    try:
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
    except (KeyError, ValueError, TypeError) as exc:
        raise SSOError(f"Malformed RSA JWK: {exc}")
    if n < 2 ** 1023:
        raise SSOError("Central SSO public key is smaller than 1024 bits; refusing.")
    return n, e


# --- JWT verification ----------------------------------------------------
def verify_token(token, public_jwk, expected_audience, expected_issuer="rdpshield-central",
                 leeway=DEFAULT_LEEWAY, max_lifetime=300):
    """Verify a Central-issued SSO token and return its claims dict.

    Raises SSOError on any problem. Checks, in order:
      * three well-formed segments
      * header alg is exactly RS256 (never 'none', never an HMAC alg -- an
        attacker must not be able to downgrade us into verifying with the
        public key as an HMAC secret)
      * the RSA signature over "<header>.<payload>"
      * iss matches Central
      * aud matches THIS agent -- a token minted for another customer's box is
        rejected even though its signature is perfectly valid
      * exp / nbf / iat within `leeway`
      * the token's total lifetime is not absurd (guards against Central being
        misconfigured to mint long-lived tokens)
      * jti is present, so the caller can enforce single use
    """
    if not token or not isinstance(token, str):
        raise SSOError("Missing SSO token.")
    parts = token.split(".")
    if len(parts) != 3:
        raise SSOError("Malformed SSO token.")
    head_b64, payload_b64, sig_b64 = parts

    try:
        header = json.loads(b64url_decode(head_b64))
        claims = json.loads(b64url_decode(payload_b64))
        signature = b64url_decode(sig_b64)
    except (ValueError, TypeError) as exc:
        raise SSOError(f"Unreadable SSO token: {exc}")

    if not isinstance(header, dict) or not isinstance(claims, dict):
        raise SSOError("SSO token header/payload must be JSON objects.")

    # Algorithm confusion defence: accept one algorithm and one only.
    if header.get("alg") != "RS256":
        raise SSOError(f"Unsupported SSO token algorithm: {header.get('alg')!r}")

    n, e = load_public_jwk(public_jwk)
    signing_input = (head_b64 + "." + payload_b64).encode("ascii")
    if not rsa_verify_sha256(signing_input, signature, n, e):
        raise SSOError("SSO token signature is not valid.")

    # --- claim checks (only after the signature is proven) ---
    if expected_issuer and claims.get("iss") != expected_issuer:
        raise SSOError("SSO token was not issued by this Central.")

    aud = claims.get("aud")
    aud_ok = (aud == expected_audience
              or (isinstance(aud, list) and expected_audience in aud))
    if not aud_ok:
        raise SSOError("SSO token was issued for a different agent.")

    now = time.time()
    exp = claims.get("exp")
    if not isinstance(exp, (int, float)):
        raise SSOError("SSO token has no expiry.")
    if now > exp + leeway:
        raise SSOError("SSO token has expired.")

    nbf = claims.get("nbf")
    if isinstance(nbf, (int, float)) and now < nbf - leeway:
        raise SSOError("SSO token is not valid yet.")

    iat = claims.get("iat")
    if isinstance(iat, (int, float)):
        if now < iat - leeway:
            raise SSOError("SSO token was issued in the future.")
        if exp - iat > max_lifetime:
            raise SSOError("SSO token lifetime exceeds the allowed maximum.")

    if not claims.get("jti"):
        raise SSOError("SSO token has no jti; cannot enforce single use.")

    return claims
