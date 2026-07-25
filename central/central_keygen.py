"""
RDPShield Central — one-time SSO signing key generation
=======================================================
Creates the RSA keypair Central uses to sign click-through SSO tokens.

    cd central
    python central_keygen.py

Writes two files next to this script:

    central_sso_private.pem       SECRET. Never leaves Central. Gitignored.
    central_sso_public.jwk.json   Public. Copy into each instance's config.py
                                  as CENTRAL_SSO_PUBLIC_KEY.

Why the split matters: an instance holds only the PUBLIC key, which can verify
a token but can never mint one. So even a fully compromised customer box cannot
forge an SSO session into any dashboard — not another customer's, and not its
own. See CENTRAL.md, "Threat model".

Refuses to overwrite existing keys unless you pass --force; regenerating the
keypair invalidates every instance's configured public key at once and every
one of them must be updated before SSO works again.
"""

import argparse
import base64
import json
import os
import sys

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
except ImportError:
    sys.exit(
        "This script needs the 'cryptography' package (Central only — the\n"
        "customer instances verify with the pure-stdlib central_sso_verify.py\n"
        "and need nothing installed).\n\n"
        "    pip install cryptography\n"
    )

import central_config as cfg

_HERE = os.path.dirname(os.path.abspath(__file__))
KEY_SIZE = 3072   # comfortably above the 2048 floor for a long-lived signing key


def _b64url_uint(value):
    """Encode a non-negative int as base64url, per RFC 7518 §2 (JWK numbers)."""
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def generate(force=False):
    priv_path = os.path.join(_HERE, getattr(cfg, "CENTRAL_SSO_PRIVATE_KEY_PATH",
                                            "central_sso_private.pem"))
    pub_path = os.path.join(_HERE, getattr(cfg, "CENTRAL_SSO_PUBLIC_JWK_PATH",
                                           "central_sso_public.jwk.json"))

    if os.path.exists(priv_path) and not force:
        sys.exit(
            f"Refusing to overwrite {priv_path}.\n"
            "Regenerating invalidates the public key configured on EVERY enrolled\n"
            "instance — each one must be updated before SSO works again.\n"
            "Pass --force if that is really what you want."
        )

    print(f"[KEYGEN] Generating a {KEY_SIZE}-bit RSA keypair…")
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(priv_path, "wb") as fh:
        fh.write(pem)
    # Best-effort: make the private key owner-readable only. On Windows this is
    # a no-op, so the real protection there is filesystem ACLs on central/.
    try:
        os.chmod(priv_path, 0o600)
    except OSError:
        pass

    nums = key.public_key().public_numbers()
    jwk = {
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "kid": "rdpshield-central-sso",
        "n": _b64url_uint(nums.n),
        "e": _b64url_uint(nums.e),
    }
    with open(pub_path, "w", encoding="utf-8") as fh:
        json.dump(jwk, fh, indent=2)

    print(f"[KEYGEN] Private key -> {priv_path}   (SECRET, gitignored)")
    print(f"[KEYGEN] Public JWK  -> {pub_path}")
    print()
    print("Add this to every managed instance's config.py as one line:")
    print()
    print("    CENTRAL_SSO_PUBLIC_KEY = " + repr(json.dumps(jwk, separators=(",", ":"))))
    print()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Generate Central's SSO signing keypair.")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing keypair (invalidates all instances)")
    generate(ap.parse_args().force)
