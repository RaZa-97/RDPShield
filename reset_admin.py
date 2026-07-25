"""
RDPShield — root admin recovery / reset (run on the server console)
===================================================================
Use this when you cannot sign in — e.g. a fresh install left an unusable
auto-seeded 'admin', or you forgot the root password and MFA. It creates the
root admin if none exists, or resets the password (and clears MFA so you can
re-enrol) of an existing account.

Run it locally on the server:

    python reset_admin.py                         # interactive prompts
    python reset_admin.py --username admin         # prompts for password only
    python reset_admin.py --username admin --password "S0me-Strong-Pass"

After it finishes, open the dashboard, sign in with these credentials, and
enrol MFA on the first login. Change nothing else — this only touches the one
account. This script has NO network access and never prints the password.
"""

import argparse
import getpass
import sys

import auth
import database

MIN_PASSWORD_LEN = 8


def _read_password():
    while True:
        pw = getpass.getpass("New password (min 8 chars): ")
        if len(pw) < MIN_PASSWORD_LEN:
            print(f"  Too short — needs at least {MIN_PASSWORD_LEN} characters.")
            continue
        again = getpass.getpass("Confirm password: ")
        if pw != again:
            print("  Passwords didn't match — try again.")
            continue
        return pw


def main():
    ap = argparse.ArgumentParser(description="Create or reset the RDPShield root admin.")
    ap.add_argument("--username", help="admin username (default: 'admin')")
    ap.add_argument("--password", help="new password (min 8 chars); prompted if omitted")
    args = ap.parse_args()

    # Make sure the users table exists even on a brand-new database.
    database.create_users_table()

    username = (args.username or "").strip()
    if not username:
        existing = database.list_users()
        default = existing[0]["username"] if existing else "admin"
        entered = input(f"Admin username [{default}]: ").strip()
        username = entered or default

    password = args.password
    if password is None:
        password = _read_password()
    elif len(password) < MIN_PASSWORD_LEN:
        print(f"[FAIL] Password must be at least {MIN_PASSWORD_LEN} characters.")
        sys.exit(1)

    pw_hash = auth.hash_password(password)
    user = database.get_user_by_username(username)

    if user:
        # Reset the existing account: new password, promote to root admin, mark
        # verified, and clear MFA so a fresh enrolment happens on next login.
        database.update_user_password(user["id"], pw_hash)
        database.set_user_totp(user["id"], None, 0)
        conn = database.get_connection(); c = conn.cursor()
        c.execute("UPDATE users SET role='admin', is_root=1, disabled=0, verified=1 "
                  "WHERE id=?", (user["id"],))
        conn.commit(); conn.close()
        print(f"[ OK ] Reset root admin '{username}': new password set, MFA cleared, "
              f"account enabled.")
    else:
        uid = database.create_user(username, pw_hash, role="admin",
                                   is_root=1, verified=1)
        if not uid:
            print(f"[FAIL] Could not create '{username}'.")
            sys.exit(1)
        print(f"[ OK ] Created root admin '{username}'.")

    print("      Sign in at the dashboard and enrol MFA on this first login.")


if __name__ == "__main__":
    main()
