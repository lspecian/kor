"""Firebase Admin SDK for Python against Kor's sign-in bridge, as Python
backends commonly use it: verifying each request's ID token with
check_revoked=True, and managing users.

Usage: FIREBASE_AUTH_EMULATOR_HOST=host:port python admin_sdk.py <label>
Exits non-zero when a check fails. Needs kord with -identity-project
$PROJECT -admin-tokens owner -identity-trust-unsigned-custom-tokens.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request
import uuid

import firebase_admin
from firebase_admin import auth

label = sys.argv[1] if len(sys.argv) > 1 else "kor"
project = os.environ.get("PROJECT", "kor-auth-test")
host = os.environ["FIREBASE_AUTH_EMULATOR_HOST"]
app = firebase_admin.initialize_app(options={"projectId": project}, name=f"admin-{uuid.uuid4().hex[:6]}")
run = uuid.uuid4().hex[:8]
email = f"py.{run}@example.com"
results: dict[str, str] = {}
state: dict[str, str] = {}


def rest(op, body):
    req = urllib.request.Request(
        f"http://{host}/identitytoolkit.googleapis.com/v1/accounts:{op}?key=test",
        data=json.dumps(body).encode(), headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as res:
            return res.status, json.load(res)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)


def sign_in(password="first-pass"):
    code, body = rest("signInWithPassword", {"email": email, "password": password, "returnSecureToken": True})
    assert code == 200, f"sign-in HTTP {code}: {body}"
    return body["idToken"]


def check(name):
    def wrap(fn):
        try:
            detail = fn()
            results[name] = f"PASS {detail if detail is not None else ''}".strip()
        except Exception as e:  # noqa: BLE001 - a suite reports every failure
            results[name] = f"FAIL {type(e).__name__}: {str(e)[:200]}"
        print(f"  {results[name][:4]} {name}{'' if results[name].startswith('PASS') else ' — ' + results[name][5:]}", flush=True)
        return fn
    return wrap


print(f"Firebase Admin SDK for Python ({label}):")


@check("create_user, get_user, get_user_by_email")
def _():
    u = auth.create_user(email=email, password="first-pass", display_name="Py", app=app)
    state["uid"] = u.uid
    assert auth.get_user(u.uid, app=app).email == email
    assert auth.get_user_by_email(email.upper(), app=app).uid == u.uid


@check("verify_id_token with check_revoked")
def _():
    claims = auth.verify_id_token(sign_in(), check_revoked=True, app=app)
    assert claims["uid"] == state["uid"] and claims["email"] == email, claims


@check("set_custom_user_claims reach ID tokens")
def _():
    auth.set_custom_user_claims(state["uid"], {"role": "admin"}, app=app)
    assert auth.get_user(state["uid"], app=app).custom_claims == {"role": "admin"}
    assert auth.verify_id_token(sign_in(), check_revoked=True, app=app)["role"] == "admin"


@check("a disabled user's token is refused")
def _():
    token = sign_in()
    auth.update_user(state["uid"], disabled=True, app=app)
    try:
        auth.verify_id_token(token, check_revoked=True, app=app)
        raise AssertionError("disabled user's token accepted")
    except auth.UserDisabledError:
        pass
    finally:
        auth.update_user(state["uid"], disabled=False, app=app)


@check("revoke_refresh_tokens revokes earlier ID tokens")
def _():
    token = sign_in()
    time.sleep(1.1)
    auth.revoke_refresh_tokens(state["uid"], app=app)
    try:
        auth.verify_id_token(token, check_revoked=True, app=app)
        raise AssertionError("revoked token accepted")
    except auth.RevokedIdTokenError:
        pass
    auth.verify_id_token(sign_in(), check_revoked=True, app=app)


@check("create_custom_token, then sign in with it")
def _():
    token = auth.create_custom_token(state["uid"], {"tier": "gold"}, app=app)
    code, body = rest("signInWithCustomToken", {"token": token.decode() if isinstance(token, bytes) else token})
    assert code == 200, body
    assert auth.verify_id_token(body["idToken"], app=app)["tier"] == "gold"


@check("list_users and generate_password_reset_link")
def _():
    assert state["uid"] in [u.uid for u in auth.list_users(app=app).iterate_all()]
    assert "oobCode=" in auth.generate_password_reset_link(email, app=app)


@check("update_user and delete_user")
def _():
    assert auth.update_user(state["uid"], display_name="Renamed", app=app).display_name == "Renamed"
    auth.delete_user(state["uid"], app=app)
    try:
        auth.get_user(state["uid"], app=app)
        raise AssertionError("deleted user still found")
    except auth.UserNotFoundError:
        pass


failed = sum(not v.startswith("PASS") for v in results.values())
print(f"  {len(results) - failed}/{len(results)} passed")
sys.exit(1 if failed else 0)
