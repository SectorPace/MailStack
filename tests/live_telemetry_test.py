import urllib.request
import urllib.parse
import json
import http.cookiejar
import os
import sys

def run_tests():
    user = os.environ.get("TEST_ADMIN_USER", "admin")
    password = os.environ.get("TEST_ADMIN_PASS", "")
    if not password:
        print("Note: TEST_ADMIN_PASS not provided. Skipping live HTTP authentication test.")
        return
        
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cookie_jar))
    urllib.request.install_opener(opener)

    print("=== Step 1: Login via POST /api/auth/login ===")
    login_payload = json.dumps({"username": user, "password": password}).encode("utf-8")
    req = urllib.request.Request(
        "http://127.0.0.1:8787/api/auth/login",
        data=login_payload,
        headers={"Content-Type": "application/json"}
    )

    try:
        with opener.open(req) as resp:
            login_data = json.loads(resp.read().decode())
            print("Login Success:", login_data)
            csrf_token = login_data.get("csrf", "")
    except Exception as e:
        print("Live login test failed:", e)
        return

    headers = {
        "x-csrf-token": csrf_token,
        "Content-Type": "application/json"
    }

    print("\n=== Step 2: Testing GET /api/metrics/realtime ===")
    req = urllib.request.Request("http://127.0.0.1:8787/api/metrics/realtime", headers=headers)
    with opener.open(req) as resp:
        data = json.loads(resp.read().decode())
        print("Realtime metrics:", json.dumps(data, indent=2))

if __name__ == "__main__":
    run_tests()
