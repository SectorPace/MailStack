#!/usr/bin/env bash
set -Eeuo pipefail

red(){ printf '\033[31m%s\033[0m\n' "$*"; }
green(){ printf '\033[32m%s\033[0m\n' "$*"; }
yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

green "=== [1/5] 检查前端与后端源码完整性 ==="
TSX_COUNT=$(find src -name '*.tsx' | wc -l)
echo "已检测到 $TSX_COUNT 个 TypeScript/React 组件源码文件"
if [ "$TSX_COUNT" -lt 40 ]; then
  red "源码不完整：src 目录下缺少必要的 .tsx 组件 (数量: $TSX_COUNT < 40)"
  exit 1
fi

green "=== [2/5] 验证依赖并执行源码构建 (npm run build:all) ==="
if [ ! -d "node_modules" ]; then
  (npm ci --no-audit --no-fund 2>/dev/null || npm install --no-audit --no-fund) || { red "npm 依赖安装失败"; exit 1; }
fi
npm run build:all || { red "全栈构建失败 (npm run build:all)"; exit 1; }

green "=== [3/5] 校验构建产物完整性 ==="
for f in "dist/index.html" "dist/server.cjs" "dist/webmail.cjs" "dist/build-manifest.json"; do
  if [ ! -s "$f" ]; then
    red "缺少核心构建产物: $f"
    exit 1
  fi
done

green "=== [4/5] 校验 build-manifest.json 哈希摘要一致性 ==="
python3 - <<'PY'
import json, hashlib, os, sys

mf_path = "dist/build-manifest.json"
if not os.path.exists(mf_path):
    print("Missing manifest:", mf_path)
    sys.exit(1)

with open(mf_path, "r", encoding="utf-8") as f:
    data = json.load(f)

artifacts = data.get("artifacts", {})
if not artifacts:
    print("Empty artifacts in manifest!")
    sys.exit(1)

for rel_path, expected_hash in artifacts.items():
    full_path = os.path.join("dist", rel_path)
    if not os.path.exists(full_path):
        print(f"File missing from dist: {rel_path}")
        sys.exit(1)
    with open(full_path, "rb") as bf:
        calc_hash = hashlib.sha256(bf.read()).hexdigest()
    if calc_hash != expected_hash:
        print(f"Hash mismatch for {rel_path}: expected {expected_hash}, got {calc_hash}")
        sys.exit(1)

print(f"Manifest verification successful: {len(artifacts)} files verified.")
PY

green "=== [5/6] 执行全套自动化单元测试 ==="
NODE_CMD=""
if command -v node >/dev/null 2>&1; then
  NODE_CMD="node"
elif command -v node.exe >/dev/null 2>&1; then
  NODE_CMD="node.exe"
fi

if [ -n "$NODE_CMD" ]; then
  $NODE_CMD --test tests/*.test.mjs || { red "自动化测试未全部通过"; exit 1; }
else
  yellow "环境未安装 node，跳过测试执行"
fi

green "=== [6/6] 生产服务最小化 Smoke 启动验证 ==="
python3 - <<'PY'
import subprocess, time, urllib.request, json, sys, os

node_cmd = "node"
for c in ["node", "node.exe"]:
    try:
        r = subprocess.run([c, "-v"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r.returncode == 0:
            node_cmd = c
            break
    except Exception:
        pass

env = os.environ.copy()
env["PORT"] = "19787"
env["HOST"] = "127.0.0.1"
env["WEBMAIL_PORT"] = "19788"
env["WEBMAIL_HOST"] = "127.0.0.1"

is_windows_node = node_cmd.endswith(".exe")
if is_windows_node:
    cmd_admin = ["cmd.exe", "/c", "set PORT=19787&& set HOST=127.0.0.1&& node.exe dist/server.cjs"]
    cmd_webmail = ["cmd.exe", "/c", "set WEBMAIL_PORT=19788&& set WEBMAIL_HOST=127.0.0.1&& node.exe dist/webmail.cjs"]
else:
    cmd_admin = [node_cmd, "dist/server.cjs"]
    cmd_webmail = [node_cmd, "dist/webmail.cjs"]

p_admin = subprocess.Popen(cmd_admin, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
p_webmail = subprocess.Popen(cmd_webmail, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

def fetch_json(url):
    if is_windows_node:
        try:
            r = subprocess.run(["curl.exe", "-s", url], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip():
                return json.loads(r.stdout.strip())
        except Exception:
            pass
    with urllib.request.urlopen(url, timeout=5) as r:
        if r.status == 200:
            return json.loads(r.read())
    return None

def post_json_status(url, data):
    payload = json.dumps(data)
    if is_windows_node:
        try:
            r = subprocess.run(["curl.exe", "-s", "-o", "nul", "-w", "%{http_code}", "-X", "POST", "-H", "Content-Type: application/json", "-d", payload, url], capture_output=True, text=True, timeout=5)
            if r.returncode == 0 and r.stdout.strip().isdigit():
                return int(r.stdout.strip())
        except Exception:
            pass
        return 0
    req = urllib.request.Request(url, data=payload.encode("utf-8"), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code

def fetch_text(url):
    if is_windows_node:
        try:
            r = subprocess.run(["curl.exe", "-s", url], capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                return r.stdout
        except Exception:
            pass
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.read().decode("utf-8", errors="ignore")

try:
    time.sleep(2.5)
    
    # 1. Admin API Health Check
    admin_data = fetch_json("http://127.0.0.1:19787/api/health")
    if not admin_data or admin_data.get("status") != "ok" or admin_data.get("version") != "0.8.0-beta.9":
        print("Admin API health check failed:", admin_data)
        sys.exit(1)
    print("  -> Admin API Health: 200 OK (version: " + str(admin_data.get("version")) + ", builtAt: " + str(admin_data.get("builtAt")) + ")")

    # 2. Webmail Health Check
    webmail_data = fetch_json("http://127.0.0.1:19788/api/webmail/health")
    if not webmail_data or webmail_data.get("status") != "ok" or webmail_data.get("service") != "mailstack-webmail":
        print("Webmail health check failed:", webmail_data)
        sys.exit(1)
    print("  -> Webmail Health: 200 OK (service: " + str(webmail_data.get("service")) + ", version: " + str(webmail_data.get("version")) + ")")

    # 3. Invalid Login 401 Check
    auth_status = post_json_status("http://127.0.0.1:19787/api/auth/login", {"username": "badadmin", "password": "badpassword123"})
    if auth_status == 401:
        print("  -> Auth Security: 401 Unauthorized (invalid login handling verified)")
    else:
        print("Unexpected auth error status:", auth_status)
        sys.exit(1)

    # 4. Static Asset 200 OK Check
    body = fetch_text("http://127.0.0.1:19787/") or ""
    if "<!DOCTYPE html>" in body or "<!doctype html>" in body or "root" in body:
        print("  -> Frontend UI: 200 OK (index.html entry verified)")
    else:
        print("Static frontend entry verification failed")
        sys.exit(1)

except Exception as e:
    print("Smoke Test Failed with exception:", e)
    sys.exit(1)
finally:
    for p in (p_admin, p_webmail):
        try:
            p.terminate()
        except Exception:
            pass
    if is_windows_node:
        # 仅按 PID 定向清理本测试拉起的 node 进程树；
        # 严禁 taskkill /IM node.exe —— 那会杀掉整机所有 node 进程。
        for p in (p_admin, p_webmail):
            try:
                subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(p.pid)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            except Exception:
                pass
    else:
        for p in (p_admin, p_webmail):
            try:
                p.wait()
            except Exception:
                pass

print("Smoke test passed: Admin API and Webmail runtime verified.")
PY

green "========================================="
green "  MailStack 源码构建与全链路发布校验通过! "
green "========================================="
