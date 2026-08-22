#!/usr/bin/env python3
"""
Cerberus — End-to-end simulation with evidence (re-verification F1-F9 post-review).

Verifies against the REAL release binary: block/redact/warn, JSON preserved,
hot-reload, allowlist, break-glass, shadow, no-raw in CLI, clean no-warn and
zero leakage.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
BINARY = REPO / "target" / "release" / "cerberus"
MOCK = REPO / "tools" / "mock-server.py"
EVIDENCE_DIR = REPO / "evidence" / "sim"

PASS = 0
FAIL = 0
FAILURES = []
OUT = []


def free_port():
    for _ in range(40):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        try:
            p = socket.socket()
            p.settimeout(0.2)
            p.connect(("127.0.0.1", port))
            p.close()
        except OSError:
            return port
    raise RuntimeError("no free port")


def kill_listener(port):
    try:
        procs = subprocess.run(
            ["lsof", "-iTCP:%d" % port, "-sTCP:LISTEN", "-t"], capture_output=True, text=True
        ).stdout.split()
        for p in procs:
            subprocess.run(["kill", "-9", p.strip()], capture_output=True)
    except FileNotFoundError:
        pass


def request(method, url, body=None, headers=None, timeout=8):
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)
    except Exception as e:
        return None, str(e), {}


def wait_health(base):
    for _ in range(40):
        st, body, _ = request("GET", f"{base}/health")
        if st == 200 and '"ok"' in body:
            return True
        time.sleep(0.4)
    return False


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
        tag = "PASS"
    else:
        FAIL += 1
        FAILURES.append(name)
        tag = "FAIL"
    OUT.append(f"[{tag}] {name}")
    if detail:
        OUT.append(f"      {detail}")


def heading(t):
    OUT.append("")
    OUT.append("=" * 78)
    OUT.append(f"  {t}")
    OUT.append("=" * 78)


def chat(content):
    return json.dumps({"messages": [{"role": "user", "content": content}]})


RAW_BLOCK = "sk-abc123def456ghi789jkl012mno345"
RAW_REDACT = "Bearer abcdefghijklmnopqrstuvwxyzA123456"
RAW_WARN = "juan.perez@example.com"
CLEAN = "Hello, explain the universe in one sentence."


class Driver:
    def __init__(self, mode):
        self.mode = mode
        self.home = Path(tempfile.mkdtemp(prefix="cerberus-sim-"))
        self.mock_port = free_port()
        self.proxy_port = free_port()
        self.base = f"http://127.0.0.1:{self.proxy_port}"

        mock_env = dict(os.environ, CERBERUS_MOCK_LOG=str(self.home / "mock.log"), LOG_REQUESTS="0")
        self.mock = subprocess.Popen(
            [sys.executable, str(MOCK), str(self.mock_port)],
            env=mock_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(40):
            st, _, _ = request("GET", f"http://127.0.0.1:{self.mock_port}/__cerberus__/ready")
            if st == 200:
                break
            time.sleep(0.2)

        self.env = dict(os.environ, HOME=str(self.home),
                        CERBERUS_UPSTREAM_URL=f"http://127.0.0.1:{self.mock_port}",
                        CERBERUS_HMAC_SECRET="evidence-local-secret")
        subprocess.run([str(BINARY), "init"], env=self.env, capture_output=True, text=True)
        if mode == "shadow":
            cfg = self.home / ".cerberus" / "config.yaml"
            cfg.write_text("listen: 127.0.0.1:8787\nmode: shadow\nfail_policy: closed\n")

        self.dlog = open(self.home / "daemon.log", "w")
        self.daemon = subprocess.Popen(
            [str(BINARY), "start", "--port", str(self.proxy_port)], env=self.env,
            stdout=self.dlog, stderr=self.dlog)
        ok = wait_health(self.base)
        check(f"daemon starts in {mode} mode and /health ok", ok)
        if ok:
            _, h, _ = request("GET", f"{self.base}/health")
            OUT.append(f"      health={h}")

    def mock_last(self):
        _, raw, _ = request("GET", f"http://127.0.0.1:{self.mock_port}/__cerberus__/last")
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def teardown(self):
        kill_listener(self.proxy_port)
        try:
            self.daemon.kill()
            self.mock.kill()
            self.daemon.wait(timeout=5)
            self.mock.wait(timeout=5)
        except Exception:
            pass
        self.dlog.close()


def scenarios_enforce(d):
    heading("ENFORCE / block critical + feedback header")
    st, body, hdrs = request("POST", f"{d.base}/openai/v1/chat/completions",
                             chat(f"OPENAI_API_KEY={RAW_BLOCK}"))
    check("critical secret -> 403", st == 403, f"status={st} body={body[:100]}")
    check("secret.openai flag", "secret.openai" in body, body[:120])
    check("feedback header present",
          any(k.lower() == "x-cerberus-feedback" for k in hdrs), str(list(hdrs))[:140])

    heading("ENFORCE / redact preserves JSON (P0-2)")
    payload = {"messages": [{"role": "user", "content": f"Authorization: {RAW_REDACT} fin"}],
               "model": "gpt-4", "temperature": 0.0, "n": 1}
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions", payload)
    check("redact → 200", st == 200, f"status={st}")
    last = d.mock_last()
    raw_body = last.get("body", "")
    try:
        obj = json.loads(raw_body)
        ok_json = True
    except Exception:
        obj = None
        ok_json = False
    check("upstream receives valid JSON", ok_json, raw_body[:160])
    if ok_json:
        content = obj["messages"][0]["content"]
        check("secret -> [REDACTED ...]", "[REDACTED" in content, content[:160])
        check("model/temperature intact", obj.get("model") == "gpt-4", json.dumps(obj)[:140])
        check("raw token absent upstream", RAW_REDACT not in raw_body)

    heading("ENFORCE / redact with keyword in ANOTHER field (P0 rev2)")
    gkey = "AIza" + "A" * 35
    cross_payload = {"context": "google api_key", "message": f"I am a message with {gkey} embedded"}
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions", cross_payload)
    last = d.mock_last()
    echoed = json.dumps(last)
    check("cross-field: the secret does NOT reach upstream raw", gkey not in echoed, echoed[:200])
    check("cross-field: [REDACTED present", "[REDACTED" in echoed, echoed[:200])

    heading("ENFORCE / warn PII passes intact")
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions", chat(f"Contact me: {RAW_WARN}"))
    last = d.mock_last()
    echoed = json.dumps(last)
    check("warn email -> 200 and reaches upstream", st == 200 and RAW_WARN in echoed,
          f"status={st} {echoed[:140]}")

    heading("ENFORCE / clean with no warn event (P1-12)")
    _, evs, _ = request("GET", f"{d.base}/api/events")
    before = len(json.loads(evs))
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions", chat(CLEAN))
    _, evs2, _ = request("GET", f"{d.base}/api/events")
    after_events = json.loads(evs2)
    check("clean payload forward 200", st == 200, f"status={st}")
    check("clean does not add events (nor warn)", len(after_events) == before,
          f"events before={before} after={len(after_events)}")

    heading("ENFORCE / allowlist on the real path (P0-5)")
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions",
                          chat(f"OPENAI_API_KEY={RAW_BLOCK}"))
    check("before: blocks", st == 403)
    request("POST", f"{d.base}/api/allowlist", {"value": RAW_BLOCK})
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions",
                          chat(f"OPENAI_API_KEY={RAW_BLOCK}"))
    check("after allowlist: passes", st == 200, f"status={st}")

    heading("ENFORCE / hot-reload PUT /api/config (P0-5)")
    _, cfg, _ = request("GET", f"{d.base}/api/config")
    config = json.loads(cfg)
    config["mode"] = "shadow"
    st, body, _ = request("PUT", f"{d.base}/api/config", config)
    check("PUT config responds ok", st == 200, body[:80])
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions",
                          chat(f"OPENAI_API_KEY={RAW_BLOCK}"))
    check("after reload (shadow) lets through", st == 200, f"status={st}")

    heading("ENFORCE / break-glass header (P1-7)")
    st, body, _ = request("PUT", f"{d.base}/api/config", json.loads(cfg))
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions",
                          chat(f"OPENAI_API_KEY={RAW_BLOCK}"),
                          headers={"X-Cerberus-Bypass": "emergency-test"})
    check("with bypass header: does NOT block", st == 200, f"status={st}")

    heading("ENFORCE / live body limit (413) — rev2 P1 #5")
    _, cfg, _ = request("GET", f"{d.base}/api/config")
    cfg_obj = json.loads(cfg)
    cfg_obj["max_body_bytes"] = 200
    request("PUT", f"{d.base}/api/config", cfg_obj)
    big = {"messages": [{"role": "user", "content": "x" * 10000}]}
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions", big)
    check("body>200 -> 413 (limited during streaming)", st == 413, f"status={st} {body[:80]}")
    # restore
    cfg_obj["max_body_bytes"] = None
    request("PUT", f"{d.base}/api/config", cfg_obj)

    heading("ENFORCE / zero leakage + HMAC + CLI")
    leaks = []
    for f in d.home.rglob("*"):
        if f.is_file() and f.suffix in (".db", ".log"):
            if RAW_REDACT.encode() in f.read_bytes() or RAW_BLOCK.encode() in f.read_bytes():
                leaks.append(str(f))
    dlog_txt = (d.home / "daemon.log").read_text(errors="replace")
    check("no raw on disk or daemon log", not leaks and RAW_REDACT not in dlog_txt and RAW_BLOCK not in dlog_txt,
          f"leaks={leaks}" if leaks else "")
    _, evs, _ = request("GET", f"{d.base}/api/events")
    events = json.loads(evs)
    hashed = [e.get("hashed_values", []) for e in events if e.get("flags")]
    check("events use HMAC (hmac:)", bool(hashed) and all(
        (isinstance(h, list) and h and str(h[0]).startswith("hmac:")) or
        (isinstance(h, str) and h.startswith("hmac:")) for h in hashed),
        json.dumps(hashed[:2], default=str)[:200])
    cli = subprocess.run([str(BINARY), "test", f"mi openai api key es {RAW_BLOCK}"],
                         env=dict(os.environ, HOME=str(d.home)), capture_output=True, text=True).stdout
    check("CLI detects findings", "Hallazgos" in cli, cli[:160])
    check("CLI does NOT print the raw secret", RAW_BLOCK not in cli, cli[:160])
    doc = subprocess.run([str(BINARY), "doctor"], env=dict(os.environ, HOME=str(d.home)),
                         capture_output=True, text=True).stdout
    check("doctor reports rules", "Reglas cargadas:" in doc, doc[:120])


def scenarios_shadow(d):
    heading("SHADOW / blocking does not apply, but audits")
    st, body, _ = request("POST", f"{d.base}/openai/v1/chat/completions",
                          chat(f"OPENAI_API_KEY={RAW_BLOCK}"))
    check("shadow: 200 (does not block)", st == 200, f"status={st}")
    last = d.mock_last()
    check("shadow: raw secret reaches upstream", RAW_BLOCK in last.get("body", ""),
          json.dumps(last)[:160])
    _, evs, _ = request("GET", f"{d.base}/api/events")
    events = json.loads(evs)
    blocks = [e for e in events if e.get("action_taken") == "block"]
    check("shadow: block event audited", len(blocks) >= 1,
          json.dumps(blocks[-1], default=str)[:200] if blocks else "")


def main():
    if not BINARY.exists():
        print("ERROR: compila primero: cargo build --release --workspace", file=sys.stderr)
        return 1

    d = Driver("enforce")
    scenarios_enforce(d)
    d.teardown()

    s = Driver("shadow")
    scenarios_shadow(s)
    s.teardown()

    OUT.append("")
    OUT.append("=" * 78)
    OUT.append(f"  RESULT: {PASS} PASS / {FAIL} FAIL")
    OUT.append("=" * 78)
    if FAILURES:
        OUT.append("FAILED: " + "; ".join(FAILURES))
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = EVIDENCE_DIR / f"sim-run-{time.strftime('%Y%m%d-%H%M%S')}.log"
    out_path.write_text("\n".join(OUT))
    print("\n".join(OUT))
    print(f"\nTranscript: {out_path}")
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())

