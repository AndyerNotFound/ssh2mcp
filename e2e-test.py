#!/usr/bin/env python3
"""End-to-end test against the real remote host, through the MCP endpoint.

Covers: shell run, detached job + byte-offset log polling, job kill,
push with resume from a truncated remote partial, pull with sha256 verify,
and the read-only both-sides comparison.
"""
import json, os, random, string, time, urllib.request, urllib.error

BASE = os.environ.get("S2M_BASE", "http://127.0.0.1:6222")
TOKEN = open(os.path.expanduser("~/.ssh2mcp-token")).read().strip()
TMP = os.path.expanduser("~/.ssh2mcp/tmp")
os.makedirs(TMP, exist_ok=True)
results = []


def rpc(method, params):
    hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
           "Authorization": "Bearer " + TOKEN}
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    r = urllib.request.Request(BASE + "/mcp", data=body, headers=hdr, method="POST")
    with urllib.request.urlopen(r, timeout=120) as resp:
        raw = resp.read().decode()
        if "text/event-stream" in resp.headers.get("Content-Type", ""):
            for line in raw.splitlines():
                if line.startswith("data: "):
                    return json.loads(line[6:])
        return json.loads(raw)


def call(tool, args):
    j = rpc("tools/call", {"name": tool, "arguments": args})
    iserr = j.get("result", {}).get("isError", False)
    txt = (j.get("result", {}).get("content") or [{}])[0].get("text", "{}")
    return iserr, json.loads(txt)


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + ("  " + str(detail)[:110] if detail else ""))


tag = "".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(6))
remote = "/tmp/s2m-e2e-" + tag + ".bin"
local = os.path.join(TMP, "src-" + tag + ".bin")
pulled = os.path.join(TMP, "pulled-" + tag + ".bin")
payload = os.urandom(1024 * 1024)
open(local, "wb").write(payload)

try:
    e, r = call("s_shell", {"command": "uname -sr && nproc"})
    check("s_shell run", not e and r.get("exit") == 0 and "Linux" in r.get("stdout", ""), r.get("stdout", "").replace("\n", " "))

    e, r = call("s_shell", {"op": "bg", "command": "echo START; sleep 3; echo END"})
    job = r.get("job")
    check("s_shell bg returns a job id", not e and job, job)
    seen, state, since, deadline = "", "", 0, time.time() + 25
    while time.time() < deadline:
        e, r = call("s_shell", {"op": "log", "job": job, "since": since})
        seen += r.get("chunk", "")
        since = r.get("next_since", since)
        state = r.get("state", "")
        if state.startswith("done"):
            break
        time.sleep(1)
    check("bg job finishes and log resumes by offset", "END" in seen and state == "done:0", state + " bytes=" + str(len(seen)))

    e, r = call("s_shell", {"op": "bg", "command": "sleep 60"})
    job2 = r.get("job")
    e, r = call("s_shell", {"op": "kill", "job": job2})
    time.sleep(1.5)
    e, r = call("s_shell", {"op": "log", "job": job2})
    check("kill stops a running job", not e and r.get("state") != "running", r.get("state"))

    e, r = call("s_xfer", {"op": "push", "local": local, "remote": remote})
    check("push verifies sha256", not e and r.get("sha256") == __import__("hashlib").sha256(payload).hexdigest(), str(r.get("bytes")) + "B resumed_from=" + str(r.get("resumed_from")))

    e, r = call("s_shell", {"command": "head -c 400000 " + remote + " > " + remote + ".part && rm -f " + remote + " && stat -c %s " + remote + ".part"})
    e, r = call("s_xfer", {"op": "push", "local": local, "remote": remote})
    check("push resumes from the truncated partial", not e and r.get("resumed_from") == 400000, "resumed_from=" + str(r.get("resumed_from")))

    e, r = call("s_xfer", {"op": "pull", "local": pulled, "remote": remote})
    ok = not e and open(pulled, "rb").read() == payload
    check("pull roundtrip is byte-identical", ok, str(r.get("bytes")) + "B sha=" + str(r.get("sha256"))[:16])

    e, r = call("s_file", {"op": "compare", "local_path": pulled, "remote_path": remote})
    check("s_file compare reports same", not e and r.get("verdict") == "same", r.get("verdict"))

    loc2 = os.path.join(TMP, "txt-" + tag + ".txt")
    rep = "/tmp/s2m-e2e-" + tag + ".txt"
    open(loc2, "wb").write(b"line1\nlocal-ok\nline3\n")
    e, r = call("s_xfer", {"op": "push", "local": loc2, "remote": rep})
    open(loc2, "wb").write(b"line1\nREMOTE-x\nline3\n")
    e, r = call("s_file", {"op": "compare", "local_path": loc2, "remote_path": rep})
    fd = r.get("first_diff") or {}
    check("s_file compare finds the differing line", not e and r.get("verdict") == "content-differs" and fd.get("line") == 2 and fd.get("local") == "REMOTE-x", str(r.get("verdict")) + " " + str(fd))
finally:
    call("s_shell", {"command": "rm -f " + remote + " " + remote + ".part " + rep})
    for f in (local, pulled, loc2):
        try:
            os.remove(f)
        except OSError:
            pass

bad = [x for x in results if not x[1]]
print("\n%d/%d checks passed" % (len(results) - len(bad), len(results)))
raise SystemExit(1 if bad else 0)
