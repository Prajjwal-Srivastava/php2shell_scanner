#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell_scanner.py
================
Comprehensive, NON-DESTRUCTIVE exposure assessment for

    CVE-2026-109619  (PHP "php2shell" - RCE via stale global state)
    CWE-416 / CWE-824 / CWE-755      CVSS 4.0: 9.2 (Critical)
    Upstream advisory: GHSA-6wmf-4rv5-p3rp

What it does
------------
Runs every externally-observable check that the upstream advisory enumerates
for the documented producer/consumer paths, then renders a self-contained
styled HTML report with the raw evidence.

It performs ONLY read operations:
  * GET requests for fingerprinting / phpinfo / file probes
  * A single small multipart POST (32-byte file) to test whether the
    session-upload-progress consumer is reachable
It does NOT trigger OOM, does NOT attempt heap grooming, does NOT run code,
does NOT write to the target, and does NOT send large bodies.

Usage
-----
    python3 php2shell_scanner.py [https://target] [--timeout 20] [--full]
    python3 php2shell_scanner.py --json --save-raw --out ./out

The report is printed to the terminal only. Optional artefacts:
    --json      write evidence.json next to the script (or under --out)
    --save-raw  write raw HTTP captures under <out>/raw/
"""

import argparse
import datetime as dt
import html
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import textwrap
import time
import urllib.error
import urllib.parse
import urllib.request

TOOL = "php2shell_scanner"
TOOL_VERSION = "1.0"

# ---------------------------------------------------------------- constants --
FIXED = {(8, 2): (8, 2, 35), (8, 3): (8, 3, 36),
         (8, 4): (8, 4, 27), (8, 5): (8, 5, 12)}
FIX_RELEASE_DATE = dt.date(2026, 10, 21)
MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

PHPINFO_PATHS = ["/phpinfo.php", "/info.php", "/php_info.php", "/i.php",
                 "/pi.php", "/php.php", "/test.php", "/phpinfo"]
FILE_PROBES = ["/README.md", "/.env", "/composer.json", "/.git/config",
               "/CHANGELOG.txt", "/web.config", "/sites/default/settings.php"]
SESSION_PATHS = ["/", "/user/login", "/node", "/contact", "/search/node"]

UA = "Mozilla/5.0 (X11; Linux x86_64) php2shell_scanner/%s" % TOOL_VERSION

# ------------------------------------------------------------- http engine --
class Resp:
    __slots__ = ("status", "reason", "headers", "body", "url", "ms", "error")

    def __init__(self, status, reason, headers, body, url, ms, error=None):
        self.status = status
        self.reason = reason
        self.headers = headers          # list[(name, value)]
        self.body = body                # bytes
        self.url = url
        self.ms = ms
        self.error = error

    def h(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return ""

    def hall(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]

    def text(self, limit=None):
        try:
            t = self.body.decode("utf-8", "replace")
        except Exception:
            t = ""
        return t[:limit] if limit else t


def _ssl_ctx():
    c = ssl.create_default_context()
    c.check_hostname = False
    c.verify_mode = ssl.CERT_NONE
    return c


def _opener():
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=_ssl_ctx()))


def fetch(url, method="GET", data=None, headers=None, timeout=20):
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    t0 = time.time()
    try:
        with _opener().open(req, timeout=timeout) as r:
            body = r.read()
            return Resp(r.status, r.reason, list(r.headers.items()), body,
                        r.geturl(), int((time.time() - t0) * 1000))
    except urllib.error.HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        return Resp(e.code, str(e.reason), list(e.headers.items()), body,
                    url, int((time.time() - t0) * 1000))
    except Exception as e:                                    # noqa: BLE001
        return Resp(0, "ERROR", [], b"", url,
                    int((time.time() - t0) * 1000), str(e))


def multipart(fields, fname, fcontent, boundary, ctype="text/plain"):
    out = []
    for k, v in fields:
        out.append(("--%s\r\nContent-Disposition: form-data; name=\"%s\"\r\n\r\n%s\r\n"
                    % (boundary, k, v)).encode())
    out.append(("--%s\r\nContent-Disposition: form-data; name=\"file\"; "
                "filename=\"%s\"\r\nContent-Type: %s\r\n\r\n"
                % (boundary, fname, ctype)).encode())
    out.append(fcontent)
    out.append(("\r\n--%s--\r\n" % boundary).encode())
    return b"".join(out)


# ----------------------------------------------------------------- parsing --
def parse_phpinfo(page):
    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", page, re.S)
    d, order = {}, []
    for r in rows:
        cells = [html.unescape(re.sub(r"<[^>]+>", "", x)).strip()
                 for x in re.findall(r"<td[^>]*>(.*?)</td>", r, re.S)]
        if len(cells) >= 2 and cells[0]:
            if cells[0] not in d:
                d[cells[0]] = cells[1]
                order.append(cells[0])
    return d, order


def parse_ver(s):
    m = re.match(r"(\d+\.\d+\.\d+)", (s or "").strip())
    return tuple(int(x) for x in m.group(1).split(".")) if m else None


def parse_build(s):
    m = re.search(r"([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{4})", s or "")
    if not m or m.group(1) not in MONTHS:
        return None
    try:
        return dt.date(int(m.group(3)), MONTHS[m.group(1)], int(m.group(2)))
    except ValueError:
        return None


def vstr(v):
    return ".".join(map(str, v)) if v else "?"


def truthy(v):
    return str(v).strip().lower() in ("on", "1", "true", "yes", "enabled")


# ------------------------------------------------------------------ checks --
class Report:
    def __init__(self, target):
        self.target = target
        self.started = dt.datetime.now()
        self.checks = []
        self.raw = {}
        self.reqs = []
        self.phpinfo = {}
        self.phpinfo_order = []
        self.facts = {}

    def add(self, group, cid, name, status, detail, evidence=None,
            weight=0, host_cmd=None):
        self.checks.append({
            "group": group, "id": cid, "name": name, "status": status,
            "detail": detail, "evidence": evidence, "weight": weight,
            "host_cmd": host_cmd,
        })

    def by(self, cid):
        for c in self.checks:
            if c["id"] == cid:
                return c
        return None


# --------------------------------------------------------------- collection --
def run(target, outdir, timeout, save_raw=False):
    R = Report(target)
    rawdir = os.path.join(outdir, "raw") if save_raw else None
    if rawdir:
        os.makedirs(rawdir, exist_ok=True)
    base = target

    def save(name, r):
        if not rawdir:
            return
        with open(os.path.join(rawdir, name + ".body"), "wb") as f:
            f.write(r.body)
        with open(os.path.join(rawdir, name + ".headers"), "w",
                  encoding="utf-8") as f:
            f.write("HTTP %s %s\n" % (r.status, r.reason))
            for k, v in r.headers:
                f.write("%s: %s\n" % (k, v))

    # ---- 0. root -----------------------------------------------------------
    root = fetch(base + "/", timeout=timeout)
    R.raw["root"] = root
    save("00_root", root)
    tls_scheme = urllib.parse.urlparse(base).scheme

    # ---- 1. TLS ------------------------------------------------------------
    host = urllib.parse.urlparse(base).hostname or ""
    tls_detail, tls_ok = "not tested", False
    if tls_scheme == "https" and host:
        try:
            pem = ssl.get_server_certificate((host, 443), timeout=10)
            fd, tmp = tempfile.mkstemp(suffix=".pem")
            with os.fdopen(fd, "w") as f:
                f.write(pem)
            try:
                out = subprocess.run(
                    ["openssl", "x509", "-noout", "-subject", "-issuer", "-dates",
                     "-in", tmp], capture_output=True, text=True, timeout=10)
            finally:
                os.unlink(tmp)
            if out.returncode == 0 and out.stdout.strip():
                tls_detail = out.stdout.strip().replace("\n", " | ")
                tls_ok = True
        except Exception as e:                               # noqa: BLE001
            tls_detail = "openssl/ssl error: %s" % e
    R.add("Reachability", "tls", "TLS certificate", "OK" if tls_ok else "INFO",
          tls_detail if tls_ok else ("not applicable" if not tls_ok and
                                     tls_scheme != "https" else tls_detail))

    # ---- 2. reachability ---------------------------------------------------
    if root.status == 0:
        R.add("Reachability", "reachable", "Target reachable", "RISK",
              "connection failed: %s" % root.error, weight=0)
    else:
        R.add("Reachability", "reachable", "Target reachable", "OK",
              "HTTP %s %s in %d ms" % (root.status, root.reason, root.ms))

    srv = root.h("server")
    xpb = root.h("x-powered-by")
    R.add("Reachability", "server_header", "Server / X-Powered-By",
          "INFO", "Server=%r  X-Powered-By=%r" % (srv or "(blank)", xpb or "(none)"),
          evidence="Server: %s\nX-Powered-By: %s" % (srv or "(blank)", xpb or "(none)"))

    # ---- 3. tech fingerprint ----------------------------------------------
    body = root.text(400000)
    tech = []
    if "drupal-settings-json" in body or "/sites/default/" in body:
        tech.append("Drupal")
    if xpb.lower().startswith("php/") or "phpsessid" in body.lower():
        tech.append("PHP")
    if re.search(r'name="generator"[^>]*WordPress', body, re.I):
        tech.append("WordPress")
    R.add("Reachability", "tech", "CMS / runtime fingerprint", "INFO",
          ", ".join(tech) if tech else "not identified", evidence=None)
    R.facts["tech"] = tech

    # ---- 4. locate phpinfo -------------------------------------------------
    pinfo = None
    found_path = None
    for p in PHPINFO_PATHS:
        r = fetch(base + p, timeout=timeout)
        R.reqs.append({"tag": "probe " + p, "status": r.status,
                       "bytes": len(r.body), "ms": r.ms, "url": r.url})
        if r.status == 200 and re.search(r"<title>[^<]*phpinfo\(\)", r.text(5000), re.I):
            pinfo, found_path = r, p
            save("10_phpinfo", r)
            break
        time.sleep(0.15)

    if found_path:
        cc = pinfo.h("cache-control") or "(none)"
        R.add("Information Disclosure", "phpinfo", "phpinfo() exposed",
              "RISK", "publicly reachable at %s (no auth, no IP restriction)" % found_path,
              evidence="GET %s -> HTTP %s (%d bytes)\nCache-Control: %s\n"
                       "Last-Modified: %s" % (found_path, pinfo.status, len(pinfo.body),
                                              cc, pinfo.h("last-modified") or "(none)"))
        if cc == "(none)":
            R.add("Information Disclosure", "phpinfo_cache", "phpinfo() cacheability",
                  "INFO", "no Cache-Control on the phpinfo response - no explicit "
                  "no-store directive")
        elif "public" in cc.lower() or ("max-age" in cc.lower()
                                        and "no-store" not in cc.lower()):
            R.add("Information Disclosure", "phpinfo_cache", "phpinfo() cacheability",
                  "WARN", "Cache-Control: %s - config snapshot may be cached by "
                  "intermediaries" % cc)
    else:
        R.add("Information Disclosure", "phpinfo", "phpinfo() exposed",
              "OK", "no phpinfo page found in %d probe paths" % len(PHPINFO_PATHS))

    cfg = {}
    if pinfo:
        cfg, order = parse_phpinfo(pinfo.text())
        R.phpinfo, R.phpinfo_order = cfg, order
        m = re.search(r"<title>\s*PHP\s+([0-9.]+)", pinfo.text(5000), re.I)
        if m and "PHP Version" not in cfg:
            cfg["PHP Version"] = m.group(1)

    # ---- 5. version --------------------------------------------------------
    ver_raw = cfg.get("PHP Version", "")
    if not ver_raw and xpb.lower().startswith("php/"):
        ver_raw = xpb.split("/", 1)[1]
    ver = parse_ver(ver_raw)
    R.facts["php_version"] = ver_raw or None
    if ver:
        R.add("Version & Patch", "php_version", "PHP version identified", "INFO",
              "PHP %s (source: %s)" % (ver_raw, "phpinfo" if "PHP Version" in cfg else "X-Powered-By"),
              evidence="PHP Version = %s" % ver_raw)
    else:
        R.add("Version & Patch", "php_version", "PHP version identified",
              "WARN", "PHP version could not be determined externally")

    affected = False
    if ver:
        key = (ver[0], ver[1])
        if key in FIXED:
            fx = FIXED[key]
            affected = ver < fx
            R.add("Version & Patch", "version_gate", "Version vs fixed release",
                  "RISK" if affected else "OK",
                  "%s vs first fixed %s -> %s" % (
                      vstr(ver), vstr(fx),
                      "VULNERABLE RANGE" if affected else "patched"),
                  weight=35 if affected else 0)
        elif ver < (8, 2):
            affected = True
            R.add("Version & Patch", "version_gate", "Version vs fixed release",
                  "RISK", "PHP %s is an end-of-life branch with NO upstream fix "
                  "(advisory: 5.4-8.1 affected, no patch planned)" % vstr(ver),
                  weight=35)
        else:
            R.add("Version & Patch", "version_gate", "Version vs fixed release",
                  "WARN", "PHP %s is outside the published fixed-version matrix; "
                  "verify against NVD" % vstr(ver))

    build_raw = cfg.get("Build Date", "")
    bdate = parse_build(build_raw)
    if bdate:
        pre = bdate < FIX_RELEASE_DATE
        R.add("Version & Patch", "build_date", "Binary build provenance",
              "RISK" if pre else "WARN",
              "built %s by %s -> %s" % (
                  bdate.strftime("%Y-%m-%d"),
                  re.sub(r"\s+", " ", cfg.get("Build Provider", "?").split("<")[0]).strip(),
                  "PREDATES the %s fix release: binary cannot contain the patch"
                  % FIX_RELEASE_DATE if pre else
                  "built after the fix release; verify vendor backport"),
              evidence="Build Date = %s\nBuild Provider = %s\nBuild System = %s" % (
                  build_raw, cfg.get("Build Provider", "?"), cfg.get("Build System", "?")),
              weight=10 if pre else 0)
        R.facts["build_date"] = bdate.isoformat()
        R.facts["build_pre_fix"] = pre

    # ---- 6. SAPI -----------------------------------------------------------
    sapi = cfg.get("Server API", "")
    sl = sapi.lower()
    if sapi:
        if "fpm" in sl:
            sapi_status, sapi_txt = "RISK", "session-lifecycle RCE path validated against FPM"
        elif "apache" in sl:
            sapi_status, sapi_txt = "RISK", "mod_php - confirmed RCE path in the advisory"
        elif "litespeed" in sl or "lsapi" in sl:
            sapi_status, sapi_txt = "RISK", "LSAPI - conditional early-INI consumer candidate per advisory"
        else:
            sapi_status, sapi_txt = "INFO", "no published RCE chain for this SAPI"
        R.add("Producers & Consumers", "sapi", "Server API (SAPI)", sapi_status,
              "%s - %s" % (sapi, sapi_txt))
    else:
        R.add("Producers & Consumers", "sapi", "Server API (SAPI)", "WARN",
              "not disclosed (no phpinfo)")
    R.facts["sapi"] = sapi

    # ---- 7. session upload progress ---------------------------------------
    up_en = cfg.get("session.upload_progress.enabled", "")
    up_name = cfg.get("session.upload_progress.name", "")
    up_prefix = cfg.get("session.upload_progress.prefix", "")
    up_clean = cfg.get("session.upload_progress.cleanup", "")
    up_freq = cfg.get("session.upload_progress.freq", "")
    up_minf = cfg.get("session.upload_progress.min_freq", "")
    if up_en:
        R.add("Producers & Consumers", "up_enabled", "session.upload_progress enabled",
              "RISK" if truthy(up_en) else "OK",
              "%s - documented early consumer %s" % (
                  up_en, "REACHABLE" if truthy(up_en) else "disabled (mitigation)"),
              evidence="session.upload_progress.enabled = %s\n"
                       "session.upload_progress.name    = %s\n"
                       "session.upload_progress.prefix  = %s\n"
                       "session.upload_progress.cleanup = %s\n"
                       "session.upload_progress.freq    = %s\n"
                       "session.upload_progress.min_freq= %s"
                       % (up_en, up_name, up_prefix, up_clean, up_freq, up_minf),
              weight=20 if truthy(up_en) else 0,
              host_cmd="php -i | grep session.upload_progress")
    else:
        R.add("Producers & Consumers", "up_enabled", "session.upload_progress enabled",
              "WARN", "not disclosed")

    sh = cfg.get("session.save_handler", "")
    sp = cfg.get("session.save_path", "")
    if sh:
        R.add("Producers & Consumers", "sess_handler", "Session save handler",
              "INFO", "handler=%s path=%s" % (sh, sp),
              evidence="session.save_handler = %s\nsession.save_path = %s" % (sh, sp))

    strict = cfg.get("session.use_strict_mode", "")
    if strict:
        R.add("Producers & Consumers", "sess_strict", "session.use_strict_mode",
              "RISK" if not truthy(strict) else "OK",
              "%s - %s" % (strict, "attacker can fixate the session id (helps pin "
                           "producer+consumer to one session)" if not truthy(strict)
                           else "strict mode on"))

    # ---- 8. functional session liveness -----------------------------------
    sess_live, sess_ev = False, "not tested"
    ctl = fetch(base + "/", headers={"Cookie": "PHPSESSID=p2s_control_%d" % int(time.time())},
                timeout=timeout)
    ctl_cookie = [c for c in ctl.hall("Set-Cookie") if "phpsessid" in c.lower()]
    b = "----p2s%d" % int(time.time())
    body_mp = multipart([("PHP_SESSION_UPLOAD_PROGRESS", "p2s_probe")],
                        "p.txt", b"php2shell_scanner_probe_32b", b)
    probe = None
    for path in SESSION_PATHS:
        r = fetch(base + path, method="POST", data=body_mp,
                  headers={"Cookie": "PHPSESSID=p2s_%d" % int(time.time()),
                           "Content-Type": "multipart/form-data; boundary=%s" % b},
                  timeout=timeout)
        R.reqs.append({"tag": "session probe %s" % path, "status": r.status,
                       "bytes": len(r.body), "ms": r.ms, "url": r.url})
        if r.status == 0:
            continue
        probe = r
        save("20_session_probe", r)
        ck = [c for c in r.hall("Set-Cookie") if "phpsessid" in c.lower()]
        if ck or ctl_cookie:
            sess_live = True
            sess_ev = ("control: %s\nprobe: %s" %
                       (ctl_cookie[0] if ctl_cookie else "(none)",
                        ck[0] if ck else "(none)"))
            break
        time.sleep(0.15)
    if sess_live:
        R.add("Producers & Consumers", "session_live",
              "PHP session active on request path", "RISK",
              "server issues Set-Cookie: PHPSESSID -> session-upload-progress consumer "
              "is reachable on the same worker", evidence=sess_ev, weight=15)
    elif probe is not None:
        R.add("Producers & Consumers", "session_live",
              "PHP session active on request path", "WARN",
              "no PHPSESSID Set-Cookie observed on the probed paths; the upload-progress "
              "consumer may still be reachable on routes that call session_start()",
              evidence=sess_ev)
    else:
        R.add("Producers & Consumers", "session_live",
              "PHP session active on request path", "WARN", "probe failed")

    # ---- 9. INI diagnostics consumer --------------------------------------
    risky_ini = []
    def chk(name, key, bad=None, note=""):
        v = cfg.get(key)
        if v is None:
            return
        t = str(v).strip()
        if not t or t.lower() in ("no value", "none", ""):
            return
        risky_ini.append("%s = %s%s" % (key, t, ("  (" + note + ")") if note else ""))

    chk("filter", "filter.default", note="non-default produces a diagnostic")
    chk("adle", "auto_detect_line_endings", note="deterministic deprecation")
    chk("date", "date.timezone", note="invalid/optimistic value produces a diagnostic")
    chk("mb_in", "mbstring.http_input", note="explicit encoding produces a diagnostic")
    chk("mb_out", "mbstring.http_output", note="explicit encoding produces a diagnostic")
    chk("iconv_in", "iconv.input_encoding", note="explicit encoding produces a diagnostic")
    chk("iconv_out", "iconv.output_encoding", note="explicit encoding produces a diagnostic")
    chk("iconv_int", "iconv.internal_encoding", note="explicit encoding produces a diagnostic")
    chk("assert", "assert.active", note="PHP 8.3+ legacy assert.* setting")
    chk("zassert", "zend.assertions", note="non-default on 8.3+ is a legacy setting")
    chk("obdir", "open_basedir", note="rejected cache/log paths produce diagnostics")

    if risky_ini:
        R.add("Producers & Consumers", "ini_consumer",
              "Early INI diagnostics consumer", "WARN",
              "config values that can emit a pre-initialization diagnostic are present "
              "(applicability depends on whether they are applied per-request)", 
              evidence="\n".join(risky_ini),
              host_cmd="grep -R 'PHP_VALUE' /etc/nginx /etc/httpd /etc/php-fpm.d 2>/dev/null")
    else:
        R.add("Producers & Consumers", "ini_consumer",
              "Early INI diagnostics consumer", "OK",
              "no unusual INI values that would emit a deprecation before request init",
              evidence="checked: filter.default, auto_detect_line_endings, date.timezone, "
                       "mbstring.*, iconv.*, assert.*, zend.assertions, open_basedir")

    # advisory consumers that are version/config gated - report them when we
    # actually have a configuration snapshot to reason about
    for key, label, why in ([
        ("filter.default", "filter.default consumer",
         "PHP 8.x default is 'unsafe_raw'; a non-default value emits an early diagnostic"),
        ("mbstring.http_input", "mbstring encoding consumer",
         "removed in PHP 8.0 - cannot produce a diagnostic on 8.3"),
        ("iconv.input_encoding", "iconv encoding consumer",
         "removed in PHP 8.0 - cannot produce a diagnostic on 8.3"),
        ("assert.active", "assert.active consumer",
         "PHP 8.3 deprecates assert.*; only relevant if set per-request via PHP_VALUE"),
        ("fatal_error_backtraces", "fatal_error_backtraces consumer",
         "PHP 8.5+ only; confirmed mod_php RCE producer on 8.5"),
        ("report_memleaks", "report_memleaks consumer",
         "only a producer path on PHP 8.5 builds"),
    ] if cfg else []):
        if key in cfg:
            continue
        R.add("Producers & Consumers", "na:" + key.split(".")[0] + "_" + key.split(".")[-1],
              "Advisory consumer: %s" % label, "N/A",
              "not present/enabled in this phpinfo output - %s" % why)

    de = cfg.get("display_errors", "")
    le = cfg.get("log_errors", "")
    er = cfg.get("error_reporting", "")
    if de or le:
        R.add("Producers & Consumers", "err_cfg", "Error reporting configuration", "INFO",
              "display_errors=%s log_errors=%s error_reporting=%s (note: disabling "
              "display/log does NOT protect against CVE-2026-109619)" % (de, le, er),
              evidence="display_errors = %s\nlog_errors = %s\nerror_reporting = %s\n"
                       "error_log = %s" % (de, le, er, cfg.get("error_log", "?")))

    # ---- 10. producers: OOM / timeout -------------------------------------
    def mb(v):
        m = re.match(r"\s*(\d+)\s*([KMG]?)", str(v or ""), re.I)
        if not m:
            return None
        n = int(m.group(1)); u = m.group(2).upper()
        return n * {"": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3}[u]

    mem = mb(cfg.get("memory_limit"))
    post = mb(cfg.get("post_max_size"))
    upl = mb(cfg.get("upload_max_filesize"))
    if mem and post:
        headroom = mem < max(post, upl or 0)
        R.add("Producers & Consumers", "oom", "OOM producer reachable", 
              "RISK" if headroom else "WARN",
              "memory_limit=%s, post_max_size=%s, upload_max_filesize=%s -> %s" % (
                  cfg.get("memory_limit"), cfg.get("post_max_size"),
                  cfg.get("upload_max_filesize"),
                  "a request body can be larger than the memory limit, so OOM during "
                  "input processing is reachable (advisory's demonstrated producer)"
                  if headroom else
                  "body limits are below memory_limit; OOM requires application amplification"),
              evidence="memory_limit = %s\npost_max_size = %s\nupload_max_filesize = %s"
                       % (cfg.get("memory_limit"), cfg.get("post_max_size"),
                          cfg.get("upload_max_filesize")),
              weight=5 if headroom else 0,
              host_cmd="php -i | grep -E 'memory_limit|post_max_size|upload_max_filesize'")
    met = cfg.get("max_execution_time")
    if met:
        R.add("Producers & Consumers", "timeout", "Fatal timeout producer",
              "RISK" if str(met).strip() not in ("0", "") else "INFO",
              "max_execution_time=%ss - a request can be driven to 'Maximum execution "
              "time exceeded', which is a fatal interruption (producer)" % met)

    feb = cfg.get("fatal_error_backtraces")
    if feb is not None:
        R.add("Producers & Consumers", "feb", "fatal_error_backtraces (PHP 8.5 path)",
              "RISK" if truthy(feb) else "OK",
              "fatal_error_backtraces=%s - %s" % (
                  feb, "the confirmed PHP 8.5 mod_php RCE producer is enabled"
                  if truthy(feb) else "disabled"))
    rml = cfg.get("report_memleaks")
    if rml is not None and ver and ver[:2] >= (8, 5):
        R.add("Producers & Consumers", "memleaks", "report_memleaks (PHP 8.5 consumer)",
              "WARN" if truthy(rml) else "OK", "report_memleaks=%s" % rml)

    # ---- 11. hardening -----------------------------------------------------
    dfn = cfg.get("disable_functions", "")
    obd = cfg.get("open_basedir", "")
    if "disable_functions" in cfg:
        empty = not dfn or dfn.strip().lower() in ("no value", "")
        R.add("Hardening", "disable_functions", "disable_functions", 
              "RISK" if empty else "OK",
              "%s" % ("no functions disabled - no post-exploitation friction"
                      if empty else dfn), weight=0)
    if "open_basedir" in cfg:
        empty = not obd or obd.strip().lower() in ("no value", "")
        R.add("Hardening", "open_basedir", "open_basedir",
              "RISK" if empty else "OK",
              "%s" % ("unset - filesystem access not restricted" if empty else obd),
              weight=0)
    for k in ("allow_url_fopen", "allow_url_include", "expose_php"):
        if k in cfg:
            R.add("Hardening", k, k, "INFO", "%s = %s" % (k, cfg[k]))
    jit = cfg.get("opcache.jit", "")
    oe = cfg.get("opcache.enable", "")
    if oe or jit:
        R.add("Hardening", "opcache", "OPcache / JIT", "INFO",
              "opcache.enable=%s jit=%s (JIT affects heap layout; informational)" % (oe, jit))

    # ---- 11b. security posture --------------------------------------------
    sec = {"strict-transport-security": "HSTS",
           "x-frame-options": "X-Frame-Options",
           "content-security-policy": "CSP",
           "x-content-type-options": "X-Content-Type-Options",
           "referrer-policy": "Referrer-Policy",
           "permissions-policy": "Permissions-Policy"}
    missing = [n for h, n in sec.items() if not root.h(h)]
    present = [n for h, n in sec.items() if root.h(h)]
    R.add("Security Posture", "secheaders", "Security response headers",
          "WARN" if missing else "OK",
          "present: %s | missing: %s" % (", ".join(present) or "none",
                                         ", ".join(missing) or "none"),
          evidence="\n".join("%s: %s" % (k, root.h(k) or "(absent)") for k in sec))

    opt = fetch(base + "/", method="OPTIONS", timeout=timeout)
    allow = opt.h("allow") or opt.h("access-control-allow-methods") or "(none returned)"
    R.add("Security Posture", "options", "HTTP OPTIONS / allowed methods",
          "INFO", "HTTP %s, Allow: %s" % (opt.status, allow))

    tr = fetch(base + "/", method="TRACE", timeout=timeout)
    R.add("Security Posture", "trace", "TRACE method",
          "RISK" if tr.status == 200 else "OK",
          "HTTP %s - %s" % (tr.status, "TRACE echoed the request (Cross-Site Tracing)"
                           if tr.status == 200 else "not allowed"))

    for p in ("/robots.txt", "/sitemap.xml", "/update.php", "/user/register"):
        r = fetch(base + p, timeout=timeout)
        R.reqs.append({"tag": "posture " + p, "status": r.status,
                       "bytes": len(r.body), "ms": r.ms, "url": r.url})
        if r.status == 200:
            R.add("Security Posture", "sp:" + p.strip("/").replace("/", "_"),
                  "Endpoint %s reachable" % p, "INFO",
                  "HTTP 200 (%d bytes)" % len(r.body), evidence=(r.text(200) or "")[:200])
        time.sleep(0.12)

    fpm_found = False
    for p in ("/status", "/fpm-status", "/php-fpm-status", "/status?full"):
        r = fetch(base + p, timeout=timeout)
        R.reqs.append({"tag": "fpm " + p, "status": r.status,
                       "bytes": len(r.body), "ms": r.ms, "url": r.url})
        if r.status == 200 and re.search(r"pool:|process manager|accepted conn",
                                         r.text(4000), re.I):
            R.add("Information Disclosure", "fpm_status", "FPM status page exposed",
                  "RISK", "%s returns live pool statistics - worker reuse and "
                  "request counts become directly observable" % p,
                  evidence=r.text(320))
            fpm_found = True
            break
        time.sleep(0.1)
    if not fpm_found:
        R.add("Information Disclosure", "fpm_status", "FPM status page reachable", "OK",
              "no /status, /fpm-status or /php-fpm-status page reachable - worker reuse "
              "stays unobservable from outside")

    ck = list(dict.fromkeys(root.hall("Set-Cookie")
                            + (probe.hall("Set-Cookie") if probe else [])))
    if ck:
        joined = "; ".join(ck)
        flags = {"Secure": "secure" in joined.lower(),
                 "HttpOnly": "httponly" in joined.lower(),
                 "SameSite": "samesite" in joined.lower()}
        R.add("Security Posture", "cookie_flags", "Session cookie flags",
              "OK" if all(flags.values()) else "WARN",
              ", ".join("%s=%s" % (k, "set" if v else "MISSING") for k, v in flags.items()),
              evidence="\n".join(ck))

    # ---- 12. edge / WAF ----------------------------------------------------
    waf_blocked = False
    if probe is not None and probe.status in (403, 406, 429, 451, 501, 503):
        waf_blocked = True
    baseline = root.status
    R.add("Edge / Mitigations", "waf", "Edge / WAF behaviour on the exploit request",
          "OK" if waf_blocked else "RISK",
          "upload-progress POST returned HTTP %s -> %s" % (
              probe.status if probe else "n/a",
              "request appears to be blocked/challenged at the edge"
              if waf_blocked else
              "request passed through unchanged (no PHP_SESSION_UPLOAD_PROGRESS rule observed)"),
          evidence="baseline GET / -> HTTP %s\nupload-progress POST -> HTTP %s" % (
              baseline, probe.status if probe else "n/a"),
          weight=-25 if waf_blocked else 0)
    R.add("Edge / Mitigations", "workers", "Worker reuse / stickiness", "N/A",
          "not externally observable: exploitation requires producer+consumer on the "
          "same worker; multiple FPM workers lower per-request success but do not fix "
          "the flaw",
          host_cmd="grep -E '^pm|max_requests' /etc/php-fpm.d/*.conf")

    # ---- 13. corroborating exposures --------------------------------------
    for p in FILE_PROBES:
        r = fetch(base + p, timeout=timeout)
        R.reqs.append({"tag": "file " + p, "status": r.status,
                       "bytes": len(r.body), "ms": r.ms, "url": r.url})
        if r.status == 200 and len(r.body) > 0:
            R.add("Information Disclosure", "file:" + p, "Reachable file %s" % p,
                  "WARN" if p in ("/.env", "/.git/config", "/sites/default/settings.php")
                  else "INFO", "HTTP 200 (%d bytes)" % len(r.body),
                  evidence=(r.text(400) or "")[:400])
        time.sleep(0.12)

    acao = root.h("access-control-allow-origin")
    acac = root.h("access-control-allow-credentials")
    if acao:
        risky = acao.strip() == "*" and truthy(acac)
        R.add("Information Disclosure", "cors", "CORS policy",
              "WARN" if risky else "INFO",
              "Access-Control-Allow-Origin: %s%s" % (
                  acao, "; Allow-Credentials: %s" % acac if acac else ""))
    R.add("Information Disclosure", "hostname", "Internal identifier disclosure", "INFO",
          "Hostname=%s  System=%s" % (
              cfg.get("Hostname", "(not disclosed under FPM)"),
              (cfg.get("System", "") or "")[:90]))

    # ---- 14. verdict -------------------------------------------------------
    # Binary verdict from one dispositive fact: does the running build contain
    # the fix? Everything else only describes how easy exploitation would be.
    def is_(cid, status):
        chk = R.by(cid)
        return bool(chk and chk["status"] == status)

    sapi_ok = is_("sapi", "RISK")
    up_ok = is_("up_enabled", "RISK")
    live_ok = is_("session_live", "RISK")
    ini_ok = is_("ini_consumer", "WARN")
    oom_ok = is_("oom", "RISK")
    tmo_ok = is_("timeout", "RISK")
    edge_ok = is_("waf", "RISK")
    pre = R.facts.get("build_pre_fix")

    if ver is None:
        verdict, vclass = "UNKNOWN", "warn"
    elif affected:
        verdict, vclass = "VULNERABLE", "risk"
    else:
        verdict, vclass = "NOT VULNERABLE", "ok"

    fx = FIXED.get((ver[0], ver[1])) if ver else None
    gates = [
        ("affected build",
         "YES" if affected else ("NO" if ver else "UNKNOWN"),
         ("%s < %s" % (vstr(ver), vstr(fx))) if affected else
         (("%s >= %s" % (vstr(ver), vstr(fx))) if ver else "version not disclosed")),
        ("binary predates fix",
         "YES" if pre else ("NO" if pre is False else "UNKNOWN"),
         "build %s vs fix release %s" % (R.facts.get("build_date") or "?", FIX_RELEASE_DATE)),
        ("exploitable SAPI",
         ("YES" if sapi_ok else "UNKNOWN") if affected else "N/A",
         R.facts.get("sapi") or "not disclosed"),
        ("consumer reachable",
         ("YES" if (up_ok and live_ok) else ("PARTIAL" if (up_ok or ini_ok) else "NO"))
         if affected else "N/A",
         "session.upload_progress=%s, live session=%s, early-ini path=%s" % (
             cfg.get("session.upload_progress.enabled", "?"),
             "yes" if live_ok else "no", "yes" if ini_ok else "no")),
        ("producer reachable",
         ("YES" if (oom_ok or tmo_ok) else "NO") if affected else "N/A",
         "OOM via body size=%s, fatal timeout=%s" % (
             "yes" if oom_ok else "no", "yes" if tmo_ok else "no")),
        ("no edge filtering",
         ("YES" if edge_ok else "NO") if affected else "N/A",
         "upload-progress POST reached the app" if affected
         else "not applicable without an affected build"),
    ]

    if vclass == "risk":
        exploit = ("HIGH" if (sapi_ok and up_ok and live_ok and edge_ok)
                   else "LIMITED (some preconditions unproven)")
    elif vclass == "ok":
        exploit = "NONE (patched build)"
    else:
        exploit = "UNDETERMINED"

    dec = []
    src = found_path or "/phpinfo.php"
    if ver:
        dec.append(("E1", "running PHP version", ver_raw, "%s : PHP Version" % src))
    if affected and fx:
        dec.append(("E2", "vulnerable range", "%s < %s" % (vstr(ver), vstr(fx)),
                    "advisory GHSA-6wmf-4rv5-p3rp"))
    if bdate:
        dec.append(("E3", "binary build date", build_raw,
                    "%s : Build Date (fix released %s)" % (src, FIX_RELEASE_DATE)))
    if sapi:
        dec.append(("E4", "server API", sapi, "%s : Server API" % src))
    if affected and up_ok:
        dec.append(("E5", "session progress consumer",
                    "%s = %s" % (up_name or "PHP_SESSION_UPLOAD_PROGRESS", up_en),
                    "%s : session.upload_progress.enabled" % src))
    if affected and live_ok and sess_ev:
        pl = [l for l in sess_ev.splitlines() if l.startswith("probe")]
        dec.append(("E6", "server issues sessions",
                    (pl[0] if pl else sess_ev.splitlines()[0]).replace("probe: ", ""),
                    "Set-Cookie on POST /"))
    if affected and probe is not None:
        dec.append(("E7", "edge treatment of probe",
                    "HTTP %s, no challenge" % probe.status,
                    "POST / with PHP_SESSION_UPLOAD_PROGRESS"))

    R.facts.update({
        "verdict": verdict, "vclass": vclass, "affected": affected,
        "gates": gates, "decisive": dec, "exploitability": exploit,
        "php_fixed": vstr(fx) if fx else None,
    })
    R.facts["finished"] = dt.datetime.now().isoformat(timespec="seconds")
    return R


# ----------------------------------------------------------------- terminal --
W = 100


def _use_color():
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


COLOR = _use_color()

PILL = {"RISK": "1;97;41", "WARN": "1;30;43", "OK": "1;30;42",
        "INFO": "1;97;44", "N/A": "1;97;100"}


def c(code, s):
    return "\033[%sm%s\033[0m" % (code, s) if COLOR else s


def pill(status):
    lab = {"RISK": "RISK", "WARN": "WARN", "OK": "OK",
           "INFO": "INFO", "N/A": "N/A"}.get(status, status)
    return c(PILL.get(status, "1;97;100"), " %-4s " % lab)


def rule(ch="─"):
    print(c("90", ch * W))


def sec(title, right=""):
    left = " %s " % title
    r = (" %s " % right) if right else ""
    fill = W - len(left) - len(r) - 1
    print("")
    print(c("1;36", left) + c("90", "─" * max(3, fill)) + (c("90", r) if r else ""))


def field(key, val, keyw=26):
    txt = str(val) if val not in (None, "") else "(not disclosed)"
    lines = textwrap.wrap(txt, W - keyw - 4) or [""]
    print("  " + c("90", key.ljust(keyw)) + c("97", lines[0]))
    for ln in lines[1:]:
        print("  " + " " * keyw + c("97", ln))


def show_evidence(ev, cap, indent="        "):
    if not ev:
        return
    lines = str(ev).splitlines()
    for ln in lines[:cap]:
        print(indent + c("36", "│ ") + c("2", ln[:W - len(indent) - 4]))
    if len(lines) > cap:
        print(indent + c("36", "│ ") + c("90", "… +%d more line(s)  (--full to show)"
                                         % (len(lines) - cap)))


def banner(R):
    print("")
    print(c("90", "━" * W))
    print("  " + c("1;97", "php2shell_scanner") + c("90", " v%s" % TOOL_VERSION) +
          c("90", "  ·  ") + c("1;31", "CVE-2026-109619") +
          c("90", "  ·  PHP stale global state / UAF  ·  CVSS 9.2") )
    print("  " + c("90", "read-only: GETs + one 32-byte upload-progress probe  ·  "
                       "no OOM trigger  ·  no heap grooming  ·  no code execution"))
    print(c("90", "━" * W))
    field("target", R.target)
    field("started", R.started.strftime("%Y-%m-%d %H:%M:%S"))
    field("fingerprint", "%s  ·  %s  ·  build %s" % (
        R.facts.get("php_version") or "PHP unknown",
        R.facts.get("sapi") or "SAPI unknown",
        R.facts.get("build_date") or "unknown"))


def verdict_block(R):
    f = R.facts
    vclass = f.get("vclass", "warn")
    col = {"risk": "1;97;41", "ok": "1;30;42", "warn": "1;30;43"}.get(vclass, "1;30;43")
    inner = W - 6
    print("")
    print(c("90", "  ╭" + "─" * inner + "╮"))
    print(c("90", "  │") + c(col, " " + f.get("verdict", "?").ljust(inner - 2))
          + c("90", "│"))
    sub = "external exploitability: %s" % f.get("exploitability", "?")
    print(c("90", "  │") + c("0;37", " " + sub.ljust(inner - 2)) + c("90", "│"))
    print(c("90", "  ╰" + "─" * inner + "╯"))
    print("")
    print("  " + c("90", "decision gates"))
    for name, state, detail in f.get("gates", []):
        mark = {"YES": "✔", "NO": "✘", "PARTIAL": "~",
                "UNKNOWN": "?", "N/A": "–"}.get(state, "?")
        mc = {"YES": "1;32", "NO": "1;31", "PARTIAL": "1;33",
              "N/A": "90"}.get(state, "1;33")
        print("    " + c(mc, mark) + " " + c("97", name.ljust(22))
              + c("0;37", detail))
    print("")
    for ln in textwrap.wrap("Why: " + _producer_text(R), W - 4):
        print("  " + c("2", ln))


def decisive_evidence(R):
    dec = R.facts.get("decisive") or []
    if not dec:
        return
    sec("Evidence that decided it")
    for eid, label, val, source in dec:
        print("  " + c("1;36", eid.ljust(4)) + c("1;97", label))
        lines = textwrap.wrap(str(val), W - 10) or [""]
        for k, ln in enumerate(lines):
            tail = ""
            if k == len(lines) - 1:
                room = W - 10 - len(ln) - 4
                if len(source) <= room:
                    tail = c("90", "   ← " + source)
                else:
                    print("      " + c("0;37", ln))
                    print("      " + c("90", "← " + source))
                    continue
            print("      " + c("0;37", ln) + tail)


def evidence_table(R):
    cfg = R.phpinfo
    sec("Key evidence", "from phpinfo()" if cfg else "version-header only")
    if not cfg:
        field("PHP version", R.facts.get("php_version") or "unknown")
        field("X-Powered-By", R.raw["root"].h("x-powered-by") or "(none)")
        print("  " + c("33", "phpinfo() not reachable - config checks unavailable"))
        return
    pairs = [
        ("PHP Version", cfg.get("PHP Version")),
        ("Build Date", cfg.get("Build Date")),
        ("Build Provider", re.sub(r"\s+", " ", cfg.get("Build Provider", "").split("<")[0])),
        ("Server API", cfg.get("Server API")),
        ("PHP API / Zend build", "%s / %s" % (cfg.get("PHP API", "?"),
                                             cfg.get("Zend Extension Build", "?"))),
        ("Thread Safety", cfg.get("Thread Safety")),
        ("Loaded Configuration File", cfg.get("Loaded Configuration File")),
        ("session.upload_progress.enabled", cfg.get("session.upload_progress.enabled")),
        ("session.upload_progress.name", cfg.get("session.upload_progress.name")),
        ("session.upload_progress.cleanup", cfg.get("session.upload_progress.cleanup")),
        ("session.upload_progress.freq", "%s (min_freq %s)" % (
            cfg.get("session.upload_progress.freq", "?"),
            cfg.get("session.upload_progress.min_freq", "?"))),
        ("session.save_handler", cfg.get("session.save_handler")),
        ("session.save_path", cfg.get("session.save_path")),
        ("session.use_strict_mode", cfg.get("session.use_strict_mode")),
        ("memory_limit", cfg.get("memory_limit")),
        ("post_max_size", cfg.get("post_max_size")),
        ("upload_max_filesize", cfg.get("upload_max_filesize")),
        ("max_execution_time", cfg.get("max_execution_time")),
        ("disable_functions", cfg.get("disable_functions")),
        ("open_basedir", cfg.get("open_basedir")),
        ("expose_php", cfg.get("expose_php")),
    ]
    for k, v in pairs:
        if v is not None:
            field(k, v, keyw=32)


def matrix(R, full=False, compact=False):
    groups = []
    for chk in R.checks:
        if chk["group"] not in groups:
            groups.append(chk["group"])
    for g in groups:
        items = [x for x in R.checks if x["group"] == g]
        risk = sum(1 for x in items if x["status"] == "RISK")
        warn = sum(1 for x in items if x["status"] == "WARN")
        right = "%d checks" % len(items)
        if risk:
            right += " · %d risk" % risk
        elif warn:
            right += " · %d warn" % warn
        sec(g, right)
        for it in items:
            print("  " + pill(it["status"]) + " " + c("1;97", it["name"]))
            for ln in textwrap.wrap(it["detail"], W - 10):
                print("        " + c("0;37", ln))
            if compact:
                continue
            if it["status"] == "INFO" and not full:
                continue
            cap = 999 if full else 5
            show_evidence(it.get("evidence"), cap)
            if it.get("host_cmd") and full:
                print("        " + c("90", "verify: ") + c("2", it["host_cmd"][:W - 18]))


def remediation(R):
    sec("Remediation")
    rows = [
        ("FIX", "upgrade to PHP 8.3.36 / 8.4.27 / 8.2.35 / 8.5.12 or later "
                "(fixes released 2026-10-21)"),
        ("WORKAROUND", "session.upload_progress.enabled=0, then restart every FPM worker"),
        ("EXPOSURE", "delete /phpinfo.php; block PHP_SESSION_UPLOAD_PROGRESS POSTs at the edge"),
        ("VERIFY", "rpm -q --changelog php | grep -i 109619  ·  php-fpm -tt"),
    ]
    for k, v in rows:
        lines = textwrap.wrap(v, W - 18)
        print("  " + c("1;33", k.ljust(12)) + c("97", lines[0]))
        for ln in lines[1:]:
            print("  " + " " * 12 + c("97", ln))


def footer(R):
    st = {}
    for chk in R.checks:
        st[chk["status"]] = st.get(chk["status"], 0) + 1
    print("")
    rule("━")
    order = ["RISK", "WARN", "OK", "INFO", "N/A"]
    parts = ["%s %d" % (c(PILL[s], " %s " % s), st[s]) for s in order if s in st]
    print("  " + "   ".join(parts) + c("90", "   ·   %d checks total" % len(R.checks)))
    print("  " + c("90", "verdict: ")
          + c("1;97", R.facts.get("verdict", "").replace(" - ", " — ")) +
          c("90", "   ·   exploitability %s" % R.facts.get("exploitability", "?")) +
          c("90", "   ·   %.1fs" % (R.started and (
              dt.datetime.now() - R.started).total_seconds())))
    print("  " + c("90", "reference GHSA-6wmf-4rv5-p3rp / CVE-2026-109619 / CWE-416"))
    print("")


def _producer_text(R):
    if R.by("build_date") and R.by("build_date")["status"] == "RISK":
        return ("binary built %s, before the %s fix release - the state-reset "
                "patch cannot be present" % (R.facts.get("build_date"), FIX_RELEASE_DATE))
    if R.by("oom") and R.by("oom")["status"] == "RISK":
        return "OOM during input processing is reachable (memory_limit < body limits)"
    return "not fully confirmed from outside"


def _consumer_text(R):
    if R.by("up_enabled") and R.by("up_enabled")["status"] == "RISK":
        s = "session upload progress enabled (default PHP_SESSION_UPLOAD_PROGRESS)"
        if R.by("session_live") and R.by("session_live")["status"] == "RISK":
            s += "; the app starts a PHP session on the request path"
        return s
    return "not confirmed; depends on early INI diagnostics applied per-request"


def main():
    global W
    ap = argparse.ArgumentParser(
        description="CVE-2026-109619 non-destructive exposure assessment (terminal report)")
    ap.add_argument("target", nargs="?", default="https://caodisha.nic.in")
    ap.add_argument("--timeout", type=int, default=20)
    ap.add_argument("--full", action="store_true", help="show every evidence line")
    ap.add_argument("--compact", action="store_true", help="hide evidence blocks")
    ap.add_argument("--json", action="store_true", help="also write evidence.json")
    ap.add_argument("--save-raw", action="store_true",
                    help="save raw HTTP captures under --out/raw/")
    ap.add_argument("--out", default=None, help="output dir for --json / --save-raw")
    a = ap.parse_args()

    try:
        W = max(76, min(shutil.get_terminal_size((100, 40)).columns, 104))
    except Exception:
        W = 100

    t = a.target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    t = t.rstrip("/")
    outdir = os.path.abspath(a.out or os.path.dirname(os.path.abspath(__file__)))

    R = run(t, outdir, a.timeout, save_raw=a.save_raw)

    banner(R)
    verdict_block(R)
    decisive_evidence(R)
    evidence_table(R)
    matrix(R, full=a.full, compact=a.compact)
    remediation(R)
    footer(R)

    if a.json:
        os.makedirs(outdir, exist_ok=True)
        path = os.path.join(outdir, "evidence.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"tool": TOOL, "version": TOOL_VERSION, "target": t,
                       "started": R.started.isoformat(timespec="seconds"),
                       "facts": R.facts, "checks": R.checks,
                       "requests": R.reqs, "phpinfo": R.phpinfo},
                      f, indent=2, default=str)
        print("  " + c("90", "evidence json: ") + c("36", path) + "\n")

    return {"risk": 2, "warn": 1, "ok": 0}.get(R.facts.get("vclass"), 1)


if __name__ == "__main__":
    sys.exit(main())
