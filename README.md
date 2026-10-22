# php2shell_scanner

Non-destructive exposure assessment for **CVE-2026-109619** — the PHP "php2shell"
stale-global-state / use-after-free that leads to unauthenticated remote code
execution (CVSS 9.2, CWE-416 / CWE-824 / CWE-755, advisory `GHSA-6wmf-4rv5-p3rp`).

It fingerprints a PHP deployment, checks whether the running build can possibly
contain the fix, maps the advisory's documented *producer* and *consumer* paths
against the live configuration, and prints a self-contained terminal report with
the raw values that decided the verdict.

No exploitation. No OOM trigger. No heap grooming. No payloads.

```
╭──────────────────────────────────────────────────────────────────────────────╮
│ VULNERABLE                                                                  │
│ external exploitability: HIGH                                               │
╰──────────────────────────────────────────────────────────────────────────────╯

  decision gates
    ✔ affected build        8.3.33 < 8.3.36
    ✔ binary predates fix   build 2026-07-28 vs fix release 2026-10-21
    ✔ exploitable SAPI      FPM/FastCGI
    ✔ consumer reachable    session.upload_progress=On, live session=yes
    ✔ producer reachable    OOM via body size=no, fatal timeout=yes
    ✔ no edge filtering     upload-progress POST reached the app
```

---

## Why this exists

The advisory's proof of concept needs a memory-corrupting *producer* (OOM, fatal
error, timeout) and a *consumer* that runs early in request startup
(`session.upload_progress`, early INI diagnostics) on the **same worker**. You
cannot verify that pairing from the outside — but you can verify everything that
gates it, without touching the target's memory.

This tool answers one question: **is the deployed build capable of the bug, and
are the documented preconditions live?** It does not try to pop a shell, and it
will not tell you a site is "100% exploitable".

## Safety model

Every request the tool makes:

| Request | Purpose | Size |
| --- | --- | --- |
| `GET /` | baseline, headers, TLS | — |
| `GET /phpinfo.php` (+ 7 alternates) | configuration evidence | — |
| `POST /` × up to 5 paths | is the upload-progress consumer reachable | 32-byte file |
| `GET` posture paths (`robots.txt`, `/status`, `.user.ini`, …) | exposure surface | — |
| `OPTIONS`, `TRACE` | method policy | — |

Total: a few dozen requests, rate-limited with small sleeps, no body larger than
a few hundred bytes. It never sends a request designed to exhaust memory, it
never writes to the target, and it never executes code.

## Requirements

- Python 3.8+ (developed on 3.14)
- Standard library only — no `pip install`
- `openssl` binary (optional, for certificate details)
- A PHP target you are authorized to test

## Usage

```bash
python3 php2shell_scanner.py https://example.com
python3 php2shell_scanner.py example.com              # https:// assumed
python3 php2shell_scanner.py https://example.com --full
python3 php2shell_scanner.py https://example.com --json --out ./out
```

Report is printed to the terminal. Files are written only when asked for.

| Flag | Effect |
| --- | --- |
| `--full` | show every evidence line and the host-side verify command |
| `--compact` | hide evidence blocks, matrix only |
| `--json` | also write `evidence.json` (checks, requests, 600+ phpinfo directives) |
| `--save-raw` | also write raw HTTP captures under `<out>/raw/` |
| `--out DIR` | directory for `--json` / `--save-raw` |
| `--timeout N` | per-request timeout, default 20s |

Colour is automatic: on for a TTY, off when piped. `FORCE_COLOR=1` forces it,
`NO_COLOR=1` disables it.

### Exit codes

| Code | Verdict |
| --- | --- |
| `0` | `NOT VULNERABLE` — running build is at or above the fixed release |
| `1` | `UNKNOWN` — PHP version not disclosed |
| `2` | `VULNERABLE` — build is in the affected range |

## How the verdict is decided

One binary decision, no scoring:

> **VULNERABLE** if the running build cannot contain the fix, i.e. the version is
> below the first patched release for its branch **and** the compile date
> precedes the fix release. **NOT VULNERABLE** if the version is at or above it.
> **UNKNOWN** if the version cannot be determined.

Fixed releases, published 2026-10-21: `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`.
Older branches (5.4–8.1) are end-of-life with no upstream patch and are reported
as affected.

Everything else — SAPI, session configuration, size limits, edge filtering — is
reported as a **gate** and as **exploitability**, never folded into a number.
There is no weighted score to argue about.

### Honest caveat

A vendor backport can patch a flaw without bumping the version string. The tool
prints the command that settles it on the host:

```bash
rpm -q --changelog php | grep -i 109619
```

Treat `VULNERABLE` as "the observed build predates the fix and should be treated
as unpatched until the package changelog proves otherwise".

## What it collects

**Decisive evidence**

```
E1  running PHP version        8.3.33                  /phpinfo.php : PHP Version
E2  vulnerable range           8.3.33 < 8.3.36         advisory GHSA-6wmf-4rv5-p3rp
E3  binary build date          Jul 28 2026 17:56:10    /phpinfo.php : Build Date
E4  server API                 FPM/FastCGI             /phpinfo.php : Server API
E5  session progress consumer  PHP_SESSION_UPLOAD_PROGRESS = On
E6  server issues sessions     PHPSESSID=...           Set-Cookie on POST /
E7  edge treatment of probe    HTTP 200, no challenge  POST / with the progress field
```

**Supporting configuration** (from `phpinfo()`): version, build date/provider/
system, PHP API + Zend build + thread safety, loaded ini file, `Server API`,
`session.upload_progress.*`, session handler/path/strict mode, `memory_limit`,
`post_max_size`, `upload_max_filesize`, `max_execution_time`,
`disable_functions`, `open_basedir`, `expose_php`, OPcache/JIT.

**Up to 35 checks** (target-dependent) across: reachability and TLS, version and patch provenance,
producer/consumer conditions, hardening, security posture (headers, cookie
flags, `TRACE`, `OPTIONS`, FPM status page), edge/WAF behaviour, and
corroborating exposures.

Each check is `RISK`, `WARN`, `OK`, `INFO` or `N/A`, with the raw value and
where it came from.

## What it cannot prove

The following are **not observable from the outside** and the report says so
instead of guessing:

- how many FPM workers exist, and whether the producer and consumer land on the
  same one
- whether any application route actually reaches a fatal error or OOM
- heap layout, and therefore whether a given request would corrupt state
- whether the deployment's `session.save_path` is writable in the way the
  advisory's session path needs

These change *exploitability*, not the vulnerability verdict. Confirming them
requires host access or active exploitation — out of scope here.

## Remediation

1. **Patch.** Upgrade to `8.3.36` / `8.4.27` / `8.2.35` / `8.5.12` or later and
   restart the FPM pool.
2. **Contain.** `session.upload_progress.enabled=0`, then restart every worker.
   Note this only removes one documented consumer.
3. **Reduce the surface.** Remove `/phpinfo.php`, block
   `PHP_SESSION_UPLOAD_PROGRESS` POSTs at the edge, and lower
   `post_max_size` / `upload_max_filesize` to the application minimum.
4. **Verify on the host:**

```bash
rpm -q php && rpm -q --changelog php | grep -i 109619
php -i | grep -E 'session.upload_progress|fatal_error_backtraces'
grep -R 'PHP_VALUE' /etc/nginx /etc/httpd /etc/php-fpm.d 2>/dev/null
tail -n 200 /var/log/php-fpm/www-error.log
```

## Notes on false positives

- If `phpinfo()` is not reachable, configuration checks degrade to version
  headers and the report marks the unknowns as `N/A` rather than `OK`.
- A version outside the published fixed-version matrix is reported as `WARN`,
  not `VULNERABLE`.
- A patched version with an older build date is reported as `NOT VULNERABLE`
  with the build date surfaced for manual review.

## References

- Advisory: `GHSA-6wmf-4rv5-p3rp`
- CVE: `CVE-2026-109619`
- Weaknesses: CWE-416 (use after free), CWE-824 (uninitialized pointer),
  CWE-755 (improper handling of exceptional conditions)
- PHP security releases: 2026-10-21

## Authorized use only

This tool is for systems you own or have **written permission** to assess. It is
non-destructive by design, but unauthorized scanning may still be illegal in
your jurisdiction. Running it does not create authorization, and a `VULNERABLE`
verdict is not permission to exploit anything. If you find an affected host that
is not yours, report it to the operator or the relevant CERT — do not attempt to
prove RCE on production infrastructure.

The author accepts no liability for misuse or for damage caused by third-party
modifications.

## License

MIT. Add a `LICENSE` file before publishing if you want it to be explicit.
