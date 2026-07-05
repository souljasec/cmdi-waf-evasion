# cmdi-waf-evasion

A small skill I put together for **WAF evasion** in authorized bug bounty / pentest work — mostly OS command injection, with some path traversal / LFI.

It's less a payload list and more a way of thinking through filters: incomplete blacklists, alternative binaries when `cat` is blocked, response-body evasion, and a simple check to tell a real bypass from SPA-fallback noise. Nothing groundbreaking — just notes and techniques I found useful, organized so they're reusable.

## What's inside

- **Think like the WAF, not like the shell** — the core mental model
- Operator / binary blacklist bypasses (quote-concat, `$IFS`, backslash tricks)
- Low-noise recon binaries and alternatives when common ones (`cat`, `nc`, `curl`) are blocked
- Response-body evasion when a WAF strips things like `/etc/passwd` from output
- Path-traversal / LFI bypasses against CloudFront, AWS WAF, Cloudflare, Akamai, OWASP CRS
- A "validate against a known-existing target" method to separate real bypasses from soft-404 / SPA-fallback noise

## Layout

```
cmdi-waf-evasion/
├── SKILL.md     # the skill itself
├── LICENSE
└── README.md
```

## ⚠️ For authorized testing only

Intended for authorized bug bounty, pentest, CTF, and lab engagements. Confirm the target is in scope (HackerOne / Bugcrowd policy, written ROE, owned lab) before running anything. If scope is unclear, stop.

## Contributing

Feedback and PRs welcome if it's helpful to anyone.

## License

MIT © [@souljasec](https://github.com/souljasec)
