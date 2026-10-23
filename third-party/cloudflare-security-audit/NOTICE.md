# Cloudflare Security Audit Skill (upstream)

The files in this directory are vendored from the official Cloudflare Security Audit
Skill for local validation of agent-produced `findings.json` artifacts.

- Upstream: https://github.com/cloudflare/security-audit-skill
- License: MIT (see LICENSE in upstream repository)
- Pinned commit: see `UPSTREAM_COMMIT`

Security Scan does not embed the full multi-agent audit workflow. Install the
upstream skill for Cursor agent orchestration:

```bash
npx skills add https://github.com/cloudflare/security-audit-skill --skill security-audit
```

These validators are invoked by `security-scan audit validate` only. They do not
execute target code or perform hunting.
