# API Security Audit Tool

A Node.js CLI tool that scans a live API for common security misconfigurations and produces a structured, severity-ranked vulnerability report — directly in your terminal, and as JSON for downstream tooling.

Point it at a base URL and a list of endpoints, and it runs a set of independent security checks concurrently, then prints findings grouped by severity (Critical → Low), with a description and remediation for each.

```
$ node main.js https://vampi-target.example.com /books/v1:GET /users/v1/register:POST
```

---

## Why this exists

Most backend engineers don't think about how the systems they build actually get broken, and most security tooling treats the backend as a black box. This project sits at that intersection: it's a small, hand-built version of what tools like Burp Suite or Nuclei do, built from scratch to understand *why* each check exists — what the attacker is trying to do, what a vulnerable response actually looks like on the wire, and how to distinguish vulnerable from safe programmatically.

Every check here was written and verified against a live vulnerable target (VAmPI), not just built against a spec.

---

## Checks implemented

| Check | What it looks for |
|---|---|
| **HTTPS Check** | Whether the target is served over plain HTTP |
| **Security Headers** | Missing/misconfigured CSP, X-Frame-Options, HSTS, X-Content-Type-Options |
| **Verbose Error Responses** | Stack traces, internal paths, or framework details leaked in error bodies |
| **CORS Misconfiguration** | Wildcard origins, reflected-origin + credentials (session hijack risk), false-selectivity allowlists |
| **HTTP Methods Exposure** | Unsafe methods advertised or actually executable (TRACE, PUT, DELETE, POST) |
| **Missing Authentication Detection** | Endpoints that should require auth but don't |
| **Rate Limit Check** | Endpoints with no, late, or overly permissive rate limiting |
| **XSS Check** | Unsanitized query-parameter input reflected back in responses |

Each finding includes a severity rating, the affected endpoint, a hand-written description of the risk, and a remediation.

**Known limitation:** the XSS check currently only tests query-parameter reflection — it does not yet cover path-parameter injection or JSON request-body reflection. This is a known, deliberately scoped gap, not an oversight.

---

## Architecture — the three-stage pipeline

The tool is built as three deliberately sequenced stages:

1. **Ingestion (Input)** — currently a base URL + manually specified `path:method` pairs (every scan also automatically includes a base-URL `GET /` sanity check, tagged separately from user-specified endpoints). An OpenAPI/Swagger parser is planned but intentionally deferred until the check-correctness backlog is fully clear.
2. **Execution (Engine)** — the 8 checks above. Fully independent of input source; each check just receives a URL + endpoint and returns findings. All checks run concurrently via `Promise.allSettled`, so one check crashing doesn't block the others.
3. **Presentation & Action (Output)** — `src/reportGenerator.js` normalizes raw results, segregates them by severity, and renders a colorized, aligned, wrapped terminal report (via `chalk`), plus a structured JSON report file (`writeJsonReport`) with a finalized summary schema (total results, confirmed findings, severity breakdown, untestable/tool-error counts). CI/CD exit-code behavior is the remaining piece of this stage.

Building input parsing before the reporting layer was solid would have meant testing checks against noisy, unstructured output — so Stage 3 was prioritized before Stage 1.

---

## Getting started

**Requirements:** Node.js (with ES modules support — this project uses `"type": "module"`)

```bash
git clone https://github.com/captianzo/API-Security-Audit-Tool.git
cd API-Security-Audit-Tool
npm install
```

**Usage:**

```bash
node main.js <base-url> [path:method ...]
```

**Example:**

```bash
node main.js http://localhost:5000 /books/v1:GET /users/v1/register:POST
```

This runs all 8 checks concurrently against the given endpoints, prints a severity-grouped report to the terminal, and writes a matching JSON report to disk.

---

## Sample output

Findings are grouped and color-coded by severity:

- 🔴 **Critical** — e.g. reflected CORS origin + credentials enabled, no rate limiting at all
- 🟠 **High** — e.g. wildcard CORS, confirmed-executable TRACE method
- 🟡 **Medium** — e.g. TRACE advertised in `Allow` header
- ⚪ **Low** — e.g. rate limiting that kicks in late

Two additional non-severity banners:
- ❓ **Untestable** — a check couldn't reach a conclusion (e.g. an endpoint returned 400 before the auth check could run)
- ⚠️ **Tool Errors** — a check itself crashed (network failure, bad hostname, etc.)

The terminal report and the JSON report (`meta.summary`) both surface: total results, confirmed findings, a per-severity breakdown, and separate untestable/tool-error counts.

---

## Tech stack

- Node.js (ES modules)
- [`chalk`](https://www.npmjs.com/package/chalk) — terminal color/formatting for report output
- No framework, no database — this is a CLI tool that makes raw HTTP requests and reasons over the raw responses

---

## Background / testing

Checks have been iteratively verified against [VAmPI](https://github.com/erev0s/VAmPI), a deliberately vulnerable Flask API, using live `curl` traffic to confirm each finding (and each non-finding) is correct rather than assumed.