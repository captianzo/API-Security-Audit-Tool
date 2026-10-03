# API Security Audit Tool

A Node.js CLI that scans a live API for common security misconfigurations and gives you a severity-ranked report, both in the terminal and as a JSON file.

Point it at a base URL and a few endpoints and it runs a set of independent checks at the same time, then groups what it found by severity (Critical down to Low), with a description and a fix for each. There's also an optional BOLA/IDOR check that needs two user tokens.

```
$ node main.js https://vampi-target.example.com /books/v1:GET /users/v1/register:POST
```

## Why this exists

Most backend engineers never think much about how the systems they build get broken, and most security tooling treats the backend as a black box. This project sits between the two. It's a small, hand-built take on what Burp Suite or Nuclei do, written from scratch so I'd understand why each check exists: what the attacker is after, what a vulnerable response looks like on the wire, and how to tell vulnerable from safe in code.

Every check was written and tested against a live vulnerable target (VAmPI), not just built from a spec.

## What it checks

| Check | What it looks for |
|---|---|
| HTTPS | The target being served over plain HTTP |
| Security headers | Missing or weak CSP, X-Frame-Options, HSTS, X-Content-Type-Options |
| Verbose errors | Stack traces, internal paths or framework details leaking in error bodies |
| CORS | Wildcard origins, reflected origin plus credentials, allowlists that only look selective |
| HTTP methods | Unsafe methods that are advertised or actually work (TRACE, PUT, DELETE, POST) |
| Missing authentication | Endpoints that should require auth and don't |
| Rate limiting | No rate limit, a late one, or one that's too generous |
| XSS | Input reflected back unsanitized, tested through query parameters, request headers (User-Agent, Referer, X-Forwarded-For and so on) and cookies |
| BOLA / IDOR | A valid user reading another user's object. Optional, see [below](#bola--idor-check-optional) |

Each finding comes with a severity, the affected endpoint, a description of the risk and a remediation.

One gap to know about: the XSS check doesn't cover path parameters or JSON request bodies yet. Both come down to the same thing. The `path:method` input can't say which parts of a path are parameters, or what a body looks like. That has to wait for the OpenAPI/Swagger parser, which I've put off until the checks themselves are solid.

## How it's put together

There are three stages, with a gate in front.

**Preflight.** Before anything runs, the tool checks that the target actually responds (3 second timeout, and it tells a real network error apart from a slow cold start). It isn't a security check. It just stops the tool from running everything against a dead host and reporting nonsense. A failed preflight exits with code `2`.

**Input.** A base URL plus `path:method` pairs. Every scan also adds a `GET /` on the base URL as a sanity check, tagged separately from the endpoints you specified. The BOLA check takes its input differently, from a config file and two tokens, and never touches the `path:method` list. That way templated paths don't leak into the other checks.

**Checks.** Each check takes the URL and its inputs and returns findings. They all run at once through `Promise.allSettled`, so one crashing doesn't stop the rest.

**Output.** `src/reportGenerator.js` sorts the results by severity and prints a colored terminal report, then writes the same data as JSON into `reports/`. The exit code is set from the findings (see [Exit codes](#exit-codes)).

I built the reporting layer before the input layer on purpose. Writing an input parser first would have meant testing the checks against messy, unstructured output.

## Getting started

You need Node.js. The project uses ES modules (`"type": "module"`).

```bash
git clone https://github.com/captianzo/API-Security-Audit-Tool.git
cd API-Security-Audit-Tool
npm install
```

Usage:

```bash
node main.js <base-url> [path:method ...] [--bola-config=<file>]
```

The flag has to be written with an equals sign (`--bola-config=./file.json`). The space-separated form (`--bola-config ./file.json`) isn't supported, and the tool exits with code `2` and a message instead of guessing.

For example:

```bash
node main.js http://localhost:5000 /books/v1:GET /users/v1/register:POST
```

That runs the standard checks against those two endpoints, prints the report and saves a JSON copy. If you give no `path:method` pairs the tool says so and scans only the base URL with `GET`.

## BOLA / IDOR check (optional)

BOLA (broken object level authorization, also called IDOR) is when an API checks that you're logged in but not whether the object you asked for is yours. Change an ID in the URL and you're reading someone else's data. It sits at number one on the OWASP API Top 10.

It's the one check that can't run from a URL alone. The tool has no way of knowing who owns what, so you give it two real users and an object one of them owns. Burp's Autorize and ZAP's access control testing work the same way. If you don't pass `--bola-config`, the check is skipped and shows up as one Untestable entry saying so.

**Tokens.** Copy `.env.example` to `.env` and fill in two tokens:

```
TOKEN_A=<token of the user who owns the objects in your config>
TOKEN_B=<token of a different valid user>
```

A is the owner and B plays the attacker. They're loaded from `.env` at startup, so they never appear on the command line or in the config file. A variable already set in your shell wins over `.env`, so if results look odd, check for a stale one. Tokens need to stay valid for the whole scan, so if yours expire quickly, generate them right before you run.

**Config.** A JSON file listing the objects to test. Name it whatever you like and pass it with `--bola-config`. There's a template in `configs/bola-config.json.example`:

```json
[
  {
    "test_id": "bola_test_books_001",
    "endpoint_template": "/books/v1/{book_title}",
    "http_method": "GET",
    "parameters": { "book_title": "bookTitle19" }
  }
]
```

`endpoint_template`, `http_method` and `parameters` are required. `parameters` holds a value for each `{placeholder}`, and it should be an object that TOKEN_A's user owns. `test_id` is optional and only labels the entry in the report. For POST, PUT, PATCH and DELETE you also have to add `"confirm_state_changing": true`, because the owner's request runs first and could really modify or delete the object. Without that flag the entry is skipped.

Then run it:

```bash
node main.js http://localhost:5000 --bola-config=./configs/bola-config.json
```

**How it decides.** For each entry the tool sends the same request three times: as the owner (A), as the other user (B), and with no token (C). If B gets back what A got and C is turned away, that's a finding. The no-token request is there to rule out objects that were never protected at all. Anything the tool can't be sure about, like an expired token, a 404, or a 200 that looks different, goes to Untestable instead of being guessed at. The full verdict table, the matching rules and how confidence maps to severity are in [docs/bola.md](docs/bola.md).

A few things worth knowing:

- Every object in one config has to belong to the TOKEN_A user. To test objects owned by different users, run it once per owner.
- The tool takes your word that TOKEN_A owns the objects. It can't check.
- Tokens are sent as `Authorization: Bearer <token>`. Other schemes aren't supported yet.
- I've only tested this against VAmPI. The finding path, the public-object case, the 401 and 404 handling, the input validation, the DELETE opt-in and the exit codes all behave as expected there. The 403 "properly gated" result, a 404 on the attacker request and the non-JSON comparison are written but haven't met a target that triggers them.

## Exit codes

The tool is meant to work as a pipeline gate, so a non-zero exit fails the build.

| Code | Meaning |
|---|---|
| `0` | The scan ran and found no Critical or High issues |
| `1` | The scan ran and found at least one Critical or High issue |
| `2` | The tool couldn't run |

`2` is kept separate from `1` on purpose. It means the scan never produced a result you can trust, while `1` means it finished and found something worth failing on. You get a `2` when:

- no URL was given
- preflight couldn't confirm the target exists
- `--bola-config` points at a file that can't be read
- the config isn't valid JSON, or isn't an object or an array
- `--bola-config` is written with a space instead of an equals sign
- `--bola-config` is set but `TOKEN_A` or `TOKEN_B` is missing or empty

In CI, supply the two tokens as secrets in the environment instead of committing a `.env` file.

## Reading the output

Findings are grouped and colored by severity:

- 🔴 Critical: reflected CORS origin with credentials, no rate limiting at all, a confirmed BOLA finding
- 🟠 High: wildcard CORS, a TRACE method that actually works
- 🟡 Medium: TRACE advertised in the `Allow` header
- ⚪ Low: rate limiting that only kicks in late

Two more sections sit outside the severity scale:

- ❓ Untestable: a check couldn't reach a conclusion, for example an endpoint answered 400 before the auth check could run, or a BOLA baseline request failed
- ⚠️ Tool errors: a check itself broke (network failure, bad hostname and so on)

The terminal report and the JSON file both include totals, confirmed findings, the per-severity counts, and the untestable and tool-error counts. The JSON also keeps extra detail the terminal leaves out, such as the status codes and comparison evidence behind a BOLA result.

## Project layout

```
API-SECURITY-AUDIT-TOOL/
│
├── configs/
│   ├── .gitkeep
│   └── bola-config.json.example
│
├── docs/
│   └── bola.md
│
├── src/
│   ├── bola.js
│   ├── corsMisconfig.js
│   ├── errorVerbose.js
│   ├── httpMethodsExposure.js
│   ├── httpsCheck.js
│   ├── jsonUtils.js
│   ├── missingAuthDetection.js
│   ├── missingHeaders.js
│   ├── preflightCheck.js
│   ├── rateLimitCheck.js
│   ├── reportGenerator.js
│   ├── requestHelper.js
│   └── xssCheck.js
│
├── .env.example
├── .gitignore
├── main.js
├── package-lock.json
├── package.json
└── README.md
```

## Tech stack

- Node.js with ES modules
- [`chalk`](https://www.npmjs.com/package/chalk) for terminal colors
- [`dotenv`](https://www.npmjs.com/package/dotenv) for loading the tokens from `.env`

No framework and no database. It makes raw HTTP requests and reasons about the raw responses.

## Testing

Each check has been verified against [VAmPI](https://github.com/erev0s/VAmPI), a deliberately vulnerable Flask API, using live `curl` traffic to confirm every finding and every non-finding instead of assuming them. One VAmPI quirk matters for BOLA testing: its default tokens last only about 60 seconds, so generate them right before each run.
