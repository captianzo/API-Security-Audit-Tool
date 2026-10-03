# BOLA / IDOR check: details

The main README covers how to set the check up and run it. This page is the reference for how it reaches a verdict, so you can interpret a result or change the behavior.

## The three requests

For each config entry the tool builds one URL by filling the placeholders in `endpoint_template` from `parameters`, then sends the same request three times:

1. **A**, with TOKEN_A (the owner). This is the baseline, the response a legitimate user gets.
2. **B**, with TOKEN_B (the attacker). This is the actual test.
3. **C**, with no token. This is the control.

A and B go out together. C only goes out if B already matched A.

C exists to separate two situations that look identical from B's side. If B reads the object and so does an anonymous caller, the object was never protected, which is a missing-authentication problem and not a BOLA one. If B reads it and an anonymous caller is rejected, the server is checking that you're logged in but not that the object is yours. That's BOLA.

## Verdicts

| What comes back | Result |
|---|---|
| A isn't `200` | Untestable. There's no baseline to compare against, so the message hints at the cause: 401 means TOKEN_A was rejected (probably expired), 403 means TOKEN_A isn't allowed to see the object, 404 means the ID wasn't found |
| B returns `401` | Untestable. It means the server didn't accept B's credential, which could just be an expired token, so it says nothing about the object. The message tells you to refresh TOKEN_B |
| B returns `403` | Not a finding. The server refused B for this object |
| B returns `404` | Untestable. Either the object doesn't exist, or the server answers 404 instead of 403 to hide that it exists |
| B returns any other non-200 status | Untestable, reported with the unexpected status |
| B returns `200` but the body doesn't match A's | Untestable. It could be a safe response scoped to the caller, or a real leak that happens to look different, and the tool won't guess |
| B returns `200`, matches A, and C also returns `200` and matches | Untestable, reported as "not a BOLA finding". The object is public. Missing Authentication Detection is the check for that |
| B returns `200`, matches A, and C returns 401, 403 or 404 | Finding |
| B matched A but C couldn't be sent (network error) | Finding at Tentative confidence, with the control failure in the description |
| B matched A and C returns something else (say a 500, or a 200 that doesn't match) | Untestable, because the control couldn't settle it |

Only a `200` counts as a successful response for A, B and C.

## What counts as a match

If both bodies parse as JSON, the tool compares their structure and ignores the values. It collects every key name at every depth, then checks how many of A's keys also appear in B. It's a match when at least 2 keys are shared and at least 70% of A's keys are present in B. Comparing keys instead of values keeps timestamps, request IDs and other values that change on every call from hiding a real leak. If A's body has no keys at all (a bare string, a number, `null`, `{}`), there's nothing to compare and the result is "unknown", never a match.

If one body is JSON and the other isn't, the result is unknown.

If neither is JSON, the tool falls back to something cruder. The content types must be the same (ignoring a `; charset=...` suffix, and a missing header counts as an empty string), and the body lengths must be within 15% of each other. Two empty bodies are never a match, since there's nothing in them to compare.

The thresholds are constants at the top of `src/bola.js` (`JSON_MIN_MATCHED_KEYS`, `JSON_MIN_MATCH_RATIO`, `FALLBACK_LENGTH_TOLERANCE`) if you want to tune them.

The comparison has a known weakness. Two different objects with the same shape, such as two books that both have `title` and `author`, can look like a match. That's the main reason the non-JSON path is capped lower in confidence.

## Confidence and severity

| Confidence | When | Severity |
|---|---|---|
| Certain | JSON structure matched, and C was rejected | Critical |
| Firm | Non-JSON match (content type and length), and C was rejected | High |
| Tentative | B matched A, but C couldn't be sent | Medium |

Certain and Firm findings trigger exit code `1` like any other Critical or High finding.

## Input validation

Each entry is checked before any request goes out. The tool reports a problem for an entry when:

- `endpoint_template` or `http_method` isn't a non-empty string
- `parameters` is missing or isn't an object
- the template uses a placeholder that has no matching key in `parameters`

Each of these produces an Untestable entry that names the problem, and the other entries still run. A placeholder that appears several times in a template is replaced everywhere. Values are URL-encoded before they go into the path.

An entry with no `test_id` is labeled `entry_1`, `entry_2` and so on, by its position in the file.

The config file itself is validated in `main.js` before the scan starts. An unreadable file, invalid JSON, or something that's neither an object nor an array exits with code `2`. A single object is accepted and treated as a one-entry array.

## State-changing methods

Request A runs before B and C, so for POST, PUT, PATCH or DELETE it could change or delete the very object being tested. The tool skips those entries unless they carry `"confirm_state_changing": true`. Don't set that against data you care about.

## Internal errors

If something unexpected goes wrong while processing one entry, that entry becomes a generic Untestable result. The raw error text isn't copied into the report, to avoid leaking internals. Expected failures, like a network error on one of the requests, do include the error message, because the user can act on them.

## Limitations

- One owner per run. TOKEN_A must own every object in the config. To cover objects owned by different users, run once per owner. If you ever need mixed owners in one run, the natural change is an optional per-entry field naming which token is the owner.
- The tool trusts that TOKEN_A owns the object. If it doesn't, the finding's wording ("matches the owner's baseline") overstates what was shown, even though the access problem is still real.
- Tokens go out as `Authorization: Bearer <token>`. Other header schemes and cookie sessions aren't supported.
- Tokens have to stay valid for the whole scan.
- The path after `--bola-config=` can't itself contain an `=`.
- Tested against VAmPI only. The finding path, the public-object case, the 401 and 404 handling, validation, the DELETE opt-in and every exit-code path have run. The 403 outcome, 404 on B and the non-JSON fallback haven't been exercised against a live target. I'd like to find one that triggers them, or build a small mock server that returns chosen statuses and bodies.
