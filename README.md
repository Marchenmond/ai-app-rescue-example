# AI App Rescue Example: TaskTrack (before / after)

**Result: an app that would not even start became a secure, tested API (0 to 14 passing tests, 10 problems fixed).**

| | Before | After |
|---|---|---|
| Starts | No (missing module) | Yes |
| Secrets | Hardcoded in source | Environment variable |
| Passwords | Plaintext | PBKDF2, 600k rounds |
| Data access | Everyone sees everything | Per-owner, 404 otherwise |
| Tests | 0 | 14 passing |

A small task-list API with login, the way AI code generators often leave it: it looks finished, but it does not start, leaks data and has no tests. This case study shows the broken starting point (`before/`) and the repaired version (`after/`). All names and data are fictional.

## What was broken (`before/app.py`)

| # | Problem | Impact |
|---|---------|--------|
| 1 | **Build error**: `from helpers import parse_body`, but `helpers.py` does not exist | App does not start (`ModuleNotFoundError`) |
| 2 | **Hardcoded secret** (`SECRET_KEY` in the source, printed to the console at startup) and an unused default admin password in the code | Credential leak the moment the code is shared |
| 3 | **SQL injection** in `/register` and `/login` (string formatting) | `name = "x' OR '1'='1' --"` logs in as anybody |
| 4 | **Plaintext passwords** stored in the database | One DB leak exposes every user |
| 5 | **Forgeable token**: the token is just `base64(username)` | Anyone can impersonate any user |
| 6 | **No access control**: `GET /tasks` returns every user's tasks, `DELETE` has no owner check | Users see and delete each other's data |
| 7 | **Off-by-one**: "complete task" updates `id + 1` | Marks the wrong task as done |
| 8 | No input validation (empty titles, bad JSON, non-numeric ids) | Garbage data and 500 errors |
| 9 | Errors returned with `200 OK`; an empty or missing auth header is accepted as a user | Clients cannot tell success from failure |
| 10 | **No tests** | Nothing to catch any of the above |

I confirmed items 3, 5, 6, 7 and 8 by running the old code after stubbing the missing import (see "How the bugs were confirmed").

## What was done (`after/`)

- Added the missing piece and folded request parsing into the app with proper `400` errors for bad JSON.
- Secret now comes from the `TASKTRACK_SECRET` environment variable; the app refuses to start without it.
- All SQL is parameterized.
- Passwords hashed with PBKDF2-SHA256 (random salt, 600k rounds) and compared in constant time.
- Tokens are signed (HMAC-SHA256) and expire after one hour; the old base64 token is rejected.
- Every task query is scoped to the logged-in owner; other users get `404`.
- Correct status codes (201, 400, 401, 404, 409), title length and password length rules.
- Fixed the `id + 1` bug and added a regression test for it.
- Request bodies capped at 10 KB (`413`), and logins locked for 5 minutes after 5 failures per name (`429`).
- 14 automated tests (`unittest`, no extra packages) covering login, injection attempts, forged and expired tokens, ownership, validation and config.

## How to run and test

```bash
# before: fails to start
cd before && python app.py        # ModuleNotFoundError: No module named 'helpers'

# after: tests
cd after && python -m unittest discover -s tests -v    # Ran 14 tests ... OK

# after: run the server
set TASKTRACK_SECRET=change-me && python app.py        # http://localhost:8000
```

Requires Python 3.9+; standard library only.

## How the bugs were confirmed

With a 3-line `helpers.py` stub added in a scratch folder, the old code returned: another user's tasks to a different user, a valid token for the injection login, `200 OK` with an empty header, task `B` marked done when task `A` was completed, and accepted an empty title.

---
Built by Gabriel Montemór · Marchenmond — available on Upwork for small fixes and automations
