# Static Security Review: `baseline_secure_coding_api.py`

**Scope and method.** I read the attached source only. Nothing was executed and no tools or outside references were used. Line numbers are counted from the file as attached and may be off by ±1 if blank lines render differently. The Flask and Werkzeug versions are unknown, so any behaviour that depends on the framework is marked as such.

**Policy baseline.** No access-control policy was supplied. Where a finding depends on one, I use this assumed policy, labelled **[A-POLICY]**:
- Students may read only their own profile and grades.
- Professors may read and update grades only for courses in their `courses` list.
- Admins' rights are unspecified, so I make no assumption about them.
- Unauthenticated users may access only `/`, `/login` and `/logout`.

## Findings table

| ID | Title | Location (approx. lines) | Proposed severity | Confidence |
|---|---|---|---|---|
| F1 | Path traversal / arbitrary file read in `/files` | `download_file`, L145–149 | Critical | High |
| F2 | Unauthenticated, unauthorised grade modification | `update_grade`, L129–143 | Critical | High |
| F3 | Unauthenticated access to student profiles (IDOR/BOLA, PII) | `get_profile`, L116–121 | High | High (fact) / policy-dependent |
| F4 | Unauthenticated access to any student's grades (IDOR/BOLA) | `get_grades`, L123–127 | High | High (fact) / policy-dependent |
| F5 | Hard-coded, guessable `SECRET_KEY` enables session forgery | L9 | High (latent) | High (fact) / Medium (impact) |
| F6 | Werkzeug debugger exposed on all interfaces | L159–160 | High (conditional) | Medium |
| F7 | Missing input validation on grade update | `update_grade`, L131–141 | Medium | High |
| F8 | Verbose global error handler leaks internals and acts as a file-existence oracle | `handle_error`, L151–156 | Medium | High |
| F9 | Stale, unrevocable client-side session authorisation | `login` L92–95, `logout` L101 | Medium (latent) | Medium |
| F10 | Plaintext hard-coded credentials, no brute-force protection | `USERS` L37–44, `login` L83–97 | Medium | High (fact) |
| F11 | Missing CSRF protection and cookie hardening | `login`, `logout`; app config | Low | Medium |

## Supporting explanations

### F1: Path traversal / arbitrary file read (`/files`)
- **Location:** `download_file`, L147–149.
- **Input and flow:** The query parameter `path` goes into `raw_path`, then `MATERIALS_DIR / raw_path`, then `flask.send_file(target)`. There is no normalisation, containment check or allow-list in between.
- **Code fact:** `pathlib` does not confine joins to the base directory.
  - `MATERIALS_DIR / "../baseline_secure_coding_api.py"` resolves outside `materials/`.
  - When the right-hand operand is absolute, `/` discards the base entirely, so `MATERIALS_DIR / "/etc/passwd"` becomes `/etc/passwd`.
  - `send_file` with a path performs no containment check. That check is what `send_from_directory` / `safe_join` exist for, and neither is used here.
  - The endpoint requires no authentication.
- **Root cause:** Untrusted input is used directly as a filesystem path.
- **Preconditions:** Network access to the service only. The OS account running the process must be able to read the target file.
- **Impact:**
  - Read any file the process can read: the application source (exposing F5's key and F10's credentials), `/etc/passwd`, environment files, `/proc/self/environ`.
  - This read primitive also enables the F6 chain.
- **Test:**
  - `GET /files?path=/etc/passwd`
  - `GET /files?path=../baseline_secure_coding_api.py`
  - Also try the URL-encoded variant, `path=..%2fbaseline_secure_coding_api.py`.
  - Confirmed if file contents are returned. Rejected if every request outside `materials/` returns 403/404 without contents.
- **Uncertainty:** Low. Readable targets depend on deployment privileges.

### F2: Unauthenticated, unauthorised grade modification
- **Location:** `update_grade`, L129–143.
- **Input and flow:** The JSON body (`student_id`, `course_id`, `grade`) goes to `find_grade`, which either mutates an existing row or appends a new one to `GRADES`.
- **Code fact:** No session check, role check or course-ownership check exists. Any client can update or create any grade.
- **Inferred requirement [A-POLICY]:** Only a professor whose `courses` contains `course_id` should be able to write.
- **Root cause:** Authentication and authorisation are entirely absent at the function level.
- **Preconditions:** Network access only.
- **Impact:**
  - Integrity loss on academic records, including self-grade-raising by students and tampering by anonymous users.
  - Creation of rows for non-existent students or courses.
- **Tests:**
  1. Unauthenticated: `POST /grades/update` with `{"student_id":1001,"course_id":"SRS","grade":20}`, then `GET /grades/1001`.
  2. Logged in as `alice`: perform the same request.
  3. Logged in as `prof_srs`: target `course_id:"SSD"`.

  Under [A-POLICY], all three should be rejected. A `200` with a persisted change confirms the finding.
- **Uncertainty:** The code fact is certain. Severity assumes grades are meant to be protected.

### F3: Unauthenticated profile access (IDOR/BOLA)
- **Location:** `get_profile`, L116–121.
- **Input and flow:** The path parameter `student_id` is converted with `int()` and used for a `STUDENT_PROFILES` lookup, and the profile is returned.
- **Code fact:** There is no check that a session exists or that `session["student_id"] == student_id`. Profiles include name, email and programme. IDs are small sequential integers, so they are trivially enumerable.
- **Inferred requirement [A-POLICY]:** A student may see only their own profile. Professor and admin visibility is unknown.
- **Impact:** Disclosure and enumeration of personal data (PII). Under GDPR, this matters for a `uc.pt` deployment.
- **Test:**
  - Unauthenticated `GET /students/1001/profile`.
  - As `bob`, `GET /students/1001/profile`.
  - Both should be denied under [A-POLICY].
- **Uncertainty:** Whether professors should see profiles is unknown.

### F4: Unauthenticated grade read (IDOR/BOLA)
- **Location:** `get_grades`, L123–127.
- **Input and flow:** Same pattern as F3, filtering `GRADES` by the supplied ID.
- **Code fact:** No authentication or ownership check exists.
- **Inferred requirement:**
  - Students should see only their own grades.
  - Professors should see only rows for their own courses. The current endpoint returns all of a student's courses, including `SSD`, to anyone.
- **Impact:** Confidentiality breach of academic records.
- **Test:**
  - Unauthenticated `GET /grades/1001`.
  - As `bob`, `GET /grades/1001`.
  - As `prof_srs`, `GET /grades/1001`, and check whether the `SSD` row is present.
- **Uncertainty:** The professor-scoping rule is an assumption.

### F5: Hard-coded, guessable `SECRET_KEY`
- **Location:** L9.
- **Code fact:**
  - The key is the literal `"dev-secret-key"` in source.
  - Flask's default session is a client-side cookie signed with this key.
  - The session holds `user`, `role`, `student_id` and `courses`.
- **Attacker input:** A crafted `session` cookie signed with the known key.
- **Root cause:** The secret is static, low-entropy, committed to source and also readable via F1.
- **Impact:**
  - *Today:* Arbitrary identities can be forged in `/me`. No endpoint currently enforces role, so direct privilege gain is limited at present.
  - *Latent:* Once authorisation is added that reads `session["role"]` or `session["courses"]`, this becomes full privilege escalation, for example to `role=admin`.
- **Test:**
  - Sign a cookie `{"user":"x","role":"admin","student_id":1002,"courses":["SRS","SSD"]}` with the default Flask serializer and this key.
  - Send it to `/me`.
  - Confirmed if the forged claims are echoed back.
- **Uncertainty:** Production may override the key through other configuration not shown. I assume it does not, since nothing in the file reads environment variables.

### F6: Werkzeug debugger exposed on all interfaces
- **Location:** L159–160, `debug=True, host="0.0.0.0"`.
- **Code fact:** When run as `python baseline_secure_coding_api.py`, the debug server listens on every interface.
- **Framework-dependent inference:**
  - The Werkzeug interactive debugger and console are enabled and PIN-protected by default.
  - The global `errorhandler(Exception)` (F8) likely stops traceback pages from appearing for ordinary errors. The debugger console endpoint is still likely reachable, and that should be verified.
  - The PIN is derived from host values (username, module path, MAC address, machine-id/cgroup data). Several of these can be read through F1.
- **Impact:** Possible chain of F1 → PIN derivation → remote code execution.
- **Preconditions:**
  - The app is started via the `__main__` block, not through gunicorn or `flask run` without debug.
  - The port is network-reachable.
  - The Werkzeug version uses a derivable PIN scheme.
- **Test:**
  - Request `/console` on port 5001 and check whether a PIN prompt appears.
  - Separately, check whether the PIN inputs can be retrieved via F1 in a lab copy.
- **Uncertainty:** Medium. This depends on the launch method, network exposure and Werkzeug version.

### F7: Missing input validation on grade update
- **Location:** `update_grade`, L131–141.
- **Code facts:**
  - `get_json()` returns `None` for a non-JSON content type, and also for an empty body depending on version. Subscripting `None`, a list or a missing key raises an exception, which surfaces as a 500 via F8.
  - None of the three fields is type- or range-checked. `grade` can be a string, a negative number, `1e308`, an object or `null`. `student_id` can be a string.
  - Because `find_grade` uses `==`, a string `"1001"` never matches the integer `1001`. That request appends a duplicate, shadow row instead of updating the existing one.
  - There is no check that the student or course exists.
- **Inferred requirement:** Grades should be numbers within the institution's scale, 0–20 in the Portuguese system. That scale is an assumption.
- **Impact:**
  - Data-integrity corruption.
  - Inconsistent records, because `get_grades` uses `int(student_id)` and therefore never shows the string-keyed rows.
  - Unbounded list growth, giving memory exhaustion through repeated appends (DoS).
  - Unsynchronised mutation of a global list under a threaded server, which is a minor race condition.
- **Tests:**
  - Send `{"student_id":"1001","course_id":"SRS","grade":"A"}`, then inspect whether a new row appeared.
  - Send `grade:-5` and `grade:{"x":1}`.
  - Send a body of `[]` and a body with `Content-Type: text/plain`.
  - Send several thousand requests with unique `course_id` values and observe memory.

### F8: Verbose global error handler
- **Location:** `handle_error`, L151–156.
- **Code facts:**
  - The handler returns `str(exc)` and the exception class name for every exception.
  - A handler registered for `Exception` also catches `HTTPException`, so genuine 404/405 responses are converted into 500s with messages. This is framework behaviour and should be confirmed for the installed version.
- **Data flow:** Any exception raised from an attacker-influenced path: `int("abc")`, F1's `send_file`, or F7's malformed bodies.
- **Impact:**
  - Information disclosure. `FileNotFoundError` and `IsADirectoryError` messages include absolute server paths.
  - File-existence and permission oracle for F1. "not found", "permission denied" and "is a directory" are distinguishable.
  - Incorrect status codes, which hinder monitoring.
- **Test:**
  - `GET /files?path=nonexistent`: check for an absolute path in the message.
  - `GET /files?path=` (empty): check for a directory error.
  - `GET /students/abc/profile`.
  - `GET /doesnotexist`: check whether it returns 500 instead of 404.

### F9: Stale, unrevocable client-side session authorisation
- **Location:** `login` L92–95, `logout` L101.
- **Code facts:**
  - Role and courses are copied into the signed cookie at login and never re-checked against `USERS`.
  - `logout` clears only the client's copy, and no server-side session store exists.
- **Inferred impact:**
  - A role or course revocation does not take effect until the cookie expires.
  - A stolen or copied cookie stays valid after logout, for up to the session lifetime. Flask's default is 31 days; check the installed version.
- **Test:**
  1. Log in as `prof_srs` and save the cookie.
  2. Call `/logout`.
  3. Replay the saved cookie to `/me`.

  Confirmed if the identity is still accepted.
- **Uncertainty:** This is latent until authorisation actually relies on session claims.

### F10: Plaintext hard-coded credentials, no brute-force protection
- **Location:** `USERS` L37–44, `login` L89.
- **Code facts:**
  - Passwords are stored in plaintext, are weak, and live in source, which is also readable via F1.
  - Comparison uses `!=` rather than a constant-time comparison. The practical timing risk here is low.
  - There is no rate limiting, lockout or delay on `/login`.
  - The same error is returned for an unknown user and a wrong password, which is good, and limits user enumeration.
- **Impact:**
  - Credential disclosure leads to account takeover, including `admin1`.
  - Online password guessing is unthrottled.
- **Test:**
  - Run about 1,000 rapid `/login` attempts against `alice` and observe whether any throttling or lockout occurs.
  - Use F1 to read the source and confirm the credentials are recoverable.
- **Uncertainty:** This may be acceptable as demo data. The finding stands if the code is deployed as-is.

### F11: Missing CSRF protection and cookie hardening
- **Code facts:**
  - `/login` and `/logout` accept form POSTs with no CSRF token.
  - No `SESSION_COOKIE_SECURE` or `SESSION_COOKIE_SAMESITE` is set.
  - `HttpOnly` is on by default in Flask.
- **Inferred impact:**
  - Login CSRF: a victim can be silently logged in as the attacker.
  - Logout CSRF.
  - The session cookie can be sent over plain HTTP.
  - `/grades/update` is partly shielded, because `get_json()` requires a JSON content type, which forces a CORS preflight. That shielding depends on no permissive CORS layer existing elsewhere. Today the point is moot because F2 requires no authentication at all.
- **Test:**
  - Host a cross-origin auto-submitting form to `/login` with the attacker's credentials, then load `/me` in the victim's browser.
  - Inspect the `Set-Cookie` attributes on the login response.
- **Uncertainty:** Modern browsers default to `SameSite=Lax`, which reduces some of this. TLS termination is not visible in the source.

## Notes and limits
- **Observed controls:** I saw no authentication or authorisation control on any data endpoint. The only security-relevant behaviours I would call correct are the uniform login error message and Flask's default `HttpOnly` cookie.
- **Out of scope:** The following are outside what this file shows and were not assessed: TLS and deployment, reverse-proxy configuration, dependency versions, logging and auditing, and any code beyond this file.
- **Absence of proof:** A finding missing from this list does not show that the corresponding area is safe.
- **Highest priorities:** F1 and F2 are exploitable without credentials. F1 also amplifies F5, F6 and F10.