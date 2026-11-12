# Static security review: `baseline_secure_coding_api.py`

**Scope and method.** I read the attached source by hand and did not run it. Line numbers are counted from the attachment as pasted, starting at 1. Each finding separates two kinds of statement:

- **Code fact:** what the source shows.
- **Inferred requirement:** a security policy assumed from the application context you gave. The source does not state any policy.

**Working policy assumption (P0).** Nothing in the request or the code defines who may do what. I assume this least-privilege model and test each finding against it:

- Students may read only their own profile and grades.
- Professors may read and update grades only for their assigned courses.
- Administrators may do everything.
- Teaching materials may be read only from inside the materials directory, possibly only by authenticated users (policy unknown).

If the real policy differs, findings F2–F4 change accordingly.

## Findings table

| ID | Title | Location | Severity (if P0 holds) | Confidence |
|---|---|---|---|---|
| F1 | Path traversal / arbitrary file read in material download | `download_file`, L146–149 | High | High |
| F2 | Unauthenticated, unauthorized grade create/update | `update_grade`, L130–143 | Critical | High |
| F3 | Missing authentication/authorization on grade retrieval (IDOR) | `get_grades`, L124–127 | High | High |
| F4 | Missing authentication/authorization on student profiles (IDOR) | `get_profile`, L117–121 | Medium–High | High |
| F5 | Hard-coded, guessable session signing key enables session forgery | L9; used by all `flask.session` code | High (latent) | High (fact), Medium (impact today) |
| F6 | Debug mode on all interfaces (Werkzeug debugger exposure) | L160 | High when run this way | Medium |
| F7 | Verbose error handler discloses internals and turns all errors into 500s | `handle_error`, L152–156 | Medium–Low | High |
| F8 | Missing input validation in grade update and ID parsing (integrity and type confusion) | L118, L125, L131–141 | Medium | High |
| F9 | Plaintext, hard-coded, weak credentials; non-constant-time comparison | L29–44, L89 | Medium | High (fact), Low (timing exploitability) |
| F10 | Session lifecycle weaknesses: no server-side revocation, stale role, cookie flags | L92–97, L101, app config | Low–Medium | Medium |
| F11 | No brute-force protection on login; login CSRF possible | `login`, L84–97 | Low–Medium | Medium |

## Supporting explanations

### F1: Path traversal / arbitrary file read (`GET /files`)

- **Location:** `download_file`, L147–149.
- **Input and flow:** The `path` query parameter flows through `raw_path` into `MATERIALS_DIR / raw_path` and then into `flask.send_file(target)`.
- **Code fact:** The path is joined without normalization, a containment check, an allow-list, or authentication.
  - With `pathlib`, `MATERIALS_DIR / "../baseline_secure_coding_api.py"` points outside the directory.
  - If the right-hand operand is absolute, `pathlib` discards the left one. So `path=/etc/passwd` yields `/etc/passwd` directly.
  - `flask.send_file` does not confine paths. `send_from_directory` would.
- **Root cause:** User input is used as a filesystem path with no check that the resolved path stays inside `MATERIALS_DIR`.
- **Preconditions:** Network access only. The endpoint requires no login.
- **Impact:** Any file readable by the process user can be read. That includes this source file, which exposes the secret key (F5) and all passwords (F9), plus environment and config files. The same files can feed the debugger-PIN chain in F6.
- **Tests:**
  - `GET /files?path=../baseline_secure_coding_api.py` should return source code if vulnerable.
  - `GET /files?path=/etc/hostname` tests the absolute-path variant (URL-encode as needed).
  - Control: `GET /files?path=secure-coding.txt` should succeed.
  - **Expected if fixed:** 403 or 404 for both traversal forms.
- **Assumptions:** The process can read files outside `materials/`.
  - Whether materials should require login is unknown. If they should, the missing authentication is a second, policy-dependent issue on the same endpoint.
  - Confidence is high: the traversal follows directly from documented `pathlib` and `send_file` semantics.

### F2: Unauthenticated, unauthorized grade create/update (`POST /grades/update`)

- **Location:** `update_grade`, L130–143.
- **Input and flow:** The JSON body fields `student_id`, `course_id`, and `grade` flow into `find_grade`. The code then either mutates an existing row (L141) or appends a new one (L139).
- **Code fact:** The function never reads `flask.session`. No login, role, or course-assignment check exists. Any client can modify any grade, or create a grade for any student/course pair, including ones that don't exist.
- **Inferred requirement (P0):** Only a professor assigned to `course_id`, or an admin, may write. Students must never write.
- **Root cause:** Authentication and authorization are missing entirely, and so is object-level checking (course ownership).
- **Preconditions:** Network access.
- **Impact:** Complete loss of grade integrity, including students changing their own grades and fabricating records. Changes leave no audit trail.
- **Tests:**
  1. Send without any cookie: `POST /grades/update` with `{"student_id":1001,"course_id":"SRS","grade":20}`, then `GET /grades/1001`. Expect 401 if fixed.
  2. Log in as `alice` (a student) and repeat. Expect 403.
  3. Log in as `prof_srs` and set a grade for `course_id:"SSD"`, a course not assigned to them. Expect 403.
  4. As `prof_srs`, set a grade for `SRS`. Expect success (positive control).
- **Assumptions and confidence:** The requirement is inferred from the roles you described. The absence of checks is a code fact. Confidence is high.
- **CSRF note:** CSRF is not the main issue today, because no authentication exists to ride on. Once session-based auth is added, `get_json()` rejects non-JSON content types, which incidentally limits cross-site form posts. That depends on the Flask version and should be verified rather than assumed.

### F3: IDOR on grade retrieval (`GET /grades/<student_id>`)

- **Location:** `get_grades`, L124–127.
- **Input and flow:** The URL segment `student_id` goes through `int()` and filters `GRADES`. The result is returned directly.
- **Code fact:** No session check exists, so anyone can read any student's grades. Sequential IDs (1001, 1002) make enumeration trivial.
- **Inferred requirement:** A student may see only their own `student_id`. A professor may see only their own courses' rows. Note the shape of the professor rule: a professor should see a filtered subset, not all of a student's grades.
- **Impact:** Disclosure of education records, which are personal data. In an EU university setting, GDPR is relevant; that is context, not a code fact.
- **Tests:**
  - Without a session, `GET /grades/1002` should return 401 if fixed.
  - As `alice`, `GET /grades/1002` should return 403.
  - As `prof_srs`, `GET /grades/1001` should exclude the `SSD` row.
- **Confidence:** High for the missing check. The precise professor policy is assumed.

### F4: IDOR on student profiles (`GET /students/<student_id>/profile`)

- **Location:** `get_profile`, L117–121.
- **Input and flow:** The same pattern as F3. The full profile is returned: name, email, program.
- **Code fact:** No authentication or ownership check exists.
- **Inferred requirement:** Owner, plus staff on a need-to-know basis. A university might legitimately treat some fields as directory information, so this policy is genuinely uncertain.
- **Impact:** Enumeration of personal data and email harvesting for phishing.
- **Tests:**
  - Unauthenticated `GET /students/1001/profile`.
  - As `bob`, request profile `1001`.
- **Confidence:** High for the code fact. Severity is medium–high and depends on the actual disclosure policy.

### F5: Hard-coded, guessable `SECRET_KEY`

- **Location:** L9 (`"dev-secret-key"`). It affects every use of `flask.session` (L92–95, L101, L106–113).
- **Code fact:** Flask's default session is a client-side cookie signed with this key. The session holds `user`, `role`, `student_id`, and `courses`.
- **Root cause:** The secret is a predictable constant committed in source and is also readable via F1.
- **Impact:**
  - *Today:* only `/me` reads the session, so forgery mostly lets an attacker spoof `/me` output.
  - *Latent and serious:* any authorization later built on `session["role"]` or `session["courses"]` can be bypassed by forging `{"user":"x","role":"admin"}`. This is why it is rated High despite low present-day impact.
- **Test:** Sign a crafted session payload with `"dev-secret-key"` using Flask's session serializer offline, send it as the `session` cookie, and check that `/me` reports `role: admin`. If the key is fixed, the cookie is rejected and `/me` returns `user: null`.
- **Assumption:** The production deployment does not override the key. Nothing in the source does.

### F6: `debug=True` with `host="0.0.0.0"`

- **Location:** L160.
- **Code fact:** When the file is run directly, the Werkzeug development server starts with the interactive debugger and listens on all interfaces.
- **Root cause:** A development configuration in the code path used to launch the application.
- **Impact:** The Werkzeug debugger allows Python execution, gated by a PIN.
  - The PIN is derived from host properties such as the username, module path, MAC address, and machine ID. Several of these may be readable through F1. That chain can lead to remote code execution.
  - The custom `errorhandler(Exception)` (F7) probably prevents traceback pages from appearing on errors. The debugger's console endpoint may still be served.
- **Preconditions:** The app is started via `python baseline_secure_coding_api.py` (not via a production WSGI server) and is reachable over the network.
- **Test:** Start the app as written in an isolated lab and, from another host, request `/console`. Then check whether the debugger PIN prompt appears.
- **Uncertainty:** Exploitability depends on the Werkzeug version and on whether the PIN inputs are readable. Confidence is medium for full RCE and high that debug mode is exposed.

### F7: Global error handler discloses internals

- **Location:** `handle_error`, L152–156.
- **Code fact:**
  - Every exception, including `KeyError`, `ValueError`, and `FileNotFoundError`, returns `str(exc)` and the class name.
  - A handler for `Exception` also catches Werkzeug `HTTPException`s, so legitimate 404, 405, and 415 responses probably become 500s carrying the exception text.
- **Impact:**
  - Information disclosure. For example, a missing-file error from `send_file` likely contains the absolute server path, which reveals the deployment layout and makes F1 easier.
  - A file-existence oracle: "no such file" responses differ from successful ones.
  - Misleading status codes, which hamper monitoring.
- **Tests:**
  - `GET /files?path=nonexistent.txt`: check whether the response includes an absolute path.
  - `GET /grades/abc`: check for a `ValueError` message.
  - `GET /nonexistent-route`: check whether the status is 500 instead of 404.
- **Confidence:** High for the disclosure. The exact message contents depend on the version.

### F8: Missing input validation (integrity and type confusion)

- **Location:** `int(student_id)` (L118, L125); `update_grade` (L131–141).
- **Code facts:**
  - `get_json()` may return `None` or raise. Missing keys raise `KeyError`. All of these surface as 500s through F7.
  - `grade` is unconstrained: strings, negative numbers, `1000`, nested objects, and very large values are all stored.
  - `student_id` is not type-checked. A JSON string `"1001"` does not equal the integer `1001`, so `find_grade` misses and a duplicate row is appended. `GET /grades/1001` then never shows it, which corrupts the dataset.
  - Records can be created for non-existent students and courses.
  - `GRADES` grows without bound, and the endpoint is unauthenticated, so memory exhaustion is possible.
- **Inferred requirement:** Grades fall within a defined scale. Portugal commonly uses 0–20, which matches the sample data, but this is an assumption. Referenced student and course IDs must exist.
- **Tests:**
  - POST `{"student_id":"1001","course_id":"SRS","grade":"A"}`, then `GET /grades/1001`, and confirm the new row is invisible.
  - POST `grade: -5` and `grade: {"x":1}`.
  - POST an empty body.
  - **Expected if fixed:** 400 with a generic message.
- **Confidence:** High.

### F9: Credential handling

- **Location:** L29–44 and L89.
- **Code fact:**
  - Passwords are stored in plaintext in source and are short and guessable (`alicepw`, `adminpw`).
  - The comparison is plain `!=`, not constant-time. No password hashing exists.
- **Impact:** Anyone with source access, including via F1, obtains every credential, including the admin's.
  - A practical timing attack over the network is unlikely with Python string comparison. Low confidence that it is exploitable.
  - The demo dataset may be intentionally simplified. Treat this as a finding about the code pattern, not the specific values.
- **Test:** Read the source through F1 and log in as `admin1`. Also confirm by inspection that no hashing function is involved anywhere in the login flow.

### F10: Session lifecycle

- **Location:** L92–97, L101; the absence of session configuration.
- **Code facts:**
  - Sessions are stateless signed cookies. `session.clear()` on logout only tells the browser to drop the cookie, so a captured pre-logout cookie stays valid until it expires.
  - No lifetime or expiry is configured.
  - Role and courses are cached in the cookie at login and never re-checked against `USERS`, so revoked privileges persist.
  - `SESSION_COOKIE_SECURE` and `SESSION_COOKIE_SAMESITE` are not set, which leaves Flask's defaults in place.
- **Assumptions:** The transport (TLS, reverse proxy) is not shown and may set cookie flags elsewhere.
- **Tests:**
  - Log in, copy the cookie, POST `/logout`, replay the old cookie to `/me`. If it still reports the user, logout did not revoke the session.
  - Inspect the `Set-Cookie` attributes.
- **Confidence:** Medium, because impact depends on future authorization design and on deployment.

### F11: Login abuse

- **Location:** `login`, L84–97.
- **Code facts:**
  - There is no rate limiting, lockout, or attempt logging.
  - Login is a plain form POST with no CSRF token, and SameSite is not set.
- **Impact:**
  - Online brute force against weak passwords (F9).
  - Login CSRF: an attacker logs a victim into the attacker's account. Low impact here.
- **Tests:**
  - Send 1,000 rapid failed logins and check whether any are throttled.
  - Submit a cross-origin auto-posting HTML form to `/login` and check whether a session cookie is set (browser-dependent).
- **Confidence:** Medium. Rate limiting could exist upstream at a proxy, which the source doesn't show.

## Items reviewed and not reported

- **`/me` (L105–114):** It returns only the caller's own session data, so I found no issue beyond its reliance on the forgeable cookie (F5).
- **Redirect at L97:** The target is fixed, so it is not an open redirect.
- **`index` endpoint list (L69–81):** Trivial information disclosure, not reported separately.

## Limitations

- This is a single-file, static, manual review.
- I did not see dependency versions, the deployment configuration, the WSGI server, the proxy/TLS setup, or the real authorization policy. Version-sensitive claims are marked as such, mainly in F6 and F7.
- Fewer findings in an area does not mean that area is safe. Logic and authorization issues in particular should be confirmed by running the proposed tests against the documented policy, once one exists.