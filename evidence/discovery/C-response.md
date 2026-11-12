# Static Security Review: `baseline_secure_coding_api.py`

**Scope and method.** This review is static only. It uses the attached source and the stated requirements R1–R7. Line numbers come from the attached file (line 1 is `import dataclasses`). Nothing was run.

**Labels used below.**
- **Fact:** something the code demonstrably does.
- **Req:** a gap measured against R1–R7.
- **Inferred:** a requirement or behavior not stated in R1–R7, or one that depends on library or version behavior. These are flagged as such.

## Findings table

| ID | Title | Location | Req. | Severity | Confidence |
|---|---|---|---|---|---|
| SR-01 | No authentication on protected endpoints | `get_profile` L116–121, `get_grades` L123–127, `update_grade` L129–143, `download_file` L145–149 | R1, R7 | Critical | High |
| SR-02 | Profile read without object-level authorization | `get_profile` L116–121 | R2, R3, R4 | High | High |
| SR-03 | Grade read without student/course scoping; empty-list response | `get_grades` L123–127 | R2, R3, R4 | High | High |
| SR-04 | Unauthorized grade modification | `update_grade` L129–143 | R1, R3, R4, R7 | Critical | High |
| SR-05 | Grade update input not validated | `update_grade` L131–141 | R5, R7 | High | High |
| SR-06 | Path traversal / arbitrary file read | `download_file` L147–149 | R6, R1 | Critical | High |
| SR-07 | Over-permissive path `student_id` parsing; bad input yields 500 | L118, L125 | R5, R7 | Medium | High |
| SR-08 | Global error handler leaks exception details and turns all errors into 500 | `handle_error` L151–156 | R7 | Medium | High (leak) / Med-High (status remap) |
| SR-09 | Hard-coded `SECRET_KEY` allows session forgery | L9, L92–95 | R1, R4 (inferred impact) | High | High (conditional) |
| SR-10 | Debug mode on all interfaces | L160 | R7 (inferred) | Medium | Medium |
| SR-11 | Authorization claims cached in client-side cookie; no revocation | L92–95, L101 | Inferred | Low–Med | Medium |
| SR-12 | Plaintext passwords, non-constant-time compare, no login throttling | L37–44, L89 | Inferred (outside R1–R7) | Low | Medium |
| SR-13 | Unsynchronized mutation of shared grade list | L137–141 | Inferred | Low | Low |

## Supporting explanations

### SR-01: No authentication on protected endpoints
- **Fact:** None of the four handlers reads `flask.session`. There is no decorator and no `before_request` hook. Only `/me` (L106) checks for `"user"`.
- **Input / flow:** Any HTTP client goes straight from route to data access.
- **Root cause:** Authentication is not enforced at all. R1 requires it for exactly these four routes.
- **Preconditions / impact:** Network reachability only. An anonymous attacker can read every profile and grade, modify grades, and read files (see SR-06). Missing auth returns 200 or 404 instead of the 401 that R7 requires.
- **Test:** Send each of these with no cookie and expect 401:
  - `GET /students/1001/profile`
  - `GET /grades/1001`
  - `POST /grades/update` with valid JSON (also confirm `GRADES` is unchanged)
  - `GET /files?path=srs-summary.txt`
- **Assumptions:** None material.

### SR-02: Profile read without object-level authorization
- **Fact:** L118 looks up any `student_id` from the URL. The requester's identity and role are never compared to the record.
- **Root cause:** There is no ownership check (R2), professors are not denied (R3), and the identifier alone grants access (R4).
- **Preconditions / impact:**
  - As alice, `GET /students/1002/profile` returns Bob's name, email and program.
  - `prof_srs` can read all profiles, which R3 forbids.
  - Existing IDs return 200 and missing ones return 404, so student IDs can be enumerated. Whether a uniform response is required is **inferred**; R4/R7 imply denial should be 403.
- **Test:**
  - alice → `/students/1002/profile`: expect 403.
  - prof_srs → `/students/1001/profile`: expect 403.
  - admin1 → `/students/1001/profile`: expect 200.
  - alice → `/students/1001/profile`: expect 200.

### SR-03: Grade read without scoping
- **Fact:** L126 returns every row matching the path ID, with no filter by requester or course. L127 returns `200 []` when nothing matches.
- **Root cause:**
  - Students are not limited to their own ID (R2).
  - Professors are not limited to their assigned courses (R3). `prof_srs` would see Alice's SSD grade.
  - The response is not filtered to authorized rows, and "no permitted records" is not denied (R4).
- **Impact:** Any requester can see all grades of any student. The `[]` versus non-empty difference also reveals whether a student has grades.
- **Test:**
  - alice → `/grades/1002`: expect 403.
  - prof_srs → `/grades/1001`: expect only the SRS row.
  - A professor whose courses match none of a student's rows: expect 403, not `[]`.
  - admin1 → `/grades/1001`: expect both rows.
- **Uncertainty:** R4 says to deny when there are no permitted records. It does not say whether a nonexistent student should get 403 or 404. That choice is left open here.

### SR-04: Unauthorized grade modification
- **Fact:** L129–143 applies any update with no identity, role, or course check.
- **Root cause:** There is no authorization on a state-changing operation. Only professors (for their own courses) and admins may update (R3/R4).
- **Impact:** Anonymous users or students (e.g., alice raising her own grade) can change any grade. `prof_srs` can change SSD grades. Integrity of academic records is lost.
- **Test:**
  - Unauthenticated: expect 401.
  - alice: expect 403.
  - prof_srs updating `course_id: "SSD"`: expect 403.
  - In all three cases, confirm the stored grade is unchanged.
  - prof_srs updating SRS: expect 200.

### SR-05: Grade update input not validated
- **Facts:**
  - L131 uses `get_json()` with no type check.
  - L133–135 use dict indexing.
  - No type, range, existence or allowed-value checks exist.
  - L138–139 append a new row whenever no match is found.
- **Consequences:**
  - **Missing field:** `KeyError` before any mutation, so data is unchanged. But the client gets 500 via SR-08 instead of 400.
  - **Wrong JSON shape:**
    - A JSON array or string body raises `TypeError`, giving 500.
    - A non-JSON or absent body is version-dependent (**inferred**). Newer Werkzeug raises 415/400 from `get_json()`; older versions returned `None`, leading to `TypeError`. Either way SR-08 turns the result into 500.
  - **Invalid values are stored:**
    - `grade` of `-5`, `999`, `"A"`, `null`, or `true` (a Python `bool`, which is an `int` subclass, so a naive `isinstance(x, int)` check would also accept it).
    - `NaN` or `Infinity`, which Python's `json` accepts by default (**inferred**). These may then be re-emitted as invalid JSON in later responses.
  - **Records created for invalid targets:** a nonexistent `student_id` (e.g., `9999`), an unknown `course_id` (e.g., `"XYZ"`), or a string ID like `"1001"`, which never matches the int and silently creates a duplicate row.
- **Root cause:** No schema validation (R5). An update-or-insert path exists where R5 requires the student to already exist and the course to be known.
- **Test:** Send each payload below and expect 400 with stored data unchanged:
  - Grade values: `{"student_id":1001,"course_id":"SRS","grade":true}`, then `21`, then `-1`, then `"15"`.
  - Unknown course: `{"student_id":1001,"course_id":"XYZ","grade":10}`.
  - Nonexistent student: `{"student_id":9999,...}`.
  - String ID: `{"student_id":"1001",...}`.
  - A body of `[]`.
  - Each field missing in turn.
  - Boundary values `0` and `20` must be accepted (by an authorized user).
- **Assumption:** The update-or-insert behavior counts as non-compliant because R5 requires an "existing student identifier." Whether a new (student, course) row may be created for an existing student and known course is not stated. This review assumes it may, as long as validation passes.

### SR-06: Path traversal / arbitrary file read
- **Fact:** L147–149 does `MATERIALS_DIR / raw_path` and passes the result to `send_file`. It does not normalize the path, check containment, or call `safe_join`.
- **Flow:** query parameter `path` → `pathlib` join → filesystem read.
- **Root cause:** Two `pathlib` behaviors are not handled:
  - `../` segments are kept and resolved by the OS.
  - An absolute right operand replaces the base entirely, so `MATERIALS_DIR / "/etc/passwd"` becomes `/etc/passwd`.
- **Impact:** Combined with SR-01, an anonymous user can read any file the process can read. This includes the application source, which exposes the SR-09 key and the plaintext passwords.
- **Secondary leaks:**
  - `path=` (empty) targets the directory itself.
  - A nonexistent name raises an `OSError` whose message contains the absolute server path, returned via SR-08.
- **Test:** Send each request and expect the result shown:
  - `GET /files?path=../baseline_secure_coding_api.py`: expect 403/404 and no content.
  - `GET /files?path=/etc/hostname`: same.
  - `GET /files?path=..%2f..%2fetc%2fhostname`: same.
  - `GET /files?path=`: expect a 4xx with no path in the body.
  - `GET /files?path=srs-summary.txt` while authenticated: expect 200.
- **Uncertainty:** Symlinks placed inside `materials/` that point outside it are not addressed by the current code. Whether they would be addressed by a future containment check depends on whether the resolved path is checked. This is a residual risk to cover in testing.

### SR-07: Over-permissive path `student_id` parsing
- **Fact:** The routes use the default string converter, and L118/L125 call `int()` directly.
- **How `int()` behaves here:**
  - It accepts `-5`, `0`, `+1001`, ` 1001 `, `1_001`, and non-ASCII Unicode digits. All of these violate "positive integer" under R5, or are at least ambiguous.
  - Non-numeric input such as `abc` raises `ValueError`. Via SR-08 that becomes a 500 containing `invalid literal for int() with base 10: 'abc'`.
- **Test:**
  - `/grades/-1`, `/grades/0`, `/grades/abc`, `/grades/1_001`: expect 400 with a generic message.
  - `/grades/1001`: behaves normally.
- **Assumption:** Whether `+1001` or leading zeros should be accepted is unspecified. A strict ASCII `^[1-9][0-9]*$` form is the conservative reading.

### SR-08: Global error handler
- **Fact:** L151–156 catches every `Exception` and returns `str(exc)` plus the class name with status 500.
- **Root cause:** Exception details are exposed, which R7 forbids. Server paths leak via `OSError` in SR-06, and parse details via SR-05/SR-07.
- **Status remapping (inferred from documented Flask behavior; Medium-High confidence):** A handler registered for `Exception` also receives `HTTPException`s. So 404 (unknown route), 405, 400 and 415 would be returned as 500, contradicting R7's client-error requirement.
- **Test:**
  - `GET /nonexistent`: expect 404, but likely get 500.
  - `GET /files?path=nope.txt`: inspect the body for an absolute path.
  - `POST /grades/update` with body `{}`: expect 400 with no `KeyError` text.

### SR-09: Hard-coded `SECRET_KEY`
- **Fact:** L9 sets the key to a fixed literal in the source. Flask's default session is a client-side cookie signed with this key. L92–95 store `user`, `role`, `student_id` and `courses` in that cookie.
- **Impact (conditional):**
  - Anyone who knows the key can mint a cookie with, for example, `role: "admin"` or arbitrary `courses`.
  - Today this matters little, because authorization is absent anyway (SR-01–04).
  - Once authorization is added, it becomes a full bypass if checks trust session claims.
  - The key is exposed through source disclosure, a shared repository, or SR-06.
- **Test:** Using the known key, sign a session payload offline with Flask's session serializer, then call `/me`. Accepting the forged identity confirms the finding.
- **Assumption:** Deployment would use this same key. The literal suggests a development value, but nothing in the code overrides it.

### SR-10: Debug mode on all interfaces
- **Fact:** L160 runs `app.run(debug=True, host="0.0.0.0")`, but only when executed as `__main__`.
- **Inferred impact:** The development server and debug features are exposed to the network. Because SR-08 handles every exception, the interactive traceback page may not appear for request errors. Exposure of the Werkzeug debugger console is version- and configuration-dependent and is not confirmed here.
- **Test:** Start via `__main__` and check whether the service is reachable from another host and whether debugger endpoints respond.

### SR-11: Session design
- **Facts:**
  - Role and courses are copied into the cookie at login (L92–95).
  - Logout clears only the client's copy (L101).
  - No cookie flags (`Secure`, `SameSite`) are configured.
- **Inferred risks:**
  - A copied cookie remains valid after logout, because there is no server-side revocation.
  - Role or course changes do not take effect until re-login.
  - Logout and login can be triggered cross-site (low impact).
  - CSRF on `/grades/update` is likely limited by its JSON content-type requirement. That depends on version behavior and is unconfirmed.
- **Test:** Capture a cookie, log out, then replay the cookie against `/me` and expect `{"user": null}`.

### SR-12: Credential handling
- **Facts:**
  - Plaintext passwords in source (L37–44).
  - Comparison with `!=` (L89).
  - No attempt limiting on `/login`.
- **Why this is inferred:** R1–R7 do not specify credential storage or brute-force controls. These are noted as hardening gaps against general practice, not as requirement violations.
- **Test:** Repeated failed logins should eventually be throttled. That expectation is itself an assumed policy.

### SR-13: Unsynchronized mutation of shared grade list
- **Fact:** `GRADES` is a module-level list mutated by check-then-act logic (L137–141).
- **Inferred risk:** Under a threaded server (the Flask dev server is threaded by default in recent versions), concurrent updates to the same new (student, course) pair could create duplicate rows. This is low impact given the stated teaching-only datastore.

## Positive observations (facts)
- Failed login returns a uniform 401 for an unknown user and a wrong password (L89–90).
- `/me` meets R1's allowance for returning `{"user": null}`.
- Missing-key failures in `update_grade` occur before any mutation, so data stays unchanged in that specific case.

## Limitations
- The review covers only this file. It does not examine Flask/Werkzeug versions, deployment configuration, reverse-proxy behavior, or contents of `materials/` such as symlinks.
- Version-dependent behaviors are marked as inferred in the findings above.
- No finding was confirmed by execution. The proposed tests are the means to confirm or reject each one.
- Not finding a further issue does not mean the code is safe.