# DAST Playbook: Web Application Security Scan

## Scope & Rules

- Only test the provided target URL and its subpaths.
- Do NOT attempt denial-of-service or destructive operations (e.g., `DROP TABLE`, `DELETE` endpoints, bulk data modification).
- Do NOT modify or delete production data on the target.
- All findings MUST include a reproducible Proof of Concept (PoC): quote the exact HTTP request sent and the relevant snippet from the HTTP response that confirms the vulnerability.
- A finding without PoC evidence in the response body, headers, or timing MUST be discarded.
- Start with a reconnaissance `GET /` request to map the application structure (links, forms, API endpoints) before running attack payloads.

## Test Categories

### 1. SQL Injection (SQLi)

**Where to test:** URL query parameters, POST form bodies (login, search, filters), JSON API fields, cookie values.

**Payloads (execute in order):**

1. **Error-based** - Inject `'` (single quote) and `"` (double quote) into each parameter. Look for database error strings in the response:
   - MySQL: `You have an error in your SQL syntax`, `mysql_fetch`
   - PostgreSQL: `ERROR: syntax error at or near`, `PG::SyntaxError`
   - SQLite: `SQLITE_ERROR`, `unrecognized token`
   - MSSQL: `Unclosed quotation mark`, `mssql_query`
   - Generic: `SQL syntax`, `ORA-`, `ODBC Driver`
2. **Boolean-based** - Send `param=1 OR 1=1` vs `param=1 OR 1=2`. Compare response lengths or content; a difference confirms injection.
3. **UNION-based** - Send `param=1 UNION SELECT NULL--`, incrementing NULLs (`NULL,NULL`, `NULL,NULL,NULL`) to determine column count. If any response includes injected data, confirm SQLi.
4. **Time-based blind** - Send `param=1; WAITFOR DELAY '0:0:5'--` (MSSQL) or `param=1' AND SLEEP(5)--` (MySQL). A response delay of >= 4 seconds confirms blind SQLi.

**Confirmation criteria:** The vulnerability is confirmed ONLY if the response contains a database error message, shows data from a UNION query, exhibits measurable timing difference, or returns different content for boolean true/false payloads.

### 2. Cross-Site Scripting (XSS)

**Where to test:** URL query parameters, form inputs, path segments, HTTP headers reflected in the response (e.g., `Referer`, `User-Agent`).

**Payloads (execute in order):**

1. **Basic reflection probe** - Inject a unique canary string `dast8x7k2m` into each parameter. Check if it appears unencoded in the HTML response body.
2. **Script injection** - `<script>alert('dast8x7k2m')</script>`
3. **Attribute breakout** - `"><img src=x onerror=alert('dast8x7k2m')>`
4. **Event handler** - `' onfocus=alert('dast8x7k2m') autofocus='`
5. **Filter bypass** - `<svg/onload=alert('dast8x7k2m')>`, `<img src=x oNeRrOr=alert('dast8x7k2m')>`, `java%0ascript:alert('dast8x7k2m')`

**Confirmation criteria:** The payload or its functional equivalent (unencoded `<script>`, unescaped event handler) appears in the response HTML. If the payload is HTML-encoded (`&lt;script&gt;`) or stripped, the test is NOT confirmed.

### 3. Security Headers Analysis

**How to test:** Send a `GET` request to the application root (`/`) and inspect response headers.

**Required headers and expected values:**

| Header | Expected | Severity if missing |
|--------|----------|---------------------|
| `Content-Security-Policy` | Present, should not contain `unsafe-inline` or `unsafe-eval` without nonce/hash | MEDIUM |
| `X-Frame-Options` | `DENY` or `SAMEORIGIN` | MEDIUM |
| `X-Content-Type-Options` | `nosniff` | LOW |
| `Strict-Transport-Security` | `max-age>=31536000; includeSubDomains` (only when target is HTTPS) | MEDIUM |
| `Referrer-Policy` | `no-referrer`, `strict-origin`, or `strict-origin-when-cross-origin` | LOW |
| `Permissions-Policy` | Present (restricts camera, microphone, geolocation at minimum) | INFO |
| `X-Powered-By` | MUST be absent (leaks technology stack) | LOW |
| `Server` | Should not reveal version numbers (e.g., `Apache/2.4.51` is bad, `Apache` alone is acceptable) | LOW |

**Confirmation criteria:** Report each missing or misconfigured header individually with the exact header value (or absence) observed.

### 4. Authentication & Authorization

**Endpoint discovery - probe these paths with unauthenticated `GET` requests:**
- `/admin`, `/admin/`, `/administrator`
- `/dashboard`, `/panel`
- `/api/admin`, `/api/users`, `/api/v1/admin`
- `/wp-admin`, `/wp-login.php`
- `/login`, `/signin`, `/auth`
- `/graphql` (send `{"query":"{__schema{types{name}}}"}` as POST)

**Tests:**

1. **Unauthenticated access** - If any admin/dashboard path returns HTTP 200 with page content (not a redirect to login), report as CRITICAL.
2. **Default credentials** - If a login form is found, try: `admin:admin`, `admin:password`, `admin:123456`, `test:test`. Report successful login as CRITICAL.
3. **IDOR** - If URLs contain numeric IDs (e.g., `/api/users/1`), request `/api/users/2`, `/api/users/0`. If different user data is returned without authentication, report as HIGH.
4. **Forced browsing** - After finding authenticated-only paths, re-request them without cookies/tokens. If content is accessible, report as HIGH.

**Confirmation criteria:** A valid HTTP 200 response with application content (not a login redirect or generic 403 page).

### 5. Information Disclosure

**Tests (execute each as a separate `GET` request):**

1. **Sensitive files:**
   - `/.env` - look for `DB_PASSWORD=`, `API_KEY=`, `SECRET_KEY=`
   - `/.git/config` - look for `[remote "origin"]`
   - `/.git/HEAD` - look for `ref: refs/`
   - `/backup.sql`, `/dump.sql`, `/db.sql` - look for `CREATE TABLE`, `INSERT INTO`
   - `/.aws/credentials` - look for `aws_access_key_id`
   - `/config.yml`, `/config.json`, `/settings.json` - look for credentials or secrets
   - `/.dockerenv` - indicates container environment
2. **Debug/status endpoints:**
   - `/debug`, `/trace`, `/actuator`, `/actuator/env`, `/actuator/health`
   - `/server-status`, `/server-info` (Apache)
   - `/elmah.axd` (ASP.NET)
   - `/_profiler`, `/_wdt` (Symfony)
3. **Error page leakage** - Send `GET /nonexistent_path_dast_test_404`. Check if the response contains stack traces, framework names with version numbers, file paths, or database connection strings.

**Confirmation criteria:** The response status is 200 (not 404/403) AND the body contains recognizable sensitive content (credentials, source code, configuration values, SQL statements).

### 6. Data Leakage Investigation

**Purpose:** Detect unintentional exposure of sensitive data in API responses, HTML source, headers, and error messages.

**6a. API Response Over-Exposure**

- For every API endpoint discovered during reconnaissance, inspect the JSON/XML response for fields that should not be publicly visible:
  - Credentials: `password`, `passwd`, `secret`, `token`, `api_key`, `apikey`, `access_token`, `private_key`
  - Personal data (PII): `ssn`, `social_security`, `date_of_birth`, `dob`, `credit_card`, `card_number`, `cvv`
  - Internal identifiers: `internal_id`, `employee_id`, `salary`, `bank_account`
- Request user-related endpoints with minimal privileges and check if the response includes fields belonging to other users or elevated-privilege data.

**6b. HTML Source Code Leakage**

- Inspect the raw HTML source of key pages (`/`, `/login`, `/dashboard`) for:
  - Hardcoded API keys or tokens in `<script>` blocks, `data-*` attributes, or hidden form fields
  - Developer comments (`<!-- TODO`, `<!-- FIXME`, `<!-- password`, `<!-- hack`) containing sensitive information
  - Environment variables or configuration objects serialized into the page (e.g., `window.__CONFIG__`, `window.ENV`)
  - Internal URLs, IP addresses (`10.x.x.x`, `192.168.x.x`, `172.16-31.x.x`), or hostnames pointing to internal infrastructure

**6c. HTTP Header Leakage**

- Inspect all response headers across multiple endpoints for:
  - Internal IP addresses in `X-Forwarded-For`, `X-Real-IP`, `Via`, or custom headers
  - Backend technology details in `X-Powered-By`, `X-AspNet-Version`, `X-Runtime`
  - Session tokens or auth data exposed in non-standard headers
  - CORS misconfigurations: send `Origin: https://evil.com` and check if `Access-Control-Allow-Origin` reflects it back or is set to `*` with `Access-Control-Allow-Credentials: true`

**6d. Error-Triggered Data Leakage**

- Send malformed requests designed to trigger verbose error responses:
  - `POST` with invalid `Content-Type: application/xml` to JSON endpoints
  - Requests with oversized parameter values (5000+ character strings)
  - Requests with unexpected HTTP methods (`PATCH`, `DELETE`, `OPTIONS`) on standard pages
- Inspect error responses for: stack traces exposing file paths, database connection strings, internal service URLs, or ORM-generated SQL queries.

**6e. Directory Listing & Backup Files**

- Request common directories: `/uploads/`, `/static/`, `/assets/`, `/files/`, `/backup/`, `/tmp/`
- If the response contains an HTML directory listing (look for `Index of /`, `<title>Directory listing`, or `Parent Directory` links), report as HIGH.
- Probe for backup files of known pages: if `/login` exists, try `/login.bak`, `/login.old`, `/login~`, `/login.swp`, `/login.php.bak`.

**Confirmation criteria:** Report only when the response actually contains sensitive data patterns (not merely a 200 status). Quote the exact leaked values (redact all but the first/last 2 characters of passwords, keys, and PII, e.g., `sk...4f`).

## Severity Ratings

| Severity | Criteria |
|----------|----------|
| CRITICAL | Confirmed SQLi, RCE, authentication bypass, exposed credentials in `.env` or config files, default admin credentials working |
| HIGH | Confirmed stored/reflected XSS with unencoded payload, IDOR exposing other users' data, directory listing with sensitive files, API over-exposure of PII/credentials, CORS misconfiguration allowing credential theft |
| MEDIUM | Reflected XSS behind minor filter bypass, missing `Content-Security-Policy` or `Strict-Transport-Security`, internal IP leak in headers, verbose stack traces in error pages |
| LOW | Missing `X-Content-Type-Options`/`Referrer-Policy`, server version in headers, developer comments with low-sensitivity info, backup files without sensitive content |
| INFO | Missing `Permissions-Policy`, technology fingerprinting without version, directory listing of public assets only |

## Output Format

For each finding, output:

```
[SEVERITY] Category - Title
  Request: METHOD /path (key parameters)
  Response: HTTP status, relevant body snippet (max 200 chars)
  Evidence: exact string or timing that confirms the vulnerability
```
