# Secure Login Form

A minimal login form (HTML/CSS/JS front end + Node/Express back end) built as a
security-focused alternative to OWASP Juice Shop's login page. It implements
matching client-side and server-side validation, bcrypt password hashing, and
a few standard hardening measures against SQL injection, XSS, and brute-force
login attempts.

## What it does

- Renders an email + password login form (`index.html`, `style.css`).
- Client-side JS (`script.js`) blocks empty submissions and checks that the
  email contains `@` and the password is at least 8 characters before ever
  sending a request.
- The same two checks are re-run on the server (`server.js`) — client-side
  validation is only a UX convenience, never trusted as the security
  boundary.
- Passwords are hashed with **bcrypt** (12 salt rounds) before being stored;
  the plaintext password is never persisted.
- The one "seeded" demo account is `user@example.com` / `Password123!`.

## Security measures

| Risk | Mitigation |
|---|---|
| SQL Injection | No raw SQL string-building. The user lookup is a plain array `find`, which is the same shape as a parameterized query (`WHERE email = ?`) — there's no string to break out of. |
| XSS | Server responses are rendered with `textContent`, never `innerHTML`, so any value shown back to the user is treated as text, not markup. A `Content-Security-Policy` header (via `helmet`) further restricts script execution. |
| Auth bypass / user enumeration | Login always returns the same generic "Invalid email or password" message, and `bcrypt.compare` runs against a dummy hash even for unknown emails, so response content/timing can't be used to guess which emails are registered. |
| Credential stuffing / brute force | `express-rate-limit` caps login attempts per IP to 10 per 15 minutes. |
| Weak password storage | Passwords are hashed with bcrypt (cost factor 12), never stored or logged in plaintext. |

## Running it locally

```bash
npm install
npm start
```

Then open <http://localhost:3000> in a browser.

## Project structure

```
index.html    # login form markup
style.css     # styling
script.js     # client-side validation + fetch call to the API
server.js     # Express server: server-side validation, bcrypt, rate limiting
package.json  # dependencies / start script
```
