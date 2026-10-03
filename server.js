const path = require("path");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

// --- Security headers -------------------------------------------------
// Sets a conservative Content-Security-Policy, X-Content-Type-Options,
// etc. This gives XSS a much smaller blast radius even if a payload ever
// slipped past input handling.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        objectSrc: ["'none'"],
      },
    },
  })
);

app.use(express.json());
app.use(express.static(path.join(__dirname)));

// --- Mock user "database" ---------------------------------------------
// In a real app this row would live in SQL/Postgres/etc. Only the bcrypt
// HASH is ever stored — the plaintext password never touches disk.
// Seed password below is "Password123!" (hashed once at startup).
const users = [];

(async function seed() {
  const passwordHash = await bcrypt.hash("Password123!", 12);
  users.push({ email: "user@example.com", passwordHash });
})();

// --- Brute-force / credential-stuffing mitigation ----------------------
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many attempts. Try again later." },
});

function isValidEmail(email) {
  // Simple, intentionally conservative check — mirrors the assignment's
  // "contains @" rule but also guards against obviously malformed input.
  return typeof email === "string" && email.includes("@") && email.length <= 254;
}

function isValidPassword(password) {
  return typeof password === "string" && password.length >= 8;
}

app.post("/api/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};

  // --- Server-side validation (never trust the client) -----------------
  if (!isValidEmail(email) || !isValidPassword(password)) {
    return res.status(400).json({ message: "Invalid email or password." });
  }

  // --- Safe lookup, no string-built SQL ---------------------------------
  // There is no raw query here, so there is nothing for a SQL-injection
  // payload (e.g. `' OR '1'='1`) to break out of. With a real database
  // this lookup would be a parameterized/prepared statement, e.g.:
  //   db.query("SELECT * FROM users WHERE email = ?", [email]);
  // never string concatenation like `"...WHERE email = '" + email + "'"`.
  const user = users.find((u) => u.email === email);

  // Same generic failure message whether the email doesn't exist or the
  // password is wrong, and bcrypt.compare runs either way (constant-ish
  // timing) so the response can't be used to enumerate valid accounts.
  const dummyHash = "$2a$12$CwTycUXWue0Thq9StjUM0uJ8n1JUsFZkXsd9WY7pX9p9X7xB2P0Ni";
  const match = await bcrypt.compare(password, user ? user.passwordHash : dummyHash);

  if (!user || !match) {
    return res.status(401).json({ message: "Invalid email or password." });
  }

  return res.status(200).json({ message: "Login successful." });
});

app.listen(PORT, () => {
  console.log(`Secure login demo running at http://localhost:${PORT}`);
});
