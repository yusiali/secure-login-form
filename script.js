// Client-side validation only improves UX — it is never trusted as the
// security boundary. The server repeats every check below before touching
// the password store (see server.js).

const form = document.getElementById("login-form");
const emailInput = document.getElementById("email");
const passwordInput = document.getElementById("password");
const messageEl = document.getElementById("form-message");

function isValidLogin(email, password) {
  const hasAt = email.includes("@");
  const longEnoughPassword = password.length >= 8;
  return hasAt && longEnoughPassword;
}

function showMessage(text, type) {
  // textContent (not innerHTML) so any value we display — including an
  // echoed error — is rendered as plain text and can never execute as HTML/JS.
  messageEl.textContent = text;
  messageEl.className = `message ${type}`;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = emailInput.value.trim();
  const password = passwordInput.value;

  if (!email || !password) {
    showMessage("Email and password are required.", "error");
    return;
  }

  if (!isValidLogin(email, password)) {
    showMessage(
      "Enter a valid email and a password of at least 8 characters.",
      "error"
    );
    return;
  }

  try {
    const response = await fetch("/api/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    const data = await response.json();

    if (response.ok) {
      showMessage(data.message || "Login successful.", "success");
    } else {
      // Server intentionally returns a generic message for both
      // "unknown email" and "wrong password" to avoid user enumeration.
      showMessage(data.message || "Invalid email or password.", "error");
    }
  } catch (err) {
    showMessage("Could not reach the server. Try again.", "error");
  }
});
