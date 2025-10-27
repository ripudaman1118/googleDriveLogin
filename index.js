const express = require("express");
const { google } = require("googleapis");
const fs = require("fs");
const path = require("path");

const app = express();

// ====== Config ======
const CLIENT_ID = process.env.DRIVE_CLIENT_ID;
const CLIENT_SECRET = process.env.DRIVE_CLIENT_SECRET;
const REDIRECT_URI = process.env.DRIVE_REDIRECT_URI;

const SCOPES = ["https://www.googleapis.com/auth/drive.file"];

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
);

const TOKEN_PATH = path.join(__dirname, "tokens.json");

// ====== Helper Functions ======

// Save tokens safely without overwriting refresh_token
const saveTokens = (newTokens) => {
  let oldTokens = {};
  if (fs.existsSync(TOKEN_PATH)) {
    oldTokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
  }

  const tokens = {
    ...oldTokens,
    ...newTokens,
    refresh_token: newTokens.refresh_token || oldTokens.refresh_token, // keep old refresh token
  };

  fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens, null, 2));
  oAuth2Client.setCredentials(tokens);
  return tokens;
};

// Get valid access token (auto refresh if expired)
const getValidAccessToken = async () => {
  if (!fs.existsSync(TOKEN_PATH)) throw new Error("Login first at /login");

  const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(tokens);

  if (!tokens.expiry_date || tokens.expiry_date < Date.now()) {
    const { credentials } = await oAuth2Client.refreshAccessToken();
    saveTokens({
      access_token: credentials.access_token,
      expiry_date: credentials.expiry_date,
      refresh_token: credentials.refresh_token,
    });
    return credentials.access_token;
  }

  return tokens.access_token;
};

// ====== Routes ======

// 1️⃣ Login route
app.get("/login", (req, res) => {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: "offline",
    scope: SCOPES,
    prompt: "consent",
  });
  res.redirect(authUrl);
});

// 2️⃣ OAuth callback
app.get("/oauth2callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.send("❌ No code received.");

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    saveTokens(tokens);
    res.send(`✅ Login successful!<br>
      Access Token: ${tokens.access_token}<br>
      Refresh Token: ${tokens.refresh_token || "Already exists"}<br>
      expiry_date: ${tokens.expiry_date}<br>
      Go to <a href='/'>Upload Form</a>`);
  } catch (err) {
    console.error(err);
    res.send("❌ OAuth Error: " + err.message);
  }
});

// 3️⃣ Manual refresh (optional)
app.get("/refresh-token", async (req, res) => {
  try {
    const token = await getValidAccessToken();
    res.send(`✅ New Access Token: ${token}`);
  } catch (err) {
    console.error(err);
    res.send("❌ Refresh failed: " + err.message);
  }
});

// 4️⃣ Upload Form
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// ====== Start Server ======
const PORT = process.env.PORT || 5050;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));

module.exports = app;
