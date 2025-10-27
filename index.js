const express = require("express");
const { google } = require("googleapis");

const app = express();

// ====== Google OAuth Config ======
const CLIENT_ID = process.env.DRIVE_CLIENT_ID;
const CLIENT_SECRET = process.env.DRIVE_CLIENT_SECRET;
const REDIRECT_URI = process.env.DRIVE_REDIRECT_URI;

const SCOPES = ["https://www.googleapis.com/auth/drive.file"];

const oAuth2Client = new google.auth.OAuth2(
  CLIENT_ID,
  CLIENT_SECRET,
  REDIRECT_URI
);

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

// 2️⃣ OAuth callback route
app.get("/oauth2callback", async (req, res) => {
  const code = req.query.code;
  if (!code) return res.send("❌ No code received.");

  try {
    const { tokens } = await oAuth2Client.getToken(code);

    res.send(`
      <html>
        <head>
          <title>Google Drive Token</title>
          <style>
            body { 
              font-family: Arial, sans-serif; 
              background: #f9f9f9; 
              padding: 40px; 
              color: #333;
            }
            h2 { color: #0b8043; }
            pre { 
              background: #fff; 
              border: 1px solid #ddd; 
              padding: 15px; 
              border-radius: 8px; 
              font-size: 14px; 
              white-space: pre-wrap;
              word-break: break-word;
            }
            button {
              margin-top: 10px;
              padding: 10px 15px;
              background: #0b8043;
              color: white;
              border: none;
              border-radius: 5px;
              cursor: pointer;
            }
          </style>
        </head>
        <body>
          <h2>✅ Google Drive Login Successful!</h2>
          <p>Here are your tokens — copy and save them safely:</p>
          <pre>${JSON.stringify(tokens, null, 2)}</pre>
          <button onclick="navigator.clipboard.writeText(JSON.stringify(${JSON.stringify(tokens)}))">
            📋 Copy Tokens
          </button>
          <hr/>
          <p>Go to <a href="/">Home</a></p>
        </body>
      </html>
    `);
  } catch (err) {
    console.error(err);
    res.send("❌ OAuth Error: " + err.message);
  }
});

// 3️⃣ Home route
app.get("/", (req, res) => {
  res.send(`
    <h2>🚀 Google Drive Upload Login</h2>
    <p>Click below to login and get your tokens.</p>
    <a href="/login">
      <button style="padding:10px 15px;background:#1a73e8;color:#fff;border:none;border-radius:5px;cursor:pointer">
        Login with Google
      </button>
    </a>
  `);
});

// ====== Start Server ======
const PORT = process.env.PORT || 5050;
app.listen(PORT, () =>
  console.log(`🚀 Server running at http://localhost:${PORT}`)
);
