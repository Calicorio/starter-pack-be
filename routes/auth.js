const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = express.Router();
const pool = require("../config/db"); // Import the database connection
const verifyToken = require("../middlewares/authMiddleware");
const { OAuth2Client } = require("google-auth-library");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  "http://localhost:4000/auth/google/callback";

const client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Redirects user to Google OAuth2 login
 *     tags: [Auth]
 */
router.get("/google", (req, res) => {
  const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(GOOGLE_REDIRECT_URI)}&scope=openid%20email%20profile`;
  res.redirect(redirectUrl);
});

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Google OAuth2 callback, exchanges code for JWT
 *     tags: [Auth]
 */
router.get("/google/callback", async (req, res) => {
  const { code } = req.query;
  if (!code) {
    return res.status(400).json({ message: "Missing authorization code" });
  }

  try {
    const { tokens } = await client.getToken({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI
    });

    // Verify ID token
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    // Lookup or create user in DB
    let [rows] = await pool
      .promise()
      .execute("SELECT * FROM users WHERE email = ?", [email]);
    let user = rows[0];
    if (!user) {
      const [result] = await pool
        .promise()
        .execute(
          "INSERT INTO users (name, email, google_id) VALUES (?, ?, ?)",
          [name, email, googleId]
        );
      user = { id: result.insertId, name, email }; // This will now have the auto-generated id
    }

    // Issue JWT
    const jwtToken = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Redirect to frontend with token
    res.redirect(`http://localhost:3000?token=${jwtToken}`);
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).json({ message: "Google login failed" });
  }
});

/**
 * @swagger
 * /auth/validate:
 *   get:
 *     summary: Validate a Bearer token and return user info if valid
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 */
router.get("/validate", verifyToken, (req, res) => {
  const { id, name, email } = req.user;
  res.status(200).json({ id, name, email });
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login a user with email/password and return JWT
 *     tags: [Auth]
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool
      .promise()
      .execute("SELECT * FROM users WHERE email = ?", [email]);
    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logs out a user (client deletes token)
 *     tags: [Auth]
 */
router.post("/logout", (req, res) => {
  res.status(200).json({ message: "Logout successful." });
});

module.exports = router;
