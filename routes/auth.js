const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = express.Router();
const pool = require("../config/db");
const verifyToken = require("../middlewares/authMiddleware");
const { OAuth2Client } = require("google-auth-library");

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  "http://localhost:4000/api/auth/google/callback";

const client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

/**
 * @swagger
 * tags:
 *   name: Auth
 *   description: Authentication and Authorization
 */

/**
 * @swagger
 * /auth/google:
 *   get:
 *     summary: Redirects user to Google OAuth2 login
 *     description: Starts the Google login flow.
 *     tags: [Auth]
 *     responses:
 *       302:
 *         description: Redirect to Google OAuth2 authorization URL
 */
router.get("/google", (req, res) => {
  const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(
    GOOGLE_REDIRECT_URI
  )}&scope=openid%20email%20profile`;
  res.redirect(redirectUrl);
});

/**
 * @swagger
 * /auth/google/callback:
 *   get:
 *     summary: Handles Google OAuth2 callback
 *     description: Exchanges authorization code for tokens, verifies identity, creates or retrieves user, and issues JWT in HttpOnly cookie.
 *     tags: [Auth]
 *     parameters:
 *       - in: query
 *         name: code
 *         required: true
 *         schema:
 *           type: string
 *         description: Google OAuth authorization code
 *     responses:
 *       302:
 *         description: Redirects to the frontend oauth-redirect page
 *       400:
 *         description: Missing authorization code
 *       500:
 *         description: Google login failed
 */
router.get("/google/callback", async (req, res) => {
  const { code } = req.query;
  if (!code)
    return res.status(400).json({ message: "Missing authorization code" });

  try {
    const { tokens } = await client.getToken({
      code,
      client_id: GOOGLE_CLIENT_ID,
      client_secret: GOOGLE_CLIENT_SECRET,
      redirect_uri: GOOGLE_REDIRECT_URI
    });

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: GOOGLE_CLIENT_ID
    });

    const payload = ticket.getPayload();
    const { email, name, sub: googleId } = payload;

    // Find or create user
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
      user = { id: result.insertId, name, email };
    }

    // Create JWT
    const jwtToken = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // ✅ Localhost-friendly cookie
    res.cookie("token", jwtToken, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    res.redirect("http://localhost:3000/oauth-redirect");
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).json({ message: "Google login failed" });
  }
});

/**
 * @swagger
 * /auth/validate:
 *   get:
 *     summary: Validate JWT cookie
 *     description: Returns the user's decoded info if the token is valid.
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Valid token, user returned
 *       401:
 *         description: Invalid or missing token
 */
router.get("/validate", verifyToken, (req, res) => {
  const { id, name, email } = req.user;
  res.status(200).json({ id, name, email });
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login with email and password
 *     description: Authenticates a user, issues a JWT in an HttpOnly cookie, and returns safe user info.
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successful login, returns user info
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                   example: 1
 *                 name:
 *                   type: string
 *                   example: John Doe
 *                 email:
 *                   type: string
 *                   example: john@example.com
 *                 role:
 *                   type: string
 *                   example: user
 *                 created_at:
 *                   type: string
 *                   format: date-time
 *                   example: 2025-10-06T12:34:56.000Z
 *       401:
 *         description: Invalid email or password
 *       500:
 *         description: Internal server error
 */
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool
      .promise()
      .execute("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const user = rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // ✅ Localhost-friendly cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

    // ✅ Return only safe user info
    res.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      created_at: user.created_at
    });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * @swagger
 * /auth/logout:
 *   post:
 *     summary: Logout
 *     description: Clears the JWT cookie.
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: Logout successful
 */
router.post("/logout", (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: "lax"
  });
  res.status(200).json({ message: "Logout successful" });
});

module.exports = router;
