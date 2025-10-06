import { Router, Request, Response } from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt";
import pool from "../config/db";
import verifyToken from "../middlewares/authMiddleware";
import { OAuth2Client, TokenPayload } from "google-auth-library";
import { RowDataPacket, OkPacket } from "mysql2";

const router = Router();

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID!;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET!;
const GOOGLE_REDIRECT_URI =
  process.env.GOOGLE_REDIRECT_URI ||
  "http://localhost:4000/api/auth/google/callback";

const client = new OAuth2Client(
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI
);

interface User {
  id: number;
  name?: string;
  email?: string;
  role?: string;
}

// =======================
// GET /auth/google
// =======================
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
router.get("/google", (req: Request, res: Response) => {
  const redirectUrl = `https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=${GOOGLE_CLIENT_ID}&redirect_uri=${encodeURIComponent(
    GOOGLE_REDIRECT_URI
  )}&scope=openid%20email%20profile`;
  res.redirect(redirectUrl);
});

// =======================
// GET /auth/google/callback
// =======================
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
router.get("/google/callback", async (req: Request, res: Response) => {
  const code = req.query.code as string;
  if (!code)
    return res.status(400).json({ message: "Missing authorization code" });

  try {
    // getToken expects only the code as string
    const { tokens } = await client.getToken(code);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token!,
      audience: GOOGLE_CLIENT_ID
    });

    const payload: TokenPayload | undefined = ticket.getPayload();
    if (!payload) throw new Error("Invalid token payload");

    const { email, name, sub: googleId } = payload;

    // Find user in DB
    const [rows] = await pool
      .promise()
      .execute<RowDataPacket[]>("SELECT * FROM users WHERE email = ?", [email]);

    let user: User | undefined = rows[0] as User;

    if (!user) {
      const [result] = await pool
        .promise()
        .execute<OkPacket>(
          "INSERT INTO users (name, email, google_id) VALUES (?, ?, ?)",
          [name, email, googleId]
        );
      user = { id: result.insertId, name, email };
    }

    const jwtToken = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET!,
      { expiresIn: "24h" }
    );

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

// =======================
// GET /auth/validate
// =======================
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
router.get("/validate", verifyToken, (req: any, res: Response) => {
  const { id, name, email } = req.user;
  res.status(200).json({ id, name, email });
});

// =======================
// POST /auth/login
// =======================
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
router.post("/login", async (req: Request, res: Response) => {
  const { email, password } = req.body as { email: string; password: string };

  try {
    const [rows] = await pool
      .promise()
      .execute<RowDataPacket[]>("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length === 0)
      return res.status(401).json({ message: "Invalid email or password" });

    const user = rows[0] as User & {
      password: string;
      role: string;
      created_at: Date;
    };
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email, role: user.role },
      process.env.JWT_SECRET!,
      { expiresIn: "24h" }
    );

    res.cookie("token", token, {
      httpOnly: true,
      secure: false,
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000
    });

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

// =======================
// POST /auth/logout
// =======================
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
router.post("/logout", (req: Request, res: Response) => {
  res.cookie("token", "", {
    httpOnly: true,
    expires: new Date(0),
    sameSite: "lax"
  });
  res.status(200).json({ message: "Logout successful" });
});

export default router;
