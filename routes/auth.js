const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const router = express.Router();
const pool = require("../config/db"); // Import the database connection
const verifyToken = require("../middlewares/authMiddleware");
/**
 * @swagger
 * /auth/validate:
 *   get:
 *     summary: Validate a Bearer token and return user info if valid
 *     tags: [Auth]
 *     security:
 *       - bearerAuth: []
 *     responses:
 *       200:
 *         description: Token is valid, user info returned
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: integer
 *                 name:
 *                   type: string
 *                 email:
 *                   type: string
 *       401:
 *         description: Invalid or expired token
 */
router.get("/validate", verifyToken, (req, res) => {
  // req.user is set by verifyToken middleware
  const { id, name, email } = req.user;
  res.status(200).json({ id, name, email });
});

/**
 * @swagger
 * /auth/login:
 *   post:
 *     summary: Login a user and return a Bearer token
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
 *                 example: user1@email.com
 *               password:
 *                 type: string
 *                 example: user1
 *     responses:
 *       200:
 *         description: Login successful and Bearer token returned
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                   example: "your_jwt_token_here"
 *       401:
 *         description: Invalid email or password
 */

router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists in the database
    const [rows] = await pool
      .promise()
      .execute("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length === 0) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    const user = rows[0];

    // Compare the entered password with the hashed password in the database
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Generate the JWT token with 24h expiration
    const token = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    // Return only the token in the response
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
 *     summary: Logs out a user (client should delete token)
 *     tags: [Auth]
 *     responses:
 *       200:
 *         description: User logged out successfully
 */

router.post("/logout", (req, res) => {
  res.status(200).json({
    message: "Logout successful."
  });
});

module.exports = router;
