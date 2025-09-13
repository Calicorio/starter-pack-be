const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const pool = require("../config/db");
const { v4: uuidv4 } = require("uuid");
const verifyToken = require("../middlewares/authMiddleware");

/**
 * @swagger
 * /users:
 *   get:
 *     summary: Get a paginated list of all users
 *     tags: [Users]
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: offset
 *         schema:
 *           type: integer
 *           default: 0
 *         description: The number of items to skip before starting to collect the result set
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 *         description: The number of items to return
 *     responses:
 *       200:
 *         description: Paginated list of users
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 offset:
 *                   type: integer
 *                   example: 0
 *                 limit:
 *                   type: integer
 *                   example: 10
 *                 total:
 *                   type: integer
 *                   example: 42
 *                 items:
 *                   type: array
 *                   items:
 *                     type: object
 *                     properties:
 *                       id:
 *                         type: integer
 *                         example: 1
 *                       name:
 *                         type: string
 *                         example: John Doe
 *                       email:
 *                         type: string
 *                         example: john@example.com
 *       401:
 *         description: Unauthorized, invalid or no token
 */
router.get("/", verifyToken, async (req, res) => {
  const limit = parseInt(req.query.limit) || 10;
  const offset = parseInt(req.query.offset) || 0;

  try {
    const [users] = await pool
      .promise()
      .query("SELECT id, name, email FROM users LIMIT ? OFFSET ?", [
        limit,
        offset
      ]);

    const [[{ count }]] = await pool
      .promise()
      .query("SELECT COUNT(*) as count FROM users");

    res.status(200).json({
      offset,
      limit,
      total: count,
      items: users
    });
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

/**
 * @swagger
 * /users/user:
 *   post:
 *     summary: Register a new user
 *     tags: [Users]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             required:
 *               - email
 *               - password
 *               - name
 *             properties:
 *               email:
 *                 type: string
 *                 example: user2@email.co
 *               password:
 *                 type: string
 *                 example: user2
 *               name:
 *                 type: string
 *                 example: User2
 *               role:
 *                 type: string
 *                 enum: [user, admin]
 *                 default: user
 *                 example: user
 *     responses:
 *       201:
 *         description: User created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 userId:
 *                   type: string
 *                   example: 550e8400-e29b-41d4-a716-446655440000
 *       400:
 *         description: Email already exists
 */

router.post("/user", async (req, res) => {
  const { email, password, name, role = "user" } = req.body; // Default role is 'user'

  try {
    // Check if email already exists
    const [rows] = await pool
      .promise()
      .execute("SELECT * FROM users WHERE email = ?", [email]);

    if (rows.length > 0) {
      return res.status(400).json({ message: "Email already exists" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate a new UUID for the user ID
    const userId = uuidv4();

    await pool.promise().execute(
      "INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)",
      [userId, name, email, hashedPassword, role] // Add role to query
    );

    // Respond with the generated user ID
    res.status(201).json({ userId: userId });
  } catch (err) {
    console.error("Error:", err);
    res.status(500).json({ message: "Internal server error" });
  }
});

module.exports = router;
