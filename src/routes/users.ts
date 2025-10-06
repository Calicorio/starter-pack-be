import { Router, Request, Response } from "express";
import bcrypt from "bcrypt";
import pool from "../config/db";
import { v4 as uuidv4 } from "uuid";
import verifyToken from "../middlewares/authMiddleware";
import { RowDataPacket, OkPacket } from "mysql2";

const router = Router();

interface User {
  id: string;
  name: string;
  email: string;
  role: "user" | "admin";
}

interface CreateUserBody {
  email: string;
  password: string;
  name: string;
  role?: "user" | "admin";
}

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
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 10
 */
router.get("/", verifyToken, async (req: Request, res: Response) => {
  const limit = parseInt(req.query.limit as string) || 10;
  const offset = parseInt(req.query.offset as string) || 0;

  try {
    const [users] = await pool
      .promise()
      .query<
        RowDataPacket[]
      >("SELECT id, name, email FROM users LIMIT ? OFFSET ?", [limit, offset]);

    const [countRows] = await pool
      .promise()
      .query<RowDataPacket[]>("SELECT COUNT(*) as count FROM users");

    const count = countRows[0].count;

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
 */
router.post(
  "/user",
  async (req: Request<{}, {}, CreateUserBody>, res: Response) => {
    const { email, password, name, role = "user" } = req.body;

    try {
      const [rows] = await pool
        .promise()
        .execute<
          RowDataPacket[]
        >("SELECT * FROM users WHERE email = ?", [email]);

      if (rows.length > 0) {
        return res.status(400).json({ message: "Email already exists" });
      }

      const hashedPassword = await bcrypt.hash(password, 10);
      const userId = uuidv4();

      await pool
        .promise()
        .execute<OkPacket>(
          "INSERT INTO users (id, name, email, password, role) VALUES (?, ?, ?, ?, ?)",
          [userId, name, email, hashedPassword, role]
        );

      res.status(201).json({ userId });
    } catch (err) {
      console.error("Error creating user:", err);
      res.status(500).json({ message: "Internal server error" });
    }
  }
);

export default router;
