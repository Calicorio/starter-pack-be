import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";

interface JwtPayload {
  id: string | number;
  name: string;
  email: string;
  role: "user" | "admin";
}

const verifyToken = (req: Request, res: Response, next: NextFunction) => {
  const headerToken = req.headers["authorization"]?.split(" ")[1];
  const cookieToken = req.cookies?.token;
  const token = headerToken || cookieToken;

  if (!token)
    return res
      .status(401)
      .json({ message: "No token provided, authorization denied" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    (req as any).user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid token" });
  }
};

export default verifyToken;
