import "dotenv/config";
import express, { Request, Response } from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import swaggerUi from "swagger-ui-express";
import swaggerJsdoc from "swagger-jsdoc";

import usersRoute from "./routes/users";
import authRoute from "./routes/auth";

const app = express();
const PORT = 4000;

// =======================
// 🧩 Middleware
// =======================
app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true
  })
);

// =======================
// 📦 Routes
// =======================
app.use("/api/users", usersRoute);
app.use("/api/auth", authRoute);

// =======================
// 📘 Swagger setup
// =======================
const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "StarterPack API",
      version: "1.0.0",
      description: "Simple API with users and login"
    },
    servers: [{ url: "http://localhost:4000/api" }],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT"
        }
      }
    }
  },
  apis: ["dist/routes/*.js"] // <-- point to compiled JS
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// =======================
// 🌐 Root route
// =======================
app.get("/", (_req: Request, res: Response) => {
  res.send("Welcome to the StarterPack API");
});

// =======================
// 🚀 Start the server
// =======================
app.listen(PORT, () => {
  console.log(`StarterPack API running at http://localhost:${PORT}`);
  console.log(`Swagger docs → http://localhost:${PORT}/api-docs`);
});
