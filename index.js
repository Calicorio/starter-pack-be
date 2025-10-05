require("dotenv").config();
const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");

const app = express();
const PORT = 4000;

// =======================
// 🧩 Middleware
// =======================

// Parse JSON and cookies
app.use(express.json());
app.use(cookieParser());

// ✅ Enable CORS so frontend (localhost:3000) can send/receive cookies
app.use(
  cors({
    origin: "http://localhost:3000", // frontend origin
    credentials: true // allow cookies and Authorization headers
  })
);

// =======================
// 📦 Routes
// =======================
const usersRoute = require("./routes/users");
const authRoute = require("./routes/auth");

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
  apis: ["./routes/*.js"]
};

const swaggerSpec = swaggerJsdoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// =======================
// 🌐 Root route
// =======================
app.get("/", (req, res) => {
  res.send("Welcome to the StarterPack API");
});

// =======================
// 🚀 Start the server
// =======================
app.listen(PORT, () => {
  console.log(`StarterPack API running at http://localhost:${PORT}`);
  console.log(`Swagger docs → http://localhost:${PORT}/api-docs`);
});
