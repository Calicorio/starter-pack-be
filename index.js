require("dotenv").config();
const express = require("express");
const app = express();
const PORT = 4000;

// Middleware to parse JSON bodies
app.use(express.json());

// Routes
const usersRoute = require("./routes/users");
const authRoute = require("./routes/auth");

app.use("/api/users", usersRoute);
app.use("/api/auth", authRoute);

// Swagger setup
const swaggerUi = require("swagger-ui-express");
const swaggerJsdoc = require("swagger-jsdoc");

const swaggerOptions = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "StarterPack API",
      version: "1.0.0",
      description: "Simple API with users and login"
    },
    servers: [
      {
        url: "http://localhost:4000/api"
      }
    ],
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

// Root route
app.get("/", (req, res) => {
  res.send("Welcome to the StarterPack API");
});

// Start the server
app.listen(PORT, () => {
  console.log(`StarterPack API is running at http://localhost:${PORT}`);
  console.log(`Swagger docs available at http://localhost:${PORT}/api-docs`);
});
