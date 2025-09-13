const jwt = require("jsonwebtoken");

const verifyToken = (req, res, next) => {
  // Get token from the Authorization header
  const token = req.headers["authorization"]?.split(" ")[1]; // Bearer token

  if (!token) {
    return res
      .status(401)
      .json({ message: "No token provided, authorization denied" });
  }

  // Verify the token
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Invalid token" });
    }
    req.user = decoded; // Attach decoded user information to the request object
    next(); // Call next middleware (which will be your protected route handler)
  });
};

module.exports = verifyToken;
