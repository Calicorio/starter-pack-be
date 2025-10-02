# Starter Pack API

A simple Node.js REST API built using:

- **Express** for server framework
- **MySQL** for database
- **JWT** for authentication
- **Swagger** for API documentation
- **Prettier** for code formatting

---

## Features

- User registration
- User login and JWT token generation
- Google sign-in (OAuth2) and JWT token generation
- Protected routes requiring authentication
- Swagger UI for API documentation
- MySQL database integration
- Environment variables management with `.env`
- Prettier setup for consistent code formatting

---

## Installation

1. **Clone the repository**

   Use your prefered method

2. **Install dependencies**

   npm install

3. **Set up environment variables**

   Create a .env file in the root directory and add your configuration (ask Dani :P)

   Required for Google sign-in:

   ```env
   GOOGLE_CLIENT_ID=your-google-client-id.apps.googleusercontent.com
   ```

4. **Run the server**

   node index.js

---

## Google Sign-In Endpoint

**POST /auth/google**

Send `{ token: <Google ID token> }` in the request body. Returns a JWT if the token is valid and user is found/created.
