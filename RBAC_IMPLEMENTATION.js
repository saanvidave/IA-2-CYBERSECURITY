// Import required modules
const express = require("express");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const { body, validationResult } = require("express-validator");
require("dotenv").config(); // Load environment variables

const app = express();
app.use(express.json()); // Enable JSON body parsing
app.use(helmet()); // Security middleware (CSP, XSS, etc.)
app.use(morgan("combined")); // Logging middleware

// Secret Key for JWT (from .env or default)
const SECRET_KEY = process.env.SECRET_KEY || "my-secret-key";

// In-memory database (Replace with DB in production)
let users = [
    { id: 1, username: "admin", password: "password123", role: "admin" },
    { id: 2, username: "user1", password: "userpass", role: "user" }
];

// Middleware for Authentication 
// JWT Authentication Middleware
const authenticateJWT = (req, res, next) => {
    const token = req.header("Authorization");
    if (!token) return res.status(401).json({ error: "Access Denied" });

    jwt.verify(token.replace("Bearer ", ""), SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Invalid Token" });
        req.user = user; // Attach user data to request
        next();
    });
};

// Role-Based Access Control (RBAC)
const requireRole = (role) => {
    return (req, res, next) => {
        if (!req.user || req.user.role !== role) {
            return res.status(403).json({ error: "Forbidden: Admins only" });
        }
        next();
    };
};

// Public Routes 
// Welcome Route
app.get("/", (req, res) => {
    res.json({ message: "Welcome to the Secure Cyber Security Lab API" });
});

// User Login Route - Returns JWT Token
app.post("/login", [
    body("username").isString(),
    body("password").isLength({ min: 6 })
], (req, res) => {
    const { username, password } = req.body;

    // Find user in database
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    // Generate JWT token
    const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ token });
});

// Secure Routes (Require Authentication) 

// Fetch all users (Authenticated users only)
app.get("/users", authenticateJWT, (req, res) => {
    res.json(users.map(user => ({ id: user.id, username: user.username, role: user.role }))); // Exclude passwords
});

// Add a new user (Admins only)
app.post("/users", authenticateJWT, requireRole("admin"), [
    body("username").isString().trim(),
    body("password").isLength({ min: 6 }),
    body("role").isIn(["admin", "user"]).withMessage("Role must be 'admin' or 'user'")
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });

    // Create new user
    const { username, password, role } = req.body;
    const newUser = { id: users.length + 1, username, password, role };
    users.push(newUser);
    res.status(201).json({ message: "User added successfully" });
});

// Delete a user (Admins only)
app.delete("/users/:id", authenticateJWT, requireRole("admin"), (req, res) => {
    users = users.filter(user => user.id !== parseInt(req.params.id));
    res.json({ message: "User deleted" });
});

//Secure Data Handling Endpoint
// Secure Data Processing Route
app.post("/data", authenticateJWT, (req, res) => {
    try {
        if (!req.body || typeof req.body !== "object") {
            return res.status(400).json({ error: "Invalid input" });
        }

        // Input Validation: Prevent XSS by removing < and >
        const sanitizedData = {};
        for (let key in req.body) {
            sanitizedData[key] = String(req.body[key]).replace(/</g, "").replace(/>/g, "");
        }

        console.log("Received Data:", sanitizedData);
        res.status(201).json({ received_data: sanitizedData, status: "Success" });
    } catch (error) {
        res.status(500).json({ error: "Server Error", message: error.message });
    }
});

// Start Server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
