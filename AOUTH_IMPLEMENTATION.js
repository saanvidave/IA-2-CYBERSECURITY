// Import required modules
const express = require("express");
const helmet = require("helmet");
const morgan = require("morgan");
const session = require("express-session");
const passport = require("passport");
const { Strategy: GoogleStrategy } = require("passport-google-oauth20");
require("dotenv").config(); // Load environment variables

const app = express();
app.use(express.json());
app.use(helmet()); // Security middleware
app.use(morgan("combined")); // Logging middleware

// Configure session (required for OAuth)
app.use(session({
    secret: process.env.SESSION_SECRET || "supersecretkey",
    resave: false,
    saveUninitialized: true
}));

app.use(passport.initialize());
app.use(passport.session());

// Dummy User Database (Replace with DB in production)
let users = [
    { id: 1, googleId: "123", username: "admin", role: "admin" },
    { id: 2, googleId: "456", username: "user1", role: "user" }
];

// Configure OAuth 2.0 with Google
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
}, (accessToken, refreshToken, profile, done) => {
    let user = users.find(u => u.googleId === profile.id);
    if (!user) {
        user = { id: users.length + 1, googleId: profile.id, username: profile.displayName, role: "user" };
        users.push(user);
    }
    return done(null, user);
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    const user = users.find(u => u.id === id);
    done(null, user);
});

// Middleware to check authentication
const authenticateOAuth = (req, res, next) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: "Access Denied" });
    next();
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

// OAuth 2.0 Authentication Routes
app.get("/auth/google",
    passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
    passport.authenticate("google", { failureRedirect: "/" }),
    (req, res) => {
        res.redirect("/dashboard");
    }
);

// Logout Route
app.get("/logout", (req, res) => {
    req.logout(() => {});
    res.json({ message: "Logged out successfully" });
});

// Public Route
app.get("/", (req, res) => {
    res.json({ message: "Welcome to the Secure Cyber Security Lab API" });
});

// Protected Routes
app.get("/dashboard", authenticateOAuth, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}, you are logged in!`, user: req.user });
});

// Fetch Users (Authenticated users only)
app.get("/users", authenticateOAuth, (req, res) => {
    res.json(users.map(user => ({ id: user.id, username: user.username, role: user.role })));
});

// Add User (Admins only)
app.post("/users", authenticateOAuth, requireRole("admin"), (req, res) => {
    const { username, googleId, role } = req.body;
    if (!username || !googleId || !["admin", "user"].includes(role)) {
        return res.status(400).json({ error: "Invalid input" });
    }
    const newUser = { id: users.length + 1, username, googleId, role };
    users.push(newUser);
    res.status(201).json({ message: "User added successfully" });
});

// Start Server
const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
