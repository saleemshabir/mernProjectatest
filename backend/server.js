require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dns = require("dns");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Event = require("./models/Event");
const User = require("./models/User");
const authMiddleware = require("./middleware/authMiddleware");

const app = express();

app.use(cors());
app.use(express.json());

dns.setServers(["8.8.8.8"]);

// ===============================
// ENV CHECK
// ===============================

console.log("JWT_SECRET loaded:", !!process.env.JWT_SECRET);

// ===============================
// MONGODB CONNECTION
// ===============================

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB Connected Successfully!");
    })
    .catch((error) => {
        console.log("MongoDB Connection Error:");
        console.log(error.message);
    });

// ===============================
// HOME
// ===============================

app.get("/", (req, res) => {
    res.json({
        message: "Backend is working"
    });
});

// ===============================
// AUTH MIDDLEWARE
// ===============================

function verifyToken(req, res, next) {

    try {

        const authHeader = req.headers.authorization;

        console.log("Authorization Header:", authHeader);

        if (!authHeader) {
            return res.status(401).json({
                message: "Token is missing"
            });
        }

        if (!authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Invalid authorization format. Use Bearer token."
            });
        }

        const token = authHeader.split(" ")[1];

        if (!token) {
            return res.status(401).json({
                message: "Token is missing"
            });
        }

        if (!process.env.JWT_SECRET) {
            console.log("JWT_SECRET is missing!");

            return res.status(500).json({
                message: "JWT_SECRET is missing in .env"
            });
        }

        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        console.log("Decoded Token:", decoded);

        req.user = decoded;

        next();

    } catch (error) {

        console.log("Token Verification Error:");
        console.log(error.message);

        return res.status(401).json({
            message: "Invalid token",
            error: error.message
        });
    }
}

// ===============================
// EVENTS
// ===============================

app.get("/api/events", async (req, res) => {

    try {

        const events = await Event.find();

        res.status(200).json(events);

    } catch (error) {

        res.status(500).json({
            message: "Error fetching events",
            error: error.message
        });
    }
});

// ===============================
// ADD EVENT
// ===============================

app.post("/api/events",authMiddleware, async (req, res) => {

    try {

        const newEvent = await Event.create(req.body);

        res.status(201).json({
            message: "Event Added Successfully!",
            event: newEvent
        });

    } catch (error) {

        res.status(500).json({
            message: "Error adding event",
            error: error.message
        });
    }
});

// ===============================
// UPDATE EVENT
// ===============================

app.put("/api/events/:id",authMiddleware, async (req, res) => {

    try {

        const updatedEvent =
            await Event.findByIdAndUpdate(
                req.params.id,
                req.body,
                { new: true }
            );

        if (!updatedEvent) {

            return res.status(404).json({
                message: "Event Not Found!"
            });
        }

        res.status(200).json({
            message: "Event Updated Successfully!",
            event: updatedEvent
        });

    } catch (error) {

        res.status(500).json({
            message: "Error updating event",
            error: error.message
        });
    }
});

// ===============================
// DELETE EVENT
// ===============================

app.delete("/api/events/:id",authMiddleware, async (req, res) => {

    try {

        const deletedEvent =
            await Event.findByIdAndDelete(
                req.params.id
            );

        if (!deletedEvent) {

            return res.status(404).json({
                message: "Event Not Found!"
            });
        }

        res.status(200).json({
            message: "Event Deleted Successfully"
        });

    } catch (error) {

        res.status(500).json({
            message: "Error deleting event",
            error: error.message
        });
    }
});

// ===============================
// REGISTER
// ===============================

app.post("/api/register", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        if (!name || !email || !password) {

            return res.status(400).json({
                message:
                    "Name, email and password are required!"
            });
        }

        const cleanEmail =
            email.trim().toLowerCase();

        const existingUser =
            await User.findOne({
                email: cleanEmail
            });

        if (existingUser) {

            return res.status(400).json({
                message: "User already exists!"
            });
        }

        const hashedPassword =
            await bcrypt.hash(password, 10);

        const newUser = new User({
            name: name.trim(),
            email: cleanEmail,
            password: hashedPassword
        });

        await newUser.save();

        console.log(
            "User registered:",
            newUser.email
        );

        res.status(201).json({

            message:
                "User Registered Successfully!",

            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email
            }
        });

    } catch (error) {

        console.log(
            "Registration Error:",
            error.message
        );

        res.status(500).json({
            message: "Registration failed",
            error: error.message
        });
    }
});

// ===============================
// LOGIN
// ===============================

app.post("/api/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        console.log("Login request received");

        // Check input
        if (!email || !password) {

            return res.status(400).json({
                message:
                    "Email and password are required!"
            });
        }

        // Check JWT secret
        if (!process.env.JWT_SECRET) {

            console.log(
                "ERROR: JWT_SECRET is missing"
            );

            return res.status(500).json({
                message:
                    "JWT_SECRET is missing in .env"
            });
        }

        const cleanEmail =
            email.trim().toLowerCase();

        // Find user
        const user =
            await User.findOne({
                email: cleanEmail
            });

        if (!user) {

            console.log(
                "User not found:",
                cleanEmail
            );

            return res.status(401).json({
                message:
                    "Invalid Email or Password!"
            });
        }

        console.log(
            "User found:",
            user.email
        );

        // Compare password
        const passwordMatch =
            await bcrypt.compare(
                password,
                user.password
            );

        if (!passwordMatch) {

            console.log(
                "Password does not match"
            );

            return res.status(401).json({
                message:
                    "Invalid Email or Password!"
            });
        }

        console.log(
            "Password matched successfully"
        );

        // ===============================
        // GENERATE TOKEN
        // ===============================

        const token = jwt.sign(

            {
                userId: user._id.toString(),
                email: user.email
            },

            process.env.JWT_SECRET,

            {
                expiresIn: "1h"
            }
        );

        console.log(
            "JWT generated successfully"
        );

        console.log(
            "Token:",
            token
        );

        // ===============================
        // SEND TOKEN
        // ===============================

        return res.status(200).json({

            message:
                "Login Successful!",

            token: token,

            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });

    } catch (error) {

        console.log(
            "Login Error:",
            error.message
        );

        return res.status(500).json({

            message:
                "Login failed",

            error:
                error.message
        });
    }
});

// ===============================
// PROTECTED TEST ROUTE
// ===============================

app.get(
    "/api/protected",
    verifyToken,
    (req, res) => {

        res.status(200).json({

            message:
                "You accessed a protected route!",

            user:
                req.user
        });
    }
);

// ===============================
// TEST TOKEN
// ===============================

app.get("/api/test-token", (req, res) => {

    try {

        if (!process.env.JWT_SECRET) {

            return res.status(500).json({
                message:
                    "JWT_SECRET is missing"
            });
        }

        const token = jwt.sign(

            {
                test: "hello"
            },

            process.env.JWT_SECRET,

            {
                expiresIn: "1h"
            }
        );

        res.status(200).json({

            message:
                "Token generated successfully",

            token: token
        });

    } catch (error) {

        res.status(500).json({

            message:
                "Token generation failed",

            error:
                error.message
        });
    }
});

// ===============================
// START SERVER
// ===============================

const PORT =
    process.env.PORT || 5000;

app.listen(PORT, () => {

    console.log(
        `Server is running on port ${PORT}`
    );

});