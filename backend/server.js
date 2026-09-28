require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const dns = require("dns");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Event = require("./models/Event");
const User = require("./models/User");

const app = express();

app.use(cors());
app.use(express.json());

dns.setServers(["8.8.8.8"]);

// =======================
// MongoDB Connection
// =======================

mongoose
    .connect(process.env.MONGO_URI)
    .then(() => {
        console.log("MongoDB Connected Successfully!");
    })
    .catch((error) => {
        console.log("MongoDB Connection Error:", error);
    });

// =======================
// Home Route
// =======================

app.get("/", (req, res) => {
    res.send("Backend is working");
});

// =======================
// GET ALL EVENTS
// =======================

app.get("/api/events", async (req, res) => {
    try {
        const events = await Event.find();

        res.json(events);
    } catch (error) {
        res.status(500).json({
            message: "Error fetching events",
            error: error.message
        });
    }
});

// =======================
// DELETE EVENT
// =======================

app.delete("/api/events/:id", async (req, res) => {
    try {
        const deletedEvent = await Event.findByIdAndDelete(
            req.params.id
        );

        if (!deletedEvent) {
            return res.status(404).json({
                message: "Event Not Found!"
            });
        }

        res.json({
            message: "Event Deleted Successfully"
        });
    } catch (error) {
        res.status(500).json({
            message: "Error deleting event",
            error: error.message
        });
    }
});

// =======================
// ADD EVENT
// =======================

app.post("/api/events", async (req, res) => {
    try {
        const newEvent = await Event.create(req.body);

        res.json({
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

// =======================
// UPDATE EVENT
// =======================

app.put("/api/events/:id", async (req, res) => {
    try {
        const updatedEvent = await Event.findByIdAndUpdate(
            req.params.id,
            req.body,
            { new: true }
        );

        if (!updatedEvent) {
            return res.status(404).json({
                message: "Event Not Found!"
            });
        }

        res.json({
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

// =======================
// REGISTER USER
// =======================

app.post("/api/register", async (req, res) => {
    try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
            return res.status(400).json({
                message: "Name, email and password are required!"
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(400).json({
                message: "User already exists!"
            });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({
            name,
            email,
            password: hashedPassword
        });

        await newUser.save();

        res.status(201).json({
            message: "User Registered Successfully!",
            user: {
                id: newUser._id,
                name: newUser.name,
                email: newUser.email
            }
        });
    } catch (error) {
        res.status(500).json({
            message: "Registration failed",
            error: error.message
        });
    }
});

// =======================
// LOGIN USER
// =======================

app.post("/api/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                message: "Email and password are required!"
            });
        }

        const user = await User.findOne({ email });

        if (!user) {
            return res.status(401).json({
                message: "Invalid Email or Password!"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid Email or Password!"
            });
        }

        // =======================
        // Generate JWT Token
        // =======================

        if (!process.env.JWT_SECRET) {
            return res.status(500).json({
                message: "JWT_SECRET is missing in .env file"
            });
        }

        const token = jwt.sign(
            {
                userId: user._id,
                email: user.email
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        // =======================
        // Send Response
        // =======================

        res.json({
            message: "Login Successful!",
            token: token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
            }
        });
    } catch (error) {
        console.log("Login Error:", error);

        res.status(500).json({
            message: "Login failed",
            error: error.message
        });
    }
});

// =======================
// START SERVER
// =======================

app.listen(5000, () => {
    console.log("Server is running on port 5000");
});