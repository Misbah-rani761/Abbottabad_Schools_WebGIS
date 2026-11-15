
const express = require("express");
const { Pool } = require("pg");
const path = require("path");
const cors = require("cors");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
require("dotenv").config({
    path: path.resolve(__dirname, "../.env")
});

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

const frontendPath = path.resolve(__dirname, "../frontend");

// Admin settings
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

if (!ADMIN_USERNAME || !ADMIN_PASSWORD || !JWT_SECRET) {
    throw new Error("Admin credentials missing in .env file");
}

const adminPasswordHash = bcrypt.hashSync(ADMIN_PASSWORD, 12);

// Database connection
const pool = new Pool({
    user: "postgres",
    host: "localhost",
    database: "abbottabad_schools_db",
    password: "1234",
    port: 5432
});

// Authentication middleware
function authorizeAdmin(req, res, next) {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Please login as admin first"
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);

        if (decoded.role !== "admin") {
            return res.status(403).json({
                error: "Admin access required"
            });
        }

        next();

    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired login session"
        });
    }
}

// Home page
app.get("/", (req, res) => {
    res.sendFile(path.join(frontendPath, "index.html"));
});

// Admin login
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            username !== ADMIN_USERNAME ||
            typeof password !== "string" ||
            !(await bcrypt.compare(password, adminPasswordHash))
        ) {
            return res.status(401).json({
                error: "Invalid username or password"
            });
        }

        const token = jwt.sign(
            { username: ADMIN_USERNAME, role: "admin" },
            JWT_SECRET,
            { expiresIn: "8h" }
        );

        res.json({
            message: "Admin login successful",
            token
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Login failed" });
    }
});

// Get all schools (Public)
app.get("/api/schools", async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT id, school_name, school_type, address,
                   latitude, longitude,
                   ST_AsGeoJSON(location)::json AS geometry
            FROM schools
            ORDER BY id
        `);

        res.json(result.rows);

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Could not fetch schools" });
    }
});

// Add new school (Admin only)
app.post("/api/schools", authorizeAdmin, async (req, res) => {
    try {
        const {
            school_name,
            school_type,
            address,
            latitude,
            longitude
        } = req.body;

        if (!school_name || !school_type ||
            latitude === undefined || longitude === undefined ||
            !Number.isFinite(Number(latitude)) ||
            !Number.isFinite(Number(longitude)) ||
            Number(latitude) < -90 || Number(latitude) > 90 ||
            Number(longitude) < -180 || Number(longitude) > 180) {
            return res.status(400).json({
                error: "Valid school name, type and coordinates are required"
            });
        }

        const result = await pool.query(`
            INSERT INTO schools
            (school_name, school_type, address, latitude, longitude, location)
            VALUES ($1, $2, $3, $4, $5,
            ST_SetSRID(ST_MakePoint($5, $4), 4326))
            RETURNING *
        `, [
            school_name,
            school_type,
            address || "",
            Number(latitude),
            Number(longitude)
        ]);

        res.status(201).json({
            message: "School added successfully",
            school: result.rows[0]
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Could not add school" });
    }
});

// Update school (Admin only)
app.put("/api/schools/:id", authorizeAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const {
            school_name,
            school_type,
            address,
            latitude,
            longitude
        } = req.body;

        if (!Number.isInteger(Number(id)) ||
            !school_name || !school_type ||
            !Number.isFinite(Number(latitude)) ||
            !Number.isFinite(Number(longitude)) ||
            Number(latitude) < -90 || Number(latitude) > 90 ||
            Number(longitude) < -180 || Number(longitude) > 180) {
            return res.status(400).json({
                error: "Valid school details are required"
            });
        }

        const result = await pool.query(`
            UPDATE schools
            SET school_name = $1,
                school_type = $2,
                address = $3,
                latitude = $4,
                longitude = $5,
                location = ST_SetSRID(ST_MakePoint($5, $4), 4326)
            WHERE id = $6
            RETURNING *
        `, [
            school_name,
            school_type,
            address || "",
            Number(latitude),
            Number(longitude),
            Number(id)
        ]);

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "School not found"
            });
        }

        res.json({
            message: "School updated successfully",
            school: result.rows[0]
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Could not update school" });
    }
});

// Delete school (Admin only)
app.delete("/api/schools/:id", authorizeAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            "DELETE FROM schools WHERE id = $1 RETURNING id",
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({
                error: "School not found"
            });
        }

        res.json({
            message: "School deleted successfully"
        });

    } catch (error) {
        console.error(error);
        res.status(500).json({
            error: "Could not delete school"
        });
    }
});

// Serve frontend files
app.use(express.static(frontendPath));

// Start server
async function startServer() {
    try {
        const client = await pool.connect();
        console.log("Database connected successfully!");
        client.release();

        console.log(
            "Frontend file exists:",
            fs.existsSync(path.join(frontendPath, "index.html"))
        );

        app.listen(PORT, "127.0.0.1", () => {
            console.log(`Server running at http://localhost:${PORT}`);
        });

    } catch (error) {
        console.error("Database connection failed:", error.message);
    }
}

startServer();
