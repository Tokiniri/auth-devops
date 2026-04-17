const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(express.json());
app.use(cors());

// 🔗 PostgreSQL connection
const pool = new Pool({
    host: "db",
    user: "postgres",
    password: "postgres",
    database: "auth_db",
    port: 5432
});

// 🧱 Create table
pool.query(`
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) UNIQUE NOT NULL,
    password TEXT NOT NULL
);
`);

// 🔐 REGISTER
app.post("/register", async (req, res) => {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
        await pool.query(
            "INSERT INTO users (email, password) VALUES ($1, $2)",
            [email, hashedPassword]
        );

        res.json({ message: "User created successfully" });
    } catch (err) {
        res.status(400).json({ error: "User already exists" });
    }
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const result = await pool.query(
        "SELECT * FROM users WHERE email = $1",
        [email]
    );

    if (result.rows.length === 0) {
        return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];

    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
        return res.status(400).json({ error: "Wrong password" });
    }

    const token = jwt.sign(
        { id: user.id, email: user.email },
        "SECRET_KEY",
        { expiresIn: "1h" }
    );

    res.json({ token });
});

// 🏠 HOME (protected simple)
app.get("/home", (req, res) => {
    res.json({ message: "Welcome to Home 🚀" });
});

app.listen(5000, () => {
    console.log("Backend running on port 5000");
});
