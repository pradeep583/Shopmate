// app.js
import express from "express";
import bodyParser from "body-parser";
import pool from "./routes/db.js";
import jwt from "jsonwebtoken";
import path from "path";
import { fileURLToPath } from "url";
import postsRouter from "./routes/posts.js";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config();

const app = express();
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;
const REFRESH_TOKEN = process.env.REFRESH_TOKEN;

app.use(bodyParser.json());

// Serve static HTML
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
app.use(express.static(__dirname));

/** Signup Route */
app.post("/signup", async (req, res) => {
  
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required" });

  try {
    const [existing] = await pool.query(
      "SELECT id FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    if (existing.length) return res.status(400).json({ message: "Username already taken" });

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
      [username, hashedPassword, "user"]
    );

    res.status(201).json({ message: "Signup successful, please login" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

/** Login Route with refresh token */
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: "Username and password required" });

  try {
    const [rows] = await pool.query(
      "SELECT * FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    if (!rows.length) return res.status(401).json({ message: "Invalid username or password" });

    const user = rows[0];
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Invalid username or password" });

    const accessToken = jwt.sign({ id: user.id, role: user.role }, ACCESS_TOKEN, { expiresIn: "1h" });
    const refreshToken = jwt.sign({ id: user.id }, REFRESH_TOKEN, { expiresIn: "7d" });

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await pool.query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES (?, ?, ?)",
      [user.id, refreshToken, expiresAt]
    );

    res.json({ accessToken, refreshToken, role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

/** Refresh token route */
app.post("/refresh", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(401).json({ message: "No refresh token provided" });

  try {
    const payload = jwt.verify(token, REFRESH_TOKEN);
    const [rows] = await pool.query(
      "SELECT * FROM refresh_tokens WHERE user_id = ? AND token = ?",
      [payload.id, token]
    );
    if (!rows.length) return res.status(403).json({ message: "Invalid refresh token" });

    const [userRow] = await pool.query("SELECT * FROM users WHERE id = ?", [payload.id]);
    if (!userRow.length) return res.status(404).json({ message: "User not found" });

    const user = userRow[0];
    const accessToken = jwt.sign({ id: user.id, role: user.role }, ACCESS_TOKEN, { expiresIn: "1h" });

    res.json({ accessToken });
  } catch (err) {
    console.error(err);
    res.status(403).json({ message: "Invalid refresh token" });
  }
});

/** Logout Route */
app.post("/logout", async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ message: "No refresh token provided" });

  try {
    await pool.query("DELETE FROM refresh_tokens WHERE token = ?", [token]);
    res.json({ message: "Logged out successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

/** JWT Middleware */
function verifyToken(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth) return res.status(401).json({ message: "No token provided" });

  try {
    const token = auth.split(" ")[1];
    req.user = jwt.verify(token, ACCESS_TOKEN);
    next();
  } catch {
    res.status(403).json({ message: "Invalid token" });
  }
}

// Inventory routes (protected)
app.use("/inventory", verifyToken, postsRouter);

app.get("/", (req, res) => {
  res.send("ShopMate is Live");
});


const PORT = 3000;
app.listen(PORT, () => console.log(`Server running on ${PORT}`));

