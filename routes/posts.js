// posts.js
// Precondition: JWT verified by middleware
// Postcondition: CRUD inventory endpoints + purchase route with role validation

import express from "express";
import pool from "./db.js";

const router = express.Router();

/**
 * Admin-only middleware
 * Precondition: req.user exists
 * Postcondition: Allows route if role is admin, else 403 forbidden
 */
function authorizeAdmin(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({ message: "Forbidden: Admin privilege required" });
  }
  next();
}

/**
 * User-only middleware (Prevents Admin from accessing)
 * Precondition: req.user exists
 * Postcondition: Allows route if role is user, else 403 forbidden
 */
function authorizeUser(req, res, next) {
    // Check if the user is authenticated (which the main JWT middleware does)
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized: Must be logged in" });
    }
    // Check if the user is an admin
    if (req.user.role === "admin") {
      return res.status(403).json({ message: "Forbidden: Admins cannot make purchases" });
    }
    // Allow if not admin (i.e., 'user' role)
    next();
}


/**
 * Validate ID param
 * Precondition: req.params.id exists
 * Postcondition: id is valid positive integer or return 400
 */
function validateIdParam(req, res, next) {
  const id = parseInt(req.params.id);
  if (isNaN(id) || id <= 0) return res.status(400).json({ message: "Invalid item ID" });
  req.itemId = id;
  next();
}

// READ all items
router.get("/", async (req, res) => {
  const limit = parseInt(req.query.limit);
  try {
    const [rows] = await pool.query(
      limit > 0 ? "SELECT * FROM inventory LIMIT ?" : "SELECT * FROM inventory",
      limit > 0 ? [limit] : []
    );
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

// READ single item
router.get("/:id", validateIdParam, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM inventory WHERE item_id = ?", [req.itemId]);
    if (!rows.length) return res.status(404).json({ message: "Item not found" });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

// CREATE new item (Admin)
router.post("/", authorizeAdmin, async (req, res) => {
  const { id, name, stock, price } = req.body;
  if (!id || !name || stock === undefined) return res.status(400).json({ message: "Missing fields" });

  try {
    await pool.query("INSERT INTO inventory (item_id, item_name, stock, price) VALUES (?, ?, ?, ?)", [id, name, stock, price]);
    res.status(201).json({ id, name, stock, price, message: "Item added successfully" });
  } catch (err) {
    if (err.code === "ER_DUP_ENTRY") return res.status(400).json({ message: "ID already exists" });
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

// UPDATE item (Admin)
router.put("/:id", authorizeAdmin, validateIdParam, async (req, res) => {
  const { name, stock } = req.body;
  try {
    const [result] = await pool.query("UPDATE inventory SET item_name = ?, stock = ?, SET price = ? WHERE item_id = ?", [name, stock, price, req.itemId]);
    if (result.affectedRows === 0) return res.status(404).json({ message: "Item not found" });

    const [rows] = await pool.query("SELECT * FROM inventory WHERE item_id = ?", [req.itemId]);
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

// DELETE item (Admin)
router.delete("/:id", authorizeAdmin, validateIdParam, async (req, res) => {
  try {
    const [rows] = await pool.query("SELECT * FROM inventory WHERE item_id = ?", [req.itemId]);
    if (!rows.length) return res.status(404).json({ message: "Item not found" });

    await pool.query("DELETE FROM inventory WHERE item_id = ?", [req.itemId]);
    res.json({ message: "Item deleted successfully", item: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Database error" });
  }
});

// PURCHASE item (User Only)
router.post("/purchase/:id", authorizeUser, validateIdParam, async (req, res) => { // <--- Added authorizeUser here
  const { quantity: quantity } = req.body;
  const userId = req.user ? req.user.id : null;

  if (!quantity || quantity <= 0) return res.status(400).json({ message: "Invalid quantity" });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [updateResult] = await conn.query(
      "UPDATE inventory SET stock = stock - ? WHERE item_id = ? AND stock >= ?",
      [quantity, req.itemId, quantity]
    );

    if (updateResult.affectedRows === 0) {
      await conn.rollback();
      const [checkRows] = await conn.query("SELECT stock FROM inventory WHERE item_id = ?", [req.itemId]);
      if (!checkRows.length) return res.status(404).json({ message: "Item not found" });
      return res.status(400).json({ message: "Insufficient stock" });
    }

    await conn.query("INSERT INTO purchases (item_id, quantity, user_id) VALUES (?, ?, ?)", [req.itemId, quantity, userId]);
    await conn.commit();
    res.json({ message: `Purchase successful: ${quantity} units of item ${req.itemId}` });
  } catch (err) {
    await conn.rollback();
    console.error("Transaction Error:", err);
    res.status(500).json({ message: "Transaction failed" });
  } finally {
    conn.release();
  }
});

export default router;