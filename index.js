const express = require("express");
const app = express();
const pg = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
require("dotenv").config();

app.use(express.json());

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

db.connect((err) => {
  if (err) {
    console.error("Connection error", err.stack);
  } else {
    console.log("Connected to the database");
  }
});

// JWT secret key
const JWT_SECRET = process.env.SECRET_KEY;

// Middleware for Authentication
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// GET req to retrieve users (with authentication)
app.get("/", authenticateToken, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM "user"');
    res.json(result.rows);
  } catch (e) {
    console.error(e);
    res.status(500).send("Error retrieving users");
  }
});

// POST for user login
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query('SELECT * FROM "user" WHERE email = $1', [
      email,
    ]);
    const user = result.rows[0];
    if (user && (await bcrypt.compare(password, user.password))) {
      const token = jwt.sign({ email: user.email, id: user.id }, JWT_SECRET, {
        expiresIn: "1h",
      });
      res.json({ token });
    } else {
      res.status(401).send("Invalid email or password");
    }
  } catch (e) {
    console.error(e);
    res.status(500).send("Error during login");
  }
});

// POST for user signup
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await db.query(
      'INSERT INTO "user"(email, password) VALUES ($1, $2) RETURNING *',
      [email, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (e) {
    console.error(e);
    res.status(500).send("Error during signup");
  }
});

// PUT route for updating user details (with authentication)
app.put("/:id", authenticateToken, async (req, res) => {
  const id = req.params.id;
  const { email, password } = req.body;
  try {
    const hashedPassword = password
      ? await bcrypt.hash(password, 10)
      : undefined; //hash the password 10 times/rounds and
    const result = await db.query(
      'UPDATE "user" SET email=$1, password=$2 WHERE id=$3 RETURNING *',
      [email, hashedPassword, id]
    );
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).send("User not found");
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error updating user");
  }
});

// DELETE route for deleting a user (with Authentication)
app.delete("/:id", authenticateToken, async (req, res) => {
  const id = req.params.id;
  try {
    const result = await db.query(
      'DELETE FROM "user" WHERE id=$1 RETURNING *',
      [id]
    );
    if (result.rows.length > 0) {
      res.json(result.rows[0]);
    } else {
      res.status(404).send("User not found");
    }
  } catch (e) {
    res.status(500).send("Error deleting user");
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
