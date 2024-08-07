const express = require("express");
const app = express();
const pg = require("pg");
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

app.get("/", async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM "users"');
    console.log(result.rows[0]);
    res.json(result.rows[0]);
  } catch (e) {
    console.log(e);
  }
});

app.post("/", async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await db.query(
      'INSERT INTO "user"(email,password) values($1,$2) RETURNING *',
      [email, password]
    );
    console.log(result);
    res.json(result);
  } catch (e) {
    console.log(e);
  }
});
app.put("/:id", async (req, res) => {
  const id = req.params.id;
  const { email, password } = req.body;
  try {
    const result = await db.query(
      'UPDATE "user" SET email=$1 ,password=$2 where id=$3 RETURNING *',
      [email, password, id]
    );
    console.log(result.rows[0]);
    res.json(result.rows[0]);
  } catch (error) {
    console.log(error);
  }
});

app.delete("/:id", async (req, res) => {
  const id = req.params.id;
  try {
    const result = await db.query(
      'DELETE FROM "user" where id=$1 RETURNING *',
      [id]
    );
    res.json(result);
  } catch (e) {
    console.log(e);
  }
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});
