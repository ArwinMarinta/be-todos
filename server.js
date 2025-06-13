const express = require("express");
const bcrypt = require("bcrypt");
const app = express();
const db = require("./prisma/connection");
const jwt = require("jsonwebtoken");
const cors = require("cors");

app.use(express.json());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) {
    return res.status(401).json({ message: "Token is required" });
  }

  const token = authHeader.split(" ")[1];

  jwt.verify(token, "papb_bisdig", (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  const existingUser = await db.user.findUnique({ where: { email } });
  if (existingUser) {
    return res.status(400).json({ message: "Email already in use" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = await db.user.create({
    data: {
      name,
      email,
      password: hashedPassword,
    },
  });

  res.status(201).json({ message: "User registered", user: { id: user.id, name: user.name, email: user.email } });
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await db.user.findUnique({ where: { email } });
  if (!user) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) {
    return res.status(400).json({ message: "Invalid email or password" });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
    },
    "papb_bisdig"
  );

  res.json({
    message: "Login successful",
    token,
    user: { id: user.id, name: user.name, email: user.email },
  });
});

// CREATE TODO
app.post("/todos", authenticateToken, async (req, res) => {
  const { title, description, complated = false } = req.body;
  const userId = req.user.id;

  try {
    if (!userId) {
      return res.status(401).json({ message: "User not found or unauthorized" });
    }
    const todo = await db.todos.create({
      data: {
        title,
        description,
        complated,
        userId,
      },
    });
    res.status(201).json(todo);
  } catch (error) {
    res.status(500).json({ message: "Failed to create todo", error: error.message });
  }
});

// READ TODOS milik user
app.get("/todos", authenticateToken, async (req, res) => {
  const userId = req.user.id;

  try {
    const todos = await db.todos.findMany({
      where: { userId },
      orderBy: { createdAt: "desc" },
    });
    res.json({ message: "success", data: todos });
  } catch (error) {
    res.status(500).json({ message: "Failed to fetch todos", error: error.message });
  }
});

// UPDATE TODO berdasarkan ID dan userId
app.put("/todos/:id", authenticateToken, async (req, res) => {
  const todoId = parseInt(req.params.id);
  const userId = req.user.id;
  const { title, description, complated } = req.body;

  try {
    const todo = await db.todos.findUnique({ where: { id: todoId } });
    if (!todo || todo.userId !== userId) {
      return res.status(404).json({ message: "Todo not found" });
    }

    const updatedTodo = await db.todos.update({
      where: { id: todoId },
      data: {
        title,
        description,
        complated,
      },
    });

    res.json({ message: "success", data: updatedTodo });
  } catch (error) {
    res.status(500).json({ message: "Failed to update todo", error: error.message });
  }
});

app.delete("/todos/:id", authenticateToken, async (req, res) => {
  const todoId = parseInt(req.params.id);
  const userId = req.user.id;

  try {
    const todo = await db.todos.findUnique({ where: { id: todoId } });
    if (!todo || todo.userId !== userId) {
      return res.status(404).json({ message: "Todo not found" });
    }

    await db.todos.delete({ where: { id: todoId } });
    res.json({ status: "success", message: "Todo berhasil di hapus" });
  } catch (error) {
    res.status(500).json({ message: "Failed to delete todo", error: error.message });
  }
});

app.get("/test", async (req, res) => {
  return res.status(200).send("Connect Success");
});

app.listen(3000, () => {
  console.log("Server berjalan di http://localhost:3000");
});
