import express from "express";
import dotenv from "dotenv";
import pool from "./db.js";

import authRoutes from "./routes/authRoutes.js";
import profileRoutes from "./routes/profileRoutes.js";
import passwordRoutes from "./routes/passwordRoutes.js";

dotenv.config();

const app = express();

const PORT = process.env.PORT || 5000;

app.use(express.json());

// TEST BACKEND
app.get("/", (req, res) => {
  res.json({
    message: "Backend Noxora berhasil berjalan!",
  });
});

// TEST DATABASE
app.get("/test-db", async (req, res) => {
  try {
    const result = await pool.query("SELECT NOW()");

    res.json({
      message: "Database berhasil terhubung!",
      time: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Database gagal terhubung",
    });
  }
});

// ROUTES
app.use("/", authRoutes);
app.use("/", profileRoutes);
app.use("/", passwordRoutes);

// MENJALANKAN SERVER
app.listen(PORT, () => {
  console.log(`Server berjalan di http://localhost:${PORT}`);
});
