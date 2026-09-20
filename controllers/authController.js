import bcrypt from "bcrypt";
import pool from "../db.js";

// REGISTRASI
export const register = async (req, res) => {
  try {
    const { username, email, phoneNumber, password, confirmPassword } =
      req.body;

    // Cek data wajib
    if (!username || !email || !password || !confirmPassword) {
      return res.status(400).json({
        message: "Data registrasi belum lengkap",
      });
    }

    // Password minimal 8 karakter
    if (password.length < 8) {
      return res.status(400).json({
        message: "Password minimal 8 karakter",
      });
    }

    // Cek konfirmasi password
    if (password !== confirmPassword) {
      return res.status(400).json({
        message: "Password dan konfirmasi password tidak sama",
      });
    }

    // Cek username atau email sudah terdaftar
    const existingUser = await pool.query(
      `SELECT user_id, username, email
       FROM users
       WHERE username = $1 OR email = $2`,
      [username, email],
    );

    if (existingUser.rows.length > 0) {
      const user = existingUser.rows[0];

      if (user.username === username) {
        return res.status(409).json({
          message: "Username sudah terdaftar",
        });
      }

      if (user.email === email) {
        return res.status(409).json({
          message: "Email sudah terdaftar",
        });
      }
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Simpan user
    const result = await pool.query(
      `INSERT INTO users 
        (username, email, "phoneNumber", password)
       VALUES ($1, $2, $3, $4)
       RETURNING user_id, username, email, "phoneNumber"`,
      [username, email, phoneNumber || null, hashedPassword],
    );

    res.status(201).json({
      message: "Registrasi berhasil",
      user: result.rows[0],
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Terjadi kesalahan pada server",
    });
  }
};

// LOGIN
export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Cek data wajib
    if (!email || !password) {
      return res.status(400).json({
        message: "Email dan password wajib diisi",
      });
    }

    // Cari user berdasarkan email
    const result = await pool.query(
      `SELECT user_id, username, email, "phoneNumber", password
       FROM users
       WHERE email = $1`,
      [email],
    );

    // User tidak ditemukan
    if (result.rows.length === 0) {
      return res.status(401).json({
        message: "Email atau password salah",
      });
    }

    const user = result.rows[0];

    // Cek password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({
        message: "Email atau password salah",
      });
    }

    // Login berhasil
    res.status(200).json({
      message: "Login berhasil",
      user: {
        user_id: user.user_id,
        username: user.username,
        email: user.email,
        phoneNumber: user.phoneNumber,
      },
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      message: "Terjadi kesalahan pada server",
    });
  }
};