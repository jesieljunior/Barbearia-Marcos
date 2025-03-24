const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const bodyParser = require("body-parser");
require("dotenv").config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(bodyParser.json());

// Configuração do banco de dados
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Middleware para verificar autenticação
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) return res.status(401).json({ error: "Acesso negado" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Token inválido" });
    req.user = user;
    next();
  });
};

// Criar tabelas se não existirem
db.query(`
    CREATE TABLE IF NOT EXISTS barbers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL
    )
`);

db.query(`
    CREATE TABLE IF NOT EXISTS appointments (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(20) NOT NULL,
        email VARCHAR(255) NOT NULL,
        service VARCHAR(255) NOT NULL,
        date DATE NOT NULL,
        time TIME NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        cancelled BOOLEAN DEFAULT false
    )
`);

// Verificar se existe usuário admin e criar se não existir
db.query(
  "SELECT * FROM barbers WHERE username = ?",
  ["macielsbarberstudio@gmail.com"],
  (err, results) => {
    if (err) throw err;

    if (results.length === 0) {
      // Criar usuário admin com senha hash
      bcrypt.hash("admin123", 10, (err, hash) => {
        if (err) throw err;

        db.query(
          "INSERT INTO barbers (username, password, name) VALUES (?, ?, ?)",
          ["macielsbarberstudio@gmail.com", hash, "Administrador"],
          (err) => {
            if (err) throw err;
            console.log("Usuário admin criado com sucesso");
          }
        );
      });
    }
  }
);

// Rotas da API

// Login
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  db.query(
    "SELECT * FROM barbers WHERE username = ?",
    [username],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Erro no servidor" });

      if (results.length === 0) {
        return res.status(401).json({ error: "Usuário ou senha incorretos" });
      }

      const user = results[0];

      bcrypt.compare(password, user.password, (err, match) => {
        if (err) return res.status(500).json({ error: "Erro no servidor" });

        if (!match) {
          return res.status(401).json({ error: "Usuário ou senha incorretos" });
        }

        const token = jwt.sign(
          { id: user.id, username: user.username },
          process.env.JWT_SECRET,
          {
            expiresIn: "8h",
          }
        );
        res.json({ token, name: user.name });
      });
    }
  );
});

// Verificar disponibilidade de horário
app.get("/api/check-availability", (req, res) => {
  const { date, time } = req.query;

  if (!date || !time) {
    return res.status(400).json({ error: "Data e hora são obrigatórios" });
  }

  db.query(
    "SELECT * FROM appointments WHERE date = ? AND time = ? AND cancelled = false",
    [date, time],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Erro no servidor" });

      res.json({ available: results.length === 0 });
    }
  );
});

// Criar agendamento
app.post("/api/appointments", (req, res) => {
  const { name, phone, email, service, date, time } = req.body;

  if (!name || !phone || !email || !service || !date || !time) {
    return res.status(400).json({ error: "Preencha todos os campos" });
  }

  db.query(
    "SELECT * FROM appointments WHERE date = ? AND time = ? AND cancelled = false",
    [date, time],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Erro no servidor" });

      if (results.length > 0) {
        return res.status(409).json({ error: "Horário já ocupado" });
      }

      db.query(
        "INSERT INTO appointments (name, phone, email, service, date, time) VALUES (?, ?, ?, ?, ?, ?)",
        [name, phone, email, service, date, time],
        (err, result) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Erro ao salvar agendamento" });

          res.status(201).json({
            id: result.insertId,
            message: "Agendamento realizado com sucesso",
          });
        }
      );
    }
  );
});

// Listar agendamentos (requer autenticação)
app.get("/api/appointments", authenticateToken, (req, res) => {
  db.query(
    "SELECT * FROM appointments WHERE cancelled = false ORDER BY date, time",
    (err, results) => {
      if (err) return res.status(500).json({ error: "Erro no servidor" });

      res.json(results);
    }
  );
});

// Cancelar agendamento (requer autenticação)
app.put("/api/appointments/:id/cancel", authenticateToken, (req, res) => {
  const { id } = req.params;

  db.query(
    "UPDATE appointments SET cancelled = true WHERE id = ?",
    [id],
    (err) => {
      if (err)
        return res.status(500).json({ error: "Erro ao cancelar agendamento" });

      res.json({ message: "Agendamento cancelado com sucesso" });
    }
  );
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});
