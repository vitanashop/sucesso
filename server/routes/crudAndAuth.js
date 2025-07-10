
import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import database from './database/connection.js';

const router = express.Router();
const db = new database();

// Middleware para verificar o token JWT
const authenticateToken = (req, res, next) => {
  const token = req.header('Authorization') && req.header('Authorization').replace('Bearer ', '');
  if (!token) return res.status(403).send('Acesso negado');

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Token inválido');
    req.user = user;
    next();
  });
};

// CRUD - Criar um novo item
router.post('/items', authenticateToken, async (req, res) => {
  const { name, description } = req.body;
  try {
    const [result] = await db.pool.execute(
      'INSERT INTO items (name, description) VALUES (?, ?)',
      [name, description]
    );
    res.status(201).json({ id: result.insertId, name, description });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao criar item' });
  }
});

// CRUD - Ler todos os itens
router.get('/items', authenticateToken, async (req, res) => {
  try {
    const [rows] = await db.pool.execute('SELECT * FROM items');
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar itens' });
  }
});

// CRUD - Atualizar um item
router.put('/items/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { name, description } = req.body;
  try {
    const [result] = await db.pool.execute(
      'UPDATE items SET name = ?, description = ? WHERE id = ?',
      [name, description, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Item não encontrado' });
    }
    res.json({ id, name, description });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar item' });
  }
});

// CRUD - Deletar um item
router.delete('/items/:id', authenticateToken, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.pool.execute('DELETE FROM items WHERE id = ?', [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Item não encontrado' });
    }
    res.json({ message: 'Item deletado com sucesso' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao deletar item' });
  }
});

// Rota para registrar um usuário
router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const [result] = await db.pool.execute(
      'INSERT INTO users (username, password) VALUES (?, ?)',
      [username, hashedPassword]
    );
    res.status(201).json({ message: 'Usuário registrado com sucesso' });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao registrar usuário' });
  }
});

// Rota para login do usuário
router.post('/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const [rows] = await db.pool.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(400).json({ error: 'Usuário não encontrado' });
    }

    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Senha incorreta' });
    }

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '1h',
    });

    res.json({ message: 'Login bem-sucedido', token });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao realizar login' });
  }
});

export default router;
