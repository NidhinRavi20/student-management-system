const express = require('express');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());

app.use(express.static('frontend'))

const secretkey = 'jwtSecretKey@123';

const studentDB = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Nidhin@123',
  database: 'students_db'
});

const principalDB = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'Nidhin@123',
  database: 'principal_db'
});

studentDB.connect(err => {
  if (err) throw err;
  console.log('Connected to student database');
});

principalDB.connect(err => {
  if (err) throw err;
  console.log('Connected to principal database');
});

// Middleware to verify token
function verifyToken(req, res, next) {
  const bearerHeader = req.headers['authorization'];
  if (typeof bearerHeader !== 'undefined') {
    const token = bearerHeader.split(' ')[1];
    req.token = token;
    jwt.verify(token, 'secretkey', (err, authData) => {
      if (err) {
        res.sendStatus(403);
      } else {
        next();
      }
    });
  } else {
    res.sendStatus(403);
  }
}

// Principal signup
app.post('/api/signup', (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 10);
  principalDB.query('INSERT INTO principals SET ?', { email, password: hashedPassword }, (err, result) => {
    if (err) return res.status(400).json({ msg: 'Error creating principal' });
    res.json({ msg: 'Principal created' });
  });
});

// Principal login
app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  principalDB.query('SELECT * FROM principals WHERE email = ?', [email], (err, results) => {
    if (err || results.length === 0) return res.status(400).json({ msg: 'Invalid credentials' });

    const principal = results[0];
    const isMatch = bcrypt.compareSync(password, principal.password);
    if (!isMatch) return res.status(400).json({ msg: 'Invalid credentials' });

    const token = jwt.sign({ id: principal.id }, 'secretkey', { expiresIn: '1h' });
    res.json({ token });
  });
});

// Add a new student
app.post('/api/students', verifyToken, (req, res) => {
  const { name, age, email, department } = req.body;
  studentDB.query('INSERT INTO students SET ?', { name, age, email, department }, (err, result) => {
    if (err) return res.status(400).json({ msg: 'Error adding student' });
    res.json({ msg: 'Student added' });
  });
});

// Get all students
app.get('/api/students', verifyToken, (req, res) => {
  studentDB.query('SELECT * FROM students', (err, results) => {
    if (err) return res.status(400).json({ msg: 'Error fetching students' });
    res.json(results);
  });
});

// Update student
app.put('/api/students/:id', verifyToken, (req, res) => {
  const { name, age, email, department } = req.body;
  studentDB.query('UPDATE students SET name=?, age=?, email=?, department=? WHERE id=?', 
    [name, age, email, department, req.params.id], (err, result) => {
      if (err) return res.status(400).json({ msg: 'Error updating student' });
      res.json({ msg: 'Student updated' });
    });
});

// Delete student
app.delete('/api/students/:id', verifyToken, (req, res) => {
  studentDB.query('DELETE FROM students WHERE id=?', [req.params.id], (err, result) => {
    if (err) return res.status(400).json({ msg: 'Error deleting student' });
    res.json({ msg: 'Student deleted' });
  });
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
