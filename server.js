require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const morgan = require('morgan');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';

const DB_HOST = process.env.DB_HOST;
const DB_PORT = process.env.DB_PORT;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const DB_NAME = process.env.DB_NAME;

mongoose.connect(`mongodb://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((error) => {
    console.error('Error connecting to MongoDB:', error);
});

app.use(cors());
app.use(bodyParser.json());

// Logging
const accessLogStream = fs.createWriteStream(path.join(__dirname, 'access.log'), { flags: 'a' });
app.use(morgan('combined', { stream: accessLogStream }));

const users = [{ username: 'admin', password: bcrypt.hashSync('password123', 10), role: 'admin' }];

const artifacts = [
    { name: 'Ancient Sword', description: 'A sword from the medieval era.' },
    { name: 'Golden Vase', description: 'A beautiful golden vase with engravings.' },
    { name: 'Mystic Scroll', description: 'A scroll containing mysterious writings.' }
];

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

app.post('/api/login', loginLimiter, [
    body('username').isString().trim().escape(),
    body('password').isString().trim().escape()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const user = users.find(u => u.username === username);
    if (user && bcrypt.compareSync(password, user.password)) {
        const token = jwt.sign({ username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.post('/api/register', [
    body('username').isString().trim().escape(),
    body('password').isString().trim().escape()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;
    const hashedPassword = bcrypt.hashSync(password, 10);
    users.push({ username, password: hashedPassword, role: 'user' });
    res.status(201).json({ message: 'User registered successfully' });
});

const authenticateJWT = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.user = decoded;
        next();
    } catch {
        res.status(403).json({ message: 'Invalid token' });
    }
};

const authorizeRole = (role) => {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ message: 'Access denied' });
        }
        next();
    };
};

app.get('/api/market', authenticateJWT, (req, res) => {
    res.json(artifacts);
});

app.post('/api/artifacts', authenticateJWT, authorizeRole('admin'), [
    body('name').isString().trim().escape(),
    body('description').isString().trim().escape()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, description } = req.body;
    artifacts.push({ name, description });
    res.status(201).json({ message: 'Artifact created successfully' });
});

app.put('/api/artifacts/:name', authenticateJWT, authorizeRole('admin'), [
    body('name').isString().trim().escape(),
    body('description').isString().trim().escape()
], (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const { name, description } = req.body;
    const artifact = artifacts.find(a => a.name === req.params.name);
    if (artifact) {
        artifact.name = name;
        artifact.description = description;
        res.json({ message: 'Artifact updated successfully' });
    } else {
        res.status(404).json({ message: 'Artifact not found' });
    }
});

app.delete('/api/artifacts/:name', authenticateJWT, authorizeRole('admin'), (req, res) => {
    const index = artifacts.findIndex(a => a.name === req.params.name);
    if (index !== -1) {
        artifacts.splice(index, 1);
        res.json({ message: 'Artifact deleted successfully' });
    } else {
        res.status(404).json({ message: 'Artifact not found' });
    }
});

app.get('/api/market', authenticateJWT, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;
    const startIndex = (page - 1) * limit;
    const endIndex = page * limit;

    const result = artifacts.slice(startIndex, endIndex);
    res.json(result);
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
