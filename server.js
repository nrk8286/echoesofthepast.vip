require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';

app.use(cors());
app.use(bodyParser.json());

const users = [{ username: 'admin', password: 'password123' }];

const artifacts = [
    { name: 'Ancient Sword', description: 'A sword from the medieval era.' },
    { name: 'Golden Vase', description: 'A beautiful golden vase with engravings.' },
    { name: 'Mystic Scroll', description: 'A scroll containing mysterious writings.' }
];

app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find(u => u.username === username && u.password === password);
    if (user) {
        const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

app.get('/api/market', (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        jwt.verify(token, SECRET_KEY);
        res.json(artifacts);
    } catch {
        res.status(403).json({ message: 'Invalid token' });
    }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
require('dotenv').config();

const dbHost = process.env.DB_HOST;
const apiKey = process.env.API_KEY;
// Now you can use these variables in your application

