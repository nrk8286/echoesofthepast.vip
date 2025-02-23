require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const xss = require('xss-clean');
const mongoSanitize = require('express-mongo-sanitize');
const winston = require('winston');

// Load environment variables
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'your_secret_key';
const DB_HOST = process.env.DB_HOST;
const DB_PORT = process.env.DB_PORT;
const DB_USER = process.env.DB_USER;
const DB_PASS = process.env.DB_PASS;
const DB_NAME = process.env.DB_NAME;

// Connect to MongoDB
mongoose.connect(`mongodb://${DB_USER}:${DB_PASS}@${DB_HOST}:${DB_PORT}/${DB_NAME}`, {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => {
    console.log('Connected to MongoDB');
}).catch((err) => {
    console.error('Failed to connect to MongoDB', err);
});

const app = express();

app.use(cors());
app.use(bodyParser.json());
app.use(helmet());
app.use(xss());
app.use(mongoSanitize());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use(limiter);

// Logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' })
    ]
});

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, default: 'user' }
});
const User = mongoose.model('User', userSchema);

// Artifact schema and model
const artifactSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String, required: true }
});
const Artifact = mongoose.model('Artifact', artifactSchema);

// Middleware for JWT authentication and authorization
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) return res.status(403).json({ message: 'Access denied' });

    try {
        const user = jwt.verify(token, SECRET_KEY);
        req.user = user;
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

// User registration endpoint
app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashedPassword });

    try {
        await user.save();
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Failed to register user', error: err.message });
    }
});

// User login endpoint
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ username: user.username, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({ token });
    } else {
        res.status(401).json({ message: 'Invalid credentials' });
    }
});

// Get artifacts endpoint with pagination
app.get('/api/market', authenticateToken, async (req, res) => {
    const { page = 1, limit = 10 } = req.query;
    const artifacts = await Artifact.find()
        .skip((page - 1) * limit)
        .limit(parseInt(limit));

    res.json(artifacts);
});

// Create artifact endpoint
app.post('/api/artifacts', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { name, description } = req.body;
    const artifact = new Artifact({ name, description });

    try {
        await artifact.save();
        res.status(201).json({ message: 'Artifact created successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Failed to create artifact', error: err.message });
    }
});

// Update artifact endpoint
app.put('/api/artifacts/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    const { name, description } = req.body;

    try {
        const artifact = await Artifact.findByIdAndUpdate(req.params.id, { name, description }, { new: true });
        res.json({ message: 'Artifact updated successfully', artifact });
    } catch (err) {
        res.status(400).json({ message: 'Failed to update artifact', error: err.message });
    }
});

// Delete artifact endpoint
app.delete('/api/artifacts/:id', authenticateToken, authorizeRole('admin'), async (req, res) => {
    try {
        await Artifact.findByIdAndDelete(req.params.id);
        res.json({ message: 'Artifact deleted successfully' });
    } catch (err) {
        res.status(400).json({ message: 'Failed to delete artifact', error: err.message });
    }
});

// Error logging middleware
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).json({ message: 'An error occurred', error: err.message });
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));
