const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { rateLimit } = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const { createMongoStore, createMemoryStore } = require('./store');

function createApplication({ store, secret, loginLimit = 5 }) {
    if (!store) throw new Error('A data store is required');
    if (typeof secret !== 'string' || secret.length < 32) {
        throw new Error('SECRET_KEY must contain at least 32 characters');
    }
    const app = express();
    app.disable('x-powered-by');
    app.use(cors());
    app.use(express.json({ limit: '32kb' }));
    app.use('/api', (_req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });

    // Serve only public files; the server, data, and environment files stay private.
    for (const filename of ['index.html', 'market.html', 'script.js', 'styles.css']) {
        app.get('/' + filename, (_req, res) => res.sendFile(filename, { root: __dirname }));
    }
    app.get('/', (_req, res) => res.sendFile('index.html', { root: __dirname }));
    app.get('/api/health', async (_req, res) => {
        await store.health();
        res.json({ ok: true, storage: store.kind });
    });

    const credentialRules = [
        body('username').isString().trim().matches(/^[a-zA-Z0-9_]{3,32}$/),
        // Passwords must reach hashing unchanged; HTML escaping changes credentials.
        body('password').isString().isLength({ min: 8 }).custom(value => Buffer.byteLength(value, 'utf8') <= 72),
    ];
    const validate = (req, res, next) => {
        if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid input' });
        next();
    };
    const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: loginLimit, standardHeaders: 'draft-8', legacyHeaders: false });

    app.post('/api/register', authLimiter, credentialRules, validate, async (req, res) => {
        const username = req.body.username.toLowerCase();
        if (await store.getUser(username)) return res.status(409).json({ message: 'Username already exists' });
        await store.createUser({ username, password: await bcrypt.hash(req.body.password, 12), role: 'user' });
        res.status(201).json({ message: 'User registered successfully' });
    });
    app.post('/api/login', authLimiter, credentialRules, validate, async (req, res) => {
        const user = await store.getUser(req.body.username.toLowerCase());
        if (!user || !await bcrypt.compare(req.body.password, user.password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ username: user.username, role: user.role }, secret, { algorithm: 'HS256', expiresIn: '1h' });
        res.json({ token });
    });
    const authenticate = (req, res, next) => {
        const match = /^Bearer (.+)$/.exec(req.headers.authorization || '');
        if (!match) return res.status(403).json({ message: 'Access denied' });
        try { req.user = jwt.verify(match[1], secret, { algorithms: ['HS256'] }); next(); }
        catch { res.status(403).json({ message: 'Invalid token' }); }
    };
    const admin = (req, res, next) => {
        if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });
        next();
    };
    const artifactRules = [body('name').isString().trim().isLength({ min: 1, max: 120 }), body('description').isString().trim().isLength({ min: 1, max: 5000 })];
    app.get('/api/market', authenticate, async (req, res) => {
        const page = Number(req.query.page || 1), limit = Number(req.query.limit || 10);
        if (!Number.isSafeInteger(page) || page < 1 || !Number.isSafeInteger(limit) || limit < 1 || limit > 100 || !Number.isSafeInteger((page - 1) * limit)) {
            return res.status(400).json({ message: 'Invalid pagination' });
        }
        res.json(await store.listArtifacts((page - 1) * limit, limit));
    });
    app.post('/api/artifacts', authenticate, admin, artifactRules, validate, async (req, res) => {
        await store.createArtifact({ name: req.body.name, description: req.body.description });
        res.status(201).json({ message: 'Artifact created successfully' });
    });
    app.put('/api/artifacts/:name', authenticate, admin, artifactRules, validate, async (req, res) => {
        const changed = await store.updateArtifact(req.params.name, { name: req.body.name, description: req.body.description });
        res.status(changed ? 200 : 404).json({ message: changed ? 'Artifact updated successfully' : 'Artifact not found' });
    });
    app.delete('/api/artifacts/:name', authenticate, admin, async (req, res) => {
        const changed = await store.deleteArtifact(req.params.name);
        res.status(changed ? 200 : 404).json({ message: changed ? 'Artifact deleted successfully' : 'Artifact not found' });
    });
    app.use('/api', (_req, res) => res.status(404).json({ message: 'API route not found' }));
    app.use((error, _req, res, _next) => {
        if (error.code === 11000) return res.status(409).json({ message: 'Entry already exists' });
        if (error.type === 'entity.parse.failed') return res.status(400).json({ message: 'Invalid JSON' });
        if (error.type === 'entity.too.large') return res.status(413).json({ message: 'Request too large' });
        res.status(503).json({ message: 'Service temporarily unavailable' });
    });
    return app;
}

async function startServer(env = process.env) {
    if (!env.SECRET_KEY || env.SECRET_KEY.length < 32) throw new Error('Configure SECRET_KEY with at least 32 random characters');
    if (env.DATA_STORE === 'memory' && env.NODE_ENV === 'production') throw new Error('Production requires MongoDB persistence');
    let uri = env.MONGODB_URI;
    if (!uri && env.DB_HOST && env.DB_NAME) {
        const auth = env.DB_USER ? `${encodeURIComponent(env.DB_USER)}:${encodeURIComponent(env.DB_PASS || '')}@` : '';
        uri = `mongodb://${auth}${env.DB_HOST}:${env.DB_PORT || 27017}/${encodeURIComponent(env.DB_NAME)}`;
    }
    if (!uri && env.DATA_STORE !== 'memory') throw new Error('Configure MONGODB_URI or explicitly use DATA_STORE=memory for local development');
    const store = env.DATA_STORE === 'memory' ? createMemoryStore() : await createMongoStore(uri);
    try {
        if (env.ADMIN_USERNAME || env.ADMIN_PASSWORD) {
            if (!/^[a-zA-Z0-9_]{3,32}$/.test(env.ADMIN_USERNAME || '') || !env.ADMIN_PASSWORD || env.ADMIN_PASSWORD.length < 8 || Buffer.byteLength(env.ADMIN_PASSWORD) > 72) {
                throw new Error('Configure a valid bootstrap ADMIN_USERNAME and ADMIN_PASSWORD');
            }
            const username = env.ADMIN_USERNAME.toLowerCase();
            const existing = await store.getUser(username);
            if (existing && existing.role !== 'admin') throw new Error('Bootstrap admin username is already in use');
            if (!existing) await store.createUser({ username, password: await bcrypt.hash(env.ADMIN_PASSWORD, 12), role: 'admin' });
        }
        const app = createApplication({ store, secret: env.SECRET_KEY });
        const server = await new Promise((resolve, reject) => {
            const listener = app.listen(Number(env.PORT || 3000), env.HOST || '127.0.0.1', () => resolve(listener));
            listener.once('error', reject);
        });
        return { app, store, server };
    } catch (error) { await store.close(); throw error; }
}

if (require.main === module) {
    require('dotenv').config({ quiet: true });
    startServer().then(({ server, store }) => {
        console.log(`Marketplace listening on port ${server.address().port}`);
        const stop = () => server.close(async () => { await store.close(); process.exit(0); });
        process.once('SIGTERM', stop); process.once('SIGINT', stop);
    }).catch(error => { console.error(error.message.includes('Configure') || error.message.includes('Production requires') ? error.message : 'Marketplace startup failed; check database and account configuration.'); process.exitCode = 1; });
}
module.exports = { createApplication, startServer };
