const mongoose = require('mongoose');

async function createMongoStore(uri) {
    const connection = await mongoose.createConnection(uri, { serverSelectionTimeoutMS: 10000 }).asPromise();
    const User = connection.model('User', new mongoose.Schema({ username: { type: String, unique: true, required: true }, password: { type: String, required: true }, role: { type: String, enum: ['user', 'admin'], required: true } }));
    const Artifact = connection.model('Artifact', new mongoose.Schema({ name: { type: String, unique: true, required: true }, description: { type: String, required: true } }, { timestamps: true }));
    try { await Promise.all([User.init(), Artifact.init()]); }
    catch (error) { await connection.close(); throw error; }
    return {
        kind: 'mongodb',
        health: () => connection.db.command({ ping: 1 }),
        getUser: username => User.findOne({ username }).lean(),
        createUser: value => User.create(value),
        listArtifacts: (offset, limit) => Artifact.find().sort({ createdAt: 1, _id: 1 }).skip(offset).limit(limit).select('name description -_id').lean(),
        createArtifact: value => Artifact.create(value),
        updateArtifact: async (name, value) => (await Artifact.updateOne({ name }, { $set: value })).matchedCount > 0,
        deleteArtifact: async name => (await Artifact.deleteOne({ name })).deletedCount > 0,
        close: () => connection.close(),
    };
}

// Explicit local development/test storage. Production startup rejects this store.
function createMemoryStore() {
    const users = new Map(), artifacts = new Map();
    const duplicate = () => { const error = new Error('Duplicate'); error.code = 11000; throw error; };
    return {
        kind: 'memory', health: async () => {}, close: async () => {},
        getUser: async name => users.get(name),
        createUser: async value => { if (users.has(value.username)) duplicate(); users.set(value.username, { ...value }); },
        listArtifacts: async (offset, limit) => [...artifacts.values()].slice(offset, offset + limit).map(value => ({ ...value })),
        createArtifact: async value => { if (artifacts.has(value.name)) duplicate(); artifacts.set(value.name, { ...value }); },
        updateArtifact: async (name, value) => { if (!artifacts.has(name)) return false; if (value.name !== name && artifacts.has(value.name)) duplicate(); artifacts.delete(name); artifacts.set(value.name, { ...value }); return true; },
        deleteArtifact: async name => artifacts.delete(name),
    };
}
module.exports = { createMongoStore, createMemoryStore };
