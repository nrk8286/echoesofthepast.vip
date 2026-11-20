const { test } = require('node:test');
const assert = require('node:assert/strict');
const bcrypt = require('bcryptjs');
const { createApplication, startServer } = require('../server');
const { createMemoryStore } = require('../store');

const secret = 'test-only-signing-key-at-least-32-characters';
async function fixture(t, options = {}) {
    const store = createMemoryStore();
    const app = createApplication({ store, secret, loginLimit: 100, ...options });
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    t.after(() => new Promise(resolve => server.close(resolve)));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const request = (pathname, method = 'GET', body, token) => fetch(origin + pathname, {
        method,
        headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: body === undefined ? undefined : JSON.stringify(body),
    });
    return { store, request };
}

test('registration preserves passwords and cannot grant administrator privileges', async t => {
    const { store, request } = await fixture(t);
    const credentials = { username: 'New_User', password: ' <test & password> ', role: 'admin' };
    assert.equal((await request('/api/register', 'POST', credentials)).status, 201);
    const user = await store.getUser('new_user');
    assert.equal(user.role, 'user');
    assert.notEqual(user.password, credentials.password);
    assert.equal(await bcrypt.compare(credentials.password, user.password), true);
    assert.equal((await request('/api/register', 'POST', credentials)).status, 409);
    const response = await request('/api/login', 'POST', credentials);
    assert.equal(response.status, 200);
    const { token } = await response.json();
    assert.equal((await request('/api/market', 'GET', undefined, token)).status, 200);
    assert.equal((await request('/api/artifacts', 'POST', { name: 'one', description: 'test' }, token)).status, 403);
    assert.equal((await request('/api/login', 'POST', { ...credentials, password: credentials.password.trim() })).status, 401);
});

test('administrator CRUD, duplicate protection and pagination use the same store', async t => {
    const { store, request } = await fixture(t);
    const credentials = { username: 'owner', password: 'Disposable password!' };
    await store.createUser({ ...credentials, password: await bcrypt.hash(credentials.password, 4), role: 'admin' });
    const { token } = await (await request('/api/login', 'POST', credentials)).json();
    for (const name of ['first', 'second']) assert.equal((await request('/api/artifacts', 'POST', { name, description: 'description' }, token)).status, 201);
    assert.equal((await request('/api/artifacts', 'POST', { name: 'first', description: 'duplicate' }, token)).status, 409);
    assert.deepEqual(await (await request('/api/market?page=2&limit=1', 'GET', undefined, token)).json(), [{ name: 'second', description: 'description' }]);
    for (const query of ['page=0', 'limit=101', 'page=1.5', 'limit=abc']) assert.equal((await request('/api/market?' + query, 'GET', undefined, token)).status, 400);
    assert.equal((await request('/api/artifacts/first', 'PUT', { name: 'renamed', description: 'updated' }, token)).status, 200);
    assert.equal((await request('/api/artifacts/renamed', 'DELETE', undefined, token)).status, 200);
    assert.equal((await request('/api/artifacts/renamed', 'DELETE', undefined, token)).status, 404);
    assert.equal((await request('/api/market')).status, 403);
    assert.equal((await request('/api/market', 'GET', undefined, 'invalid')).status, 403);
});

test('serves the interface but keeps server files private and reports database failures', async t => {
    const { store, request } = await fixture(t);
    for (const pathname of ['/', '/index.html', '/market.html', '/script.js', '/styles.css']) assert.equal((await request(pathname)).status, 200);
    for (const pathname of ['/server.js', '/store.js', '/.env', '/package.json']) assert.equal((await request(pathname)).status, 404);
    assert.deepEqual(await (await request('/api/health')).json(), { ok: true, storage: 'memory' });
    store.health = async () => { throw new Error('private connection details'); };
    const failed = await request('/api/health');
    assert.equal(failed.status, 503);
    assert.deepEqual(await failed.json(), { message: 'Service temporarily unavailable' });
    assert.equal((await request('/api/missing')).status, 404);
});

test('limits authentication attempts', async t => {
    const { request } = await fixture(t, { loginLimit: 1 });
    const credentials = { username: 'missing', password: 'wrong-password' };
    assert.equal((await request('/api/login', 'POST', credentials)).status, 401);
    assert.equal((await request('/api/login', 'POST', credentials)).status, 429);
});

test('startup requires a signing key and production persistence', async () => {
    await assert.rejects(startServer({}), /SECRET_KEY/);
    await assert.rejects(startServer({ SECRET_KEY: secret }), /MONGODB_URI/);
    await assert.rejects(startServer({ SECRET_KEY: secret, DATA_STORE: 'memory', NODE_ENV: 'production' }), /Production requires MongoDB/);
});
