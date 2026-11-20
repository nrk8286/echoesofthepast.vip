# Echoes of the Past

This Node.js application serves the login/marketplace interface and its Express API from the same origin. Users and artifacts are stored in MongoDB. Artifact creation, editing, and deletion require an administrator token; ordinary registered users can browse the market.

## Run locally

Use Node.js 22 or later and a running MongoDB database. In PowerShell:

```powershell
npm ci
Copy-Item .env.example .env
node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"
```

Put the generated random value in `SECRET_KEY` in the ignored `.env`. Set `MONGODB_URI` to your database connection string, then run `npm start` and open `http://127.0.0.1:3000`. Set `HOST=0.0.0.0` when a container or hosting platform needs to reach the server. Production requires MongoDB and `NODE_ENV=production`.

To create the initial administrator, set both `ADMIN_USERNAME` (3–32 letters, numbers, or underscores) and `ADMIN_PASSWORD` (at least eight characters and no more than 72 UTF-8 bytes) before starting once. Existing accounts and passwords are never overwritten. Remove the bootstrap password after creating the account. There is no built-in administrator or default signing key.

`POST /api/register` accepts a JSON username and password and creates an ordinary user. `POST /api/login` returns a one-hour bearer token. `GET /api/market?page=1&limit=10` requires that token. Administrators can POST `/api/artifacts`, PUT `/api/artifacts/:name`, and DELETE `/api/artifacts/:name`; create/update bodies contain `name` and `description`. The public interface supports login, browsing, and logout; it does not implement checkout or purchasing.

`GET /api/health` checks the active store. Authentication is rate limited. API failures return JSON and database outages return HTTP 503. For disposable local work only, `DATA_STORE=memory` starts an empty store that loses all records on restart; production rejects that setting.

## Verify and host

Run `npm test` for HTTP tests covering registration, exact password handling, role enforcement, artifact CRUD, pagination, rate limits, private files, and configuration failures. CI runs these checks on Linux and Windows with Node.js 22 and 24. It validates changes without deploying them.

Deploy to a Node.js server or container with access to MongoDB. This Express server is not a Cloudflare Worker. Configure your production database, signing secret, HTTPS endpoint, and host binding before deploying. Local tests do not validate a hosted database or domain.

Copy `.env.example` to an ignored local `.env` only when developing the server. The previously tracked `.env` has been removed from version control; any real credentials that appeared in it should be rotated because removing a file does not remove earlier Git history. Store production secrets in the deployment platform's secret manager.
