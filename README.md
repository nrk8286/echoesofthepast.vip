# Echoes of the Past

This repository contains a static login/marketplace interface and an unfinished Express server prototype. CI checks JavaScript syntax and the presence of the static files. It does not build or deploy the application.

The former Webpack/Cloudflare workflow could not run: the repository has no package manifest, lockfile, Webpack configuration, or Worker entry point, and its deploy step combined incompatible `uses` and `run` keys. The Express server cannot be published directly as a Cloudflare Worker.

Before enabling a deployment, define the supported server environment, add and verify its dependency manifest, replace the hardcoded demonstration administrator and signing-key fallback, implement persistent users/artifacts, and add authentication and authorization tests. The current MongoDB connection does not persist the in-memory user or artifact arrays.

Copy `.env.example` to an ignored local `.env` only when developing the server. The previously tracked `.env` has been removed from version control; any real credentials that appeared in it should be rotated because removing a file does not remove earlier Git history. Store production secrets in the deployment platform's secret manager.
