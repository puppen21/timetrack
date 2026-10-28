# Timetrack for Wasmer (Express + PostgreSQL, with accounts)

The multi-user Timetrack, rewritten so it needs **no local files and no native add-ons**: only `express` and `pg`. All data (accounts, hours, login sessions, attempt limits) lives in a PostgreSQL database, so it works on hosts where the disk is wiped on every deploy and on hosts that run several copies of the app.

It was tested against a real PostgreSQL 16 database (with the same test suite as the SQLite version, plus extra checks). It was **not** tested on Wasmer itself, which runs Node.js apps in a beta (see "Check before you rely on it").

## Run it on your own computer first

You need Node 20+ and a PostgreSQL database.

```bash
npm install
# point it at your database, then start:
DATABASE_URL=postgres://user:password@localhost:5432/timetrack INSECURE_COOKIES=1 npm start
# Windows PowerShell:
#   $env:DATABASE_URL="postgres://user:password@localhost:5432/timetrack"; $env:INSECURE_COOKIES="1"; npm start
```

Open `http://localhost:3000`. Tables are created automatically at startup. `INSECURE_COOKIES=1` is only for testing over plain http: never use it on a public site.

## Deploy on Wasmer

1. Create the app from Wasmer's **Express starter template** (`wasmer deploy` from a project folder), then copy this project's files (`server.js`, `package.json`, `public/`) over it. Wasmer's own template decides the app config file, so keep its `app.yaml` and make sure the start command runs `node server.js`.
2. In the Wasmer dashboard, add the **managed PostgreSQL database** to the app (Wasmer offers MySQL or PostgreSQL, one per app: choose PostgreSQL).
3. Set the environment variables below. The server reads `DATABASE_URL` if present, otherwise `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USERNAME`, `DB_PASSWORD`, otherwise the standard `PG*` variables. Use whichever names Wasmer shows you for the database.
4. Make sure it listens on all interfaces: `HOST=0.0.0.0`, and `PORT` as Wasmer provides. Set `TRUST_PROXY=1` because Wasmer sits in front of the app.
5. Deploy, then open `https://your-app.wasmer.app/api/health`. It should answer `{"ok":true}`.

## Check before you rely on it

Wasmer's Node.js support is a beta that runs on a different engine than normal Node. These three things are unconfirmed:

- **Password hashing:** the server needs `crypto.scrypt`. At startup it tests this, and if the host does not support it, it stops with a clear message in the logs instead of running unsafely.
- **The `pg` driver:** it needs TCP connections to the database. If the health check fails but the app starts, this is the likely cause.
- **Express 5** in that runtime.

If the app will not start or `/api/health` fails, the same project runs unchanged on any host that offers Node 20+ and PostgreSQL. Only the environment variables differ.

## Settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `DATABASE_URL` | none | PostgreSQL connection string (see step 3 for alternatives) |
| `PGSSL` | unset | Set to `1` if the database requires TLS |
| `PORT` / `HOST` | 3000 / 127.0.0.1 | Where to listen (use `HOST=0.0.0.0` on a host) |
| `TRUST_PROXY` | unset | Set to `1` behind a reverse proxy, so limits use real client IPs |
| `REGISTRATION` | open | `closed` turns off sign-up |
| `MAX_USERS` | 10000 | Sign-up cap |
| `DB_POOL` | 5 | Database connections per app copy |
| `INSECURE_COOKIES` | unset | Testing only |

## How accounts work

- **Passwords** are stored only as salted scrypt hashes. Nobody can read them.
- **Sign-in** sets a random 30-day cookie (HttpOnly, Secure, SameSite=Lax). Only a hash of it is stored. Logging out, changing the password or recovering the account ends the other sign-ins.
- **Recovery codes:** each account gets 8 one-time codes at sign-up. There is no email, so a user who loses both password and codes cannot get back in. As the admin you can issue a temporary password with `npm run set-password -- <username>`.
- **Protection:** attempt limits (stored in the database, so they survive restarts and apply across all app copies), input validation, request-forgery checks on all writes, security headers, and a cap of 100,000 sessions per user.
- **Account tools in the app:** log out, change password, new recovery codes, delete account (removes all of that user's data).

## Limits and notes

- The free plan's database size cap (Wasmer lists 100 MB) is your user limit: one user's hours take a few KB per hundred sessions, so it holds a lot of users, but watch it.
- Back up the database with your provider's tools, or with `pg_dump`.
- Conflicts between two devices editing the same session at once are resolved by last writer wins.
- Before inviting the public: add a privacy policy, consider a CAPTCHA on sign-up (or `REGISTRATION=closed`), and check your obligations under Israeli privacy law and under GDPR for EU users. This is not legal advice.
