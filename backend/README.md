# Jairo Assistant — shared API (trial scaffold)

This is a **first backend milestone**, not a finished family app. The current GitHub Pages interface still uses browser-local data and **does not connect to this API yet**. No WhatsApp messages are sent.

## Railway
1. Add a **PostgreSQL** service to your Railway project.
2. Deploy this repository as a service with **Root Directory** set to `backend`.
3. Set the backend service variables:
   - `DATABASE_URL` — reference the PostgreSQL service's `DATABASE_URL` variable (use Railway's variable reference, not a public URL).
   - `INITIAL_ADMIN_EMAIL` — your email.
   - `INITIAL_ADMIN_PASSWORD` — unique password, 12+ characters. Store only in Railway Variables.
   - `INITIAL_ADMIN_NAME` — your name.
   - `APP_ORIGIN` — `https://sebas9313.github.io` (no trailing slash).
4. Generate a public Railway domain for the backend. Check `/api/health` returns `{"ok":true}`.

**Do not paste credentials into GitHub or ChatGPT.** Remove `INITIAL_ADMIN_PASSWORD` from Railway variables after first startup; changing it later does not update the existing user's password.

## Endpoints
- `POST /api/login` returns a bearer token for an existing family account.
- `GET /api/me`, `POST /api/logout`, `GET /api/users`, `POST /api/users` (five-user limit).
- `GET /api/records`, `POST /api/records`, `PATCH /api/records/:id`, `DELETE /api/records/:id` (requires `confirm:true` and version).
- `GET /api/history` audit log with actor and before/after values.

## Not yet included
- Frontend login and data migration; account invitations/reset; WhatsApp delivery; reminder scheduler; production hardening and automated tests.
- Medical reminders must never infer actual ingestion from a checked task.
- Before real use, review authentication, logging, backups, and permissions. Trial infrastructure may sleep, expire or charge after credits end.
