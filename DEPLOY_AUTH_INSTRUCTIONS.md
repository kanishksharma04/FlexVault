Deployment & Local Setup — Authentication (JWT)

Overview
- Frontend (Vite) runs on localhost:5173 in dev and is deployed to Vercel for production.
- Backend has two forms in this repository:
  - `backend/server.js` — a regular Express server useful for local dev and platforms like Render.
  - `backend/api/*.js` — Vercel serverless function handlers used when deploying the backend to Vercel.
- Database: configured via `DATABASE_URL` (your MongoDB Atlas connection string). Prisma is used as the ORM.

Local development (recommended flow)
1. Backend
   - Copy `.env` (already present in `backend/.env`) and ensure the values are correct:
     - `DATABASE_URL` — your MongoDB connection string
     - `JWT_SECRET` — a long random secret (change value from default in dev)
     - `PORT` — `3001` (default)
     - `CLIENT_URL` — `http://localhost:5173`
   - Start the backend:
     ```bash
     cd "./backend"
     npm install
     npm run dev
     ```
   - Confirm the health endpoint: http://localhost:3001/ returns JSON.

2. Frontend
   - Either set `VITE_API_URL` or rely on the built-in default that points to the local backend when running on `localhost`.
     - If you prefer an explicit env: create `.env` in `frontend` with:
       ```env
       VITE_API_URL="http://localhost:3001/api"
       ```
   - Start the frontend:
     ```bash
     cd "./frontend"
     npm install
     npm run dev
     ```
   - Open http://localhost:5173 and test signup/login. The frontend defaults to `http://localhost:3001/api` when running on `localhost`.

Deployment (production)
- Option A: Frontend on Vercel, Backend on Render
  1. Backend (Render)
     - Create a new Web Service on Render from this repo or your backend directory.
     - Set environment variables in Render for the service:
       - `DATABASE_URL` — MongoDB connection string
       - `JWT_SECRET` — production JWT secret
       - `CLIENT_URL` — frontend URL (e.g. `https://your-frontend.vercel.app`)
       - `BCRYPT_SALT_ROUNDS` — `10` (optional)
     - Ensure your `start` script runs `node server.js` (it does in `backend/package.json`).
     - Deploy the backend and note the service URL, e.g. `https://your-backend.onrender.com`.
  2. Frontend (Vercel)
     - In the Vercel project for the frontend set an Environment Variable:
       - `VITE_API_URL` = `https://your-backend.onrender.com/api`
     - Deploy the frontend. Now the React app will use the Render backend URL for API calls.

- Option B: Backend on Vercel (serverless)
  - If you want to deploy the backend to Vercel as serverless functions, make sure in the Vercel dashboard you set project env vars for the backend (JWT_SECRET, DATABASE_URL, CLIENT_URL). The repository already contains `backend/api/*` handlers and `vercel.json` route rewrites for `/signup`, `/login`, `/me` and `/api/auth/*`.

Important env variables (production)
- `DATABASE_URL` — MongoDB connection
- `JWT_SECRET` — production secret (must be set)
- `CLIENT_URL` — frontend origin (for CORS)
- `BCRYPT_SALT_ROUNDS` — optional, default `10`

Troubleshooting checklist
- 404 on signup/login from production frontend:
  - Confirm frontend `VITE_API_URL` points to the correct backend (Render or Vercel) or that your backend routes exist in `vercel.json` if using Vercel-backend.
  - If you rely on serverless backend on Vercel, ensure `vercel.json` contains explicit routes for `POST /signup` or `/api/auth/signup`.
- 500 errors on serverless functions:
  - Check Vercel function logs for missing env vars (especially `JWT_SECRET` and `DATABASE_URL`).
- CORS issues:
  - Ensure `CLIENT_URL` env value is set to your frontend origin in backend envs.

Notes about the repository changes
- `frontend/src/context/AuthContext.jsx` was updated so that during local dev the frontend calls `http://localhost:3001/api` by default.
- `vercel.json` was adjusted to avoid routing `/` to the backend index (so the frontend is served correctly), and added compatibility paths for `/signup`, `/login`, `/me`.

If you'd like, I can:
- Run through a live checklist with you (start backend, start frontend, hit signup). Paste outputs and I'll debug remaining issues.
- Help set environment variables in Vercel/Render if you paste the target service URLs (I can't set them for you).

---
Created by the helper script to make deployment reproducible.
