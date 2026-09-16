# void — Setup (Railway)

## Step 1 — Deploy to Railway
1. Go to railway.app → sign up free
2. New Project → Deploy from GitHub repo
   OR: drag this folder into railway.app/new

## Step 2 — Add these environment variables in Railway dashboard
Go to your project → Variables tab → add each one:

| Variable | Value |
|---|---|
| DATABASE_URL | your Neon connection string |
| SECRET_KEY | c9c77f02e7d0d6fa0face945a1089857df8696661746a79cb5b5e747e5052973 |
| FERNET_KEY | mn2LwQdm6yjWfFFpVZAoUWa--vdXW6LQaHnCLynRdFU= |
| IPROYAL_HOST | geo.iproyal.com |
| IPROYAL_PORT | 12321 |
| IPROYAL_USER | your IPRoyal username |
| IPROYAL_PASS | your IPRoyal password |

## Step 3 — Deploy
Railway auto-deploys when you add variables.
Your app will be live at a .railway.app URL.

## That's it.
