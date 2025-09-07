# Vercel Deployment Guide

## Quick Deployment Steps

1. **Prepare for Git (if not already done):**
   ```bash
   git init
   git add .
   git commit -m "Ready for Vercel deployment"
   ```

2. **Create GitHub repository:**
   - Go to GitHub and create a new repository
   - Push your code:
   ```bash
   git remote add origin https://github.com/yourusername/cgpa-tracker.git
   git branch -M main
   git push -u origin main
   ```

3. **Deploy to Vercel:**
   - Go to [vercel.com](https://vercel.com)
   - Sign in with GitHub
   - Click "New Project"
   - Select your repository
   - Vercel will auto-detect the Flask app

4. **Set Environment Variables in Vercel:**
   - Go to Project Settings > Environment Variables
   - Add: `JWT_SECRET_KEY` = `bwrVEumMGXXwOpmnXv-sgy6DpI4TTq_vJOvlk6EP9Os`
   - Add: `FLASK_ENV` = `production`

## Files Created for Vercel:

- ✅ `vercel.json` - Vercel configuration
- ✅ `api/app.py` - Serverless Flask app
- ✅ `api/templates/` - Templates for serverless app
- ✅ `runtime.txt` - Python version
- ✅ `Procfile` - Alternative deployment support
- ✅ Updated `requirements.txt` with gunicorn

## Important Notes:

### Database Limitations
- SQLite in Vercel is ephemeral (resets on each deployment)
- For production, use PostgreSQL (Neon, Supabase) or MongoDB Atlas
- Replace database URL in `api/app.py` for persistent storage

### Admin Features
- Username: `admin`
- Password: `4129`
- Backup/restore limited in serverless environment

### Local vs Production
- Use original `app.py` for local development
- Vercel uses `api/app.py` automatically

Your app will be live at: `https://your-project-name.vercel.app`
