# 🚀 Deployment Guide

This guide covers multiple deployment options for the AI Voice Calendar Assistant.

## 📋 Quick Deployment Options

### 🟢 Recommended: Vercel (Free + Paid)

Vercel offers the best developer experience for Node.js applications:

1. **Install Vercel CLI:**
   ```bash
   npm install -g vercel
   ```

2. **Deploy to Vercel:**
   ```bash
   vercel --prod
   ```

3. **Configure Environment Variables:**
   - Go to your Vercel dashboard
   - Add all required environment variables from `env.production.example`
   - Redeploy: `vercel --prod`

**✅ Pros:** Automatic deployments, serverless, excellent performance
**❌ Cons:** Database limitations (use external DB)

---

### 🟡 Alternative: Railway (Free Tier Available)

Railway provides excellent full-stack hosting with database support:

1. **Install Railway CLI:**
   ```bash
   npm install -g @railway/cli
   ```

2. **Login and Deploy:**
   ```bash
   railway login
   railway deploy
   ```

3. **Add Database (Optional):**
   ```bash
   railway add postgresql
   ```

**✅ Pros:** Built-in database, easy setup, great for full-stack apps
**❌ Cons:** Free tier limitations

---

### 🟦 Alternative: Heroku (Free Tier Discontinued)

Traditional PaaS platform, now paid only:

1. **Create Heroku App:**
   ```bash
   heroku create your-app-name
   ```

2. **Add Buildpack:**
   ```bash
   heroku buildpacks:set heroku/nodejs
   ```

3. **Deploy:**
   ```bash
   git push heroku main
   ```

4. **Configure Environment:**
   ```bash
   heroku config:set NODE_ENV=production
   # Add other environment variables...
   ```

**✅ Pros:** Mature platform, add-ons ecosystem
**❌ Cons:** No free tier, more expensive

---

### 🔧 GitHub Pages (Static Demo Only)

**⚠️ Limited Functionality:** Only frontend works, no backend features.

GitHub Pages deployment is automatic via GitHub Actions when you push to main branch.

**Live Demo:** Your app will be available at `https://your-username.github.io/ai-reminder`

---

## 🔧 Environment Configuration

### Required Environment Variables

Copy `env.production.example` to `.env` and configure:

```bash
# Core Application
NODE_ENV=production
PORT=3000

# Database (Production)
DATABASE_URL=postgresql://user:pass@host:port/db

# Security
JWT_SECRET=generate-strong-random-string
SESSION_SECRET=generate-strong-random-string

# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/callback

# AI Services (at least one required)
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=sk-...
HUGGING_FACE_TOKEN=hf_...
COHERE_API_KEY=your-cohere-key

# Email (for notifications)
EMAIL_FROM=noreply@yourdomain.com
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# Stripe (for subscriptions)
STRIPE_PUBLISHABLE_KEY=pk_live_...
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
```

### 🔐 Security Configuration

1. **Generate Strong Secrets:**
   ```bash
   # Use openssl to generate random strings
   openssl rand -hex 32  # For JWT_SECRET
   openssl rand -hex 32  # For SESSION_SECRET
   ```

2. **Configure OAuth Redirect URI:**
   - Update Google OAuth settings
   - Set redirect URI to: `https://yourdomain.com/auth/callback`

3. **Configure Stripe Webhooks:**
   - Set webhook endpoint: `https://yourdomain.com/api/subscription/webhook`
   - Add webhook secret to environment variables

---

## 🗄️ Database Setup

### Development (SQLite)
The app uses SQLite by default for development.

### Production (PostgreSQL Recommended)

1. **Vercel + PlanetScale:**
   ```bash
   # Add PlanetScale database URL
   DATABASE_URL=mysql://username:password@hostname/database?sslaccept=strict
   ```

2. **Railway:**
   ```bash
   # Railway provides PostgreSQL automatically
   railway add postgresql
   ```

3. **External PostgreSQL:**
   ```bash
   # Use any PostgreSQL provider
   DATABASE_URL=postgresql://user:password@host:port/database
   ```

---

## 🚀 Deployment Commands

### One-Click Deployments

**Vercel:**
```bash
npm run deploy:vercel
```

**Railway:**
```bash
npm run deploy:railway
```

**Heroku:**
```bash
npm run deploy:heroku
```

### Manual Build
```bash
npm run build
npm start
```

---

## 🔍 Post-Deployment Checklist

### ✅ Essential Checks

1. **Application Health:**
   - Visit `/health` endpoint
   - Check application logs

2. **Authentication:**
   - Test Google OAuth login
   - Verify JWT token generation

3. **AI Services:**
   - Test voice command processing
   - Verify AI model responses

4. **Calendar Integration:**
   - Test Google Calendar sync
   - Create test events

5. **Database:**
   - Verify user registration
   - Check data persistence

6. **Email Service:**
   - Test verification emails
   - Check reminder notifications

7. **Subscription System:**
   - Test Stripe integration
   - Verify webhook handling

### 🔧 Troubleshooting

**Common Issues:**

1. **OAuth Redirect Mismatch:**
   - Update Google OAuth redirect URI
   - Ensure HTTPS in production

2. **AI Services Not Working:**
   - Verify API keys are correct
   - Check service quotas/limits

3. **Database Connection Issues:**
   - Verify DATABASE_URL format
   - Check database credentials

4. **Build Failures:**
   - Ensure Node.js version >= 18
   - Check TypeScript compilation

---

## 📊 Monitoring & Analytics

### Recommended Tools

1. **Vercel Analytics:** Built-in performance monitoring
2. **Sentry:** Error tracking and performance monitoring
3. **LogRocket:** Session replay and debugging
4. **DataDog:** Comprehensive application monitoring

### Health Endpoints

- `/health` - Basic health check
- `/api/ai/health` - AI services status
- `/api/auth/status` - Authentication status

---

## 🔄 CI/CD Pipeline

The GitHub Actions workflow automatically:

1. **Builds** TypeScript code
2. **Tests** application (add tests as needed)
3. **Deploys** to GitHub Pages (static demo)
4. **Notifies** on deployment status

For production deployments, configure webhooks from your hosting provider to auto-deploy on push to main branch.

---

## 📞 Support

- **Issues:** Create GitHub issues for bugs
- **Documentation:** Check README.md for features
- **Community:** Join discussions in GitHub Discussions

---

**🎉 Your AI Voice Calendar Assistant is now live!**

Share your deployment URL and start managing your calendar with voice commands! 🎤📅 