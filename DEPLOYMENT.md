# 🚀 AI Voice Calendar Assistant - Deployment Guide

## 🎯 **Best Free Hosting Options for Complete App**

### ⭐ **Option 1: Railway (RECOMMENDED)**
**✅ Perfect for full Node.js apps with databases**

#### Step 1: Deploy to Railway
1. **Visit**: https://railway.app
2. **Sign up** with GitHub
3. **Connect repository**: `nagavenkatasai7/ai-calender-agent`
4. **Auto-deploy** will start immediately

#### Step 2: Configure Environment Variables
In Railway dashboard → Environment tab, add:
```bash
NODE_ENV=production
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=https://your-app.railway.app/auth/callback
OPENAI_API_KEY=your_openai_key
COHERE_API_KEY=your_cohere_key
DEEPSEEK_API_KEY=your_deepseek_key
STRIPE_PUBLISHABLE_KEY=your_stripe_pub_key
STRIPE_SECRET_KEY=your_stripe_secret_key
SESSION_SECRET=your_random_session_secret
JWT_SECRET=your_random_jwt_secret
```

#### Step 3: Update OAuth Redirect
Update your Google OAuth redirect URI to:
`https://your-app.railway.app/auth/callback`

**Result**: Full app running at `https://your-app.railway.app` 🎉

---

### ⭐ **Option 2: Render.com (EXCELLENT ALTERNATIVE)**
**✅ True free tier with full features**

#### Step 1: Deploy to Render
1. **Visit**: https://render.com
2. **Sign up** with GitHub
3. **New → Web Service**
4. **Connect repository**: `nagavenkatasai7/ai-calender-agent`
5. **Build Command**: `npm install && npm run build`
6. **Start Command**: `npm start`

#### Step 2: Environment Variables (Same as Railway)

**Result**: Full app running at `https://ai-reminder-app.onrender.com` 🎉

---

### 📋 **Comparison: Railway vs Render vs Vercel**

| Feature | Railway | Render | Vercel |
|---------|---------|--------|--------|
| **Full Node.js Support** | ✅ Perfect | ✅ Perfect | ❌ Serverless only |
| **Database Support** | ✅ Built-in | ✅ PostgreSQL | ❌ External only |
| **Session Management** | ✅ Works | ✅ Works | ❌ Limited |
| **File System** | ✅ Persistent | ✅ Persistent | ❌ Read-only |
| **WebSocket Support** | ✅ Yes | ✅ Yes | ❌ Limited |
| **Cost** | $5/month credits | Free forever | Free (limited) |
| **Deploy Speed** | ⚡ Fast | ⚡ Fast | ⚡ Very Fast |
| **Custom Domains** | ✅ Yes | ✅ Yes | ✅ Yes |

---

## 🔧 **Quick Deploy Commands**

### Railway (One Command Deploy)
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway link
railway up
```

### Render (Git-based Deploy)
```bash
# Just push to GitHub - auto-deploys!
git add .
git commit -m "Deploy to Render"
git push origin main
```

### Alternative: Heroku (Still Free)
```bash
# Install Heroku CLI
npm install -g heroku

# Deploy
heroku login
heroku create your-app-name
git push heroku main
```

---

## 🛠 **Environment Setup for Production**

Create `.env.production` file:
```bash
# === REQUIRED FOR FULL FUNCTIONALITY ===
NODE_ENV=production
PORT=3000

# Google OAuth (Required for calendar)
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=https://your-domain.com/auth/callback

# AI Services (At least one required)
OPENAI_API_KEY=your_openai_key
COHERE_API_KEY=your_cohere_key
DEEPSEEK_API_KEY=your_deepseek_key
HUGGING_FACE_TOKEN=your_hf_token

# Payments (Optional)
STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret

# Security (Generate random strings)
SESSION_SECRET=your_super_secure_session_secret_min_32_chars
JWT_SECRET=your_super_secure_jwt_secret_min_32_chars

# Email (Optional)
EMAIL_FROM=noreply@yourdomain.com
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

---

## 🎯 **Recommended Deployment Path**

### For **Development & Testing**: Railway
- Quick setup
- Full features
- Easy debugging
- Free credits

### For **Production**: Render.com
- True free tier
- Professional features
- Custom domains
- SSL certificates

### For **Scaling**: DigitalOcean App Platform
- $5/month for robust hosting
- Managed databases
- Enterprise features

---

## 🚀 **Deploy Now**

### Option 1: Railway (1-Click Deploy)
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/new/template?template=https://github.com/nagavenkatasai7/ai-calender-agent)

### Option 2: Render (1-Click Deploy)
[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/nagavenkatasai7/ai-calender-agent)

### Option 3: Heroku (Classic)
[![Deploy to Heroku](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/nagavenkatasai7/ai-calender-agent)

---

## 📱 **Access Your Deployed App**

After deployment, your **complete AI Voice Calendar Assistant** will be available at:

- **Railway**: `https://your-app.railway.app`
- **Render**: `https://ai-reminder-app.onrender.com`
- **Heroku**: `https://your-app-name.herokuapp.com`

### ✨ **All Features Work**:
- 🎤 Voice recognition and commands
- 📅 Google Calendar integration
- 🤖 Multiple AI providers (OpenAI, Cohere, DeepSeek)
- 👤 User authentication (Google OAuth + Email/Password)
- 💳 Stripe payment integration
- 📧 Email notifications
- 🔒 Secure session management
- 📱 Mobile-responsive interface

---

**Choose Railway or Render for the best free hosting experience with full functionality!** 🚀 