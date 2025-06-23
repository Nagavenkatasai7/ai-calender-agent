# 🚀 AI Reminder Agent - Setup Instructions

## 📋 Required APIs and Services

### 1. Google Cloud Platform (FREE)
**What you need**: Google Calendar API and OAuth 2.0
**Cost**: Free (generous free tier)
**Steps**:
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or use existing)
3. Enable the **Google Calendar API**:
   - Go to "APIs & Services" → "Library"
   - Search for "Google Calendar API"
   - Click "Enable"
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" → "Credentials"
   - Click "Create Credentials" → "OAuth 2.0 Client ID"
   - Configure OAuth consent screen first if prompted
   - Choose "Web application"
   - Name: "AI Reminder Agent"
   - Authorized redirect URIs: `http://localhost:3000/auth/callback`
   - Save the **Client ID** and **Client Secret**

### 2. Gmail App Password (FREE)
**What you need**: Gmail account with 2FA enabled
**Cost**: Free
**Steps**:
1. Enable 2-Factor Authentication on your Gmail account
2. Go to [Google Account settings](https://myaccount.google.com/)
3. Security → 2-Step Verification → App passwords
4. Select "Mail" and generate password
5. **Save this 16-character password** (not your regular Gmail password)

### 3. OpenAI API (OPTIONAL - Has Free Fallback)
**What you need**: OpenAI API key for advanced natural language processing
**Cost**: Pay-per-use (~$0.002 per request)
**Free Alternative**: The app has a built-in regex parser that works without OpenAI
**Steps**:
1. Go to [OpenAI Platform](https://platform.openai.com/)
2. Create account and get API key
3. Add credits to your account (~$5 minimum)

## 🔑 Environment Configuration

Create a `.env` file in the root directory with these values:

```env
# Required - Google OAuth
GOOGLE_CLIENT_ID=your_client_id_from_google_cloud
GOOGLE_CLIENT_SECRET=your_client_secret_from_google_cloud
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback

# Required - Email Service
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_16_character_app_password

# Optional - AI Enhancement (has fallback)
OPENAI_API_KEY=sk-your_openai_api_key

# Application Settings
PORT=3000
NODE_ENV=development
```

## 🏃‍♂️ Quick Start

1. **Copy environment file**:
   ```bash
   cp env.example .env
   ```

2. **Edit `.env`** with your API keys (see above)

3. **Start the application**:
   ```bash
   npm start
   ```

4. **Open your browser**: `http://localhost:3000`

## ✅ Testing Your Setup

### Test 1: Health Check
Visit: `http://localhost:3000/health`
Should show all services as configured.

### Test 2: Google Authentication
1. Click "Sign in with Google"
2. Grant calendar permissions
3. Should redirect back with success message

### Test 3: Email Service
1. Use the "Send Test Email" button
2. Check your inbox (and spam folder)

### Test 4: Create Reminder
Try these examples:
- "Remind me to call mom tomorrow at 5 PM, alert me 1 hour before"
- "Meeting on Friday at 2 PM, send reminder 30 minutes before"

## 🆓 Completely Free Setup (No OpenAI)

If you want to use this completely free:

1. **Skip OpenAI**: Don't add `OPENAI_API_KEY` to your `.env`
2. **Uses built-in parser**: Automatically falls back to regex-based parsing
3. **Still works great**: Can handle common time/date patterns

The free parser understands:
- Times: "2 PM", "14:30", "2:30 PM"
- Dates: "tomorrow", "next Friday", "12/25"
- Alerts: "1 hour before", "30 minutes before", "2 hrs before"

## 🔍 Troubleshooting

### Google Auth Issues
```
Error: redirect_uri_mismatch
```
**Fix**: Make sure redirect URI in Google Cloud Console exactly matches:
`http://localhost:3000/auth/callback`

### Email Issues
```
Error: Invalid login
```
**Fix**: 
- Use Gmail App Password, not regular password
- Enable 2-Factor Authentication first
- Check that EMAIL_USER and EMAIL_PASS are correct

### Calendar Permission Issues
```
Error: insufficient_permissions
```
**Fix**: 
- Make sure Google Calendar API is enabled
- Re-authenticate and grant all permissions
- Check OAuth consent screen configuration

### AI Parsing Issues
```
OpenAI API error
```
**Fix**: 
- Check API key is correct
- Verify you have credits
- App will automatically use fallback parser

## 🌟 Advanced Configuration

### Custom Email Provider
Replace Gmail with any SMTP provider:

```env
EMAIL_HOST=smtp.yourdomain.com
EMAIL_PORT=587
EMAIL_SECURE=false
EMAIL_USER=your_username
EMAIL_PASS=your_password
```

### Production Deployment
For production, also set:

```env
NODE_ENV=production
GOOGLE_REDIRECT_URI=https://yourdomain.com/auth/callback
PORT=443
```

### Alternative AI Services
Instead of OpenAI, you can use:

```env
# Cohere (free tier)
COHERE_API_KEY=your_cohere_key

# Hugging Face (free tier)
HUGGINGFACE_API_KEY=your_hf_key
```

## 📞 Support

If you run into issues:

1. Check the console logs for detailed error messages
2. Verify all environment variables are set correctly
3. Test each service individually using the health endpoint
4. Most issues are configuration-related

## 🎉 You're Ready!

Once you have:
- ✅ Google Calendar API enabled
- ✅ OAuth credentials created
- ✅ Gmail app password generated
- ✅ Environment variables configured

Your AI Reminder Agent will be fully functional!

The system will:
1. 🔐 Authenticate users with Google
2. 📅 Create calendar events automatically
3. 🧠 Parse natural language (with or without OpenAI)
4. ✉️ Send beautiful email reminders
5. ⏰ Handle multiple alert times per event

Enjoy your new AI-powered reminder assistant! 🚀 