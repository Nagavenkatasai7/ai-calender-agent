# 🤖 AI Reminder Agent

A comprehensive smart calendar application with AI-powered natural language processing, secure authentication, and Google Calendar integration. Transform your thoughts into organized calendar events with advanced security features and subscription tiers.

![AI Reminder Agent](https://img.shields.io/badge/AI-Powered-blue)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)
![Google Calendar](https://img.shields.io/badge/Google-Calendar-red)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT-orange)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green)

## ✨ Latest Features

### 🔐 **Enterprise-Grade Security**
- **Multi-Factor Authentication (2FA)** with TOTP support
- **OAuth 2.0 Integration** with Google for secure authentication
- **Ironclad Logout Protection** - Complete session invalidation with multi-layer security
- **Anti-Back Button Access** - Prevents cached access after logout
- **Real-time Session Validation** - Continuous authentication checks
- **Email Verification System** with Gmail SMTP integration
- **Password Security** with BCrypt hashing and strength validation
- **Rate Limiting** and CSRF protection
- **Secure Session Management** with cookie encryption

### 🎯 **Core AI Functionality**
- **Natural Language Processing**: Convert speech to calendar events
- **Smart Time Detection**: Understands complex time expressions
- **Google Calendar Sync**: Real-time synchronization with your calendar
- **AI-Powered Parsing**: Advanced OpenAI integration for event extraction
- **Voice Recognition**: Direct voice-to-calendar functionality
- **Smart Reminders**: Intelligent email and push notifications

### 💎 **Subscription Tiers**
- **Free Tier**: 10 AI events/month, 1 calendar, basic features
- **Pro Tier**: 100 AI events/month, 5 calendars, advanced features
- **Max Tier**: Unlimited events, unlimited calendars, team features
- **Stripe Integration**: Secure payment processing and subscription management

### 🎨 **Modern UI/UX Features**
- **Glass Morphism Design** with beautiful translucent effects
- **Responsive Layout** that works on all devices
- **Dark/Light Theme Support** with multiple background options
- **Real-time Voice Input** with enhanced speech recognition
- **Intuitive Calendar Views** (Month, Week, Day)
- **Smart Event Categorization** with color coding
- **Enhanced Header Navigation** with Settings and Logout buttons
- **Secure Authentication Modals** with smooth transitions
- **Real-time Feedback** for all user actions
- **Background Customization** with nature, abstract, and space themes

### 📧 **Communication System**
- **Gmail SMTP Integration**: Professional email notifications
- **Password Reset**: Secure password recovery via email
- **Verification Links**: One-click account activation
- **Reminder Emails**: Smart notification scheduling

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ installed
- Google Cloud Console account
- OpenAI API account
- Gmail account with App Password
- Stripe account (for payments)

### 1. Clone the Repository
```bash
git clone https://github.com/Nagavenkatasai7/ai-calender-agent.git
cd ai-reminder-agent
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Set Up Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google Calendar API and Google+ API
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URIs:
   - `http://localhost:3000/auth/callback`
6. Add authorized JavaScript origins:
   - `http://localhost:3000`

### 4. Set Up Gmail App Password
1. Enable 2-Factor Authentication on your Gmail
2. Go to [App Passwords](https://myaccount.google.com/apppasswords)
3. Generate a new App Password for "Mail"
4. Use this 16-character password in your `.env` file

### 5. Configure Environment Variables
Create a `.env` file based on `.env.example`:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback

# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key_here

# Email Configuration (Gmail)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_16_character_app_password
EMAIL_FROM=your_email@gmail.com

# Stripe Configuration
STRIPE_PUBLISHABLE_KEY=your_stripe_publishable_key
STRIPE_SECRET_KEY=your_stripe_secret_key
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret

# Security Configuration
SESSION_SECRET=your_random_session_secret_here
JWT_SECRET=your_jwt_secret_change_in_production

# Application Configuration
PORT=3000
NODE_ENV=development
BASE_URL=http://localhost:3000
```

### 6. Run the Application
```bash
npm start
```

Visit `http://localhost:3000` in your browser! 🎉

## 🔐 Authentication System

### Sign Up Flow
1. **Account Creation**: Secure registration with password validation
2. **Email Verification**: Automated verification email with secure tokens
3. **Auto-Login**: Seamless login after email verification
4. **Google OAuth**: Alternative registration via Google account

### Sign In Options
- **Email/Password**: Traditional secure login with rate limiting
- **Google OAuth**: One-click login with Google Calendar access
- **2FA Support**: Optional two-factor authentication for enhanced security
- **Password Reset**: Secure password recovery via email

### Security Features
- **BCrypt Password Hashing**: Industry-standard password protection
- **JWT Tokens**: Secure session management
- **Rate Limiting**: Protection against brute force attacks
- **Session Timeout**: Automatic logout for security
- **CSRF Protection**: Cross-site request forgery prevention
- **SQL Injection Prevention**: Parameterized queries and input validation

## 📱 User Interface

### Landing Page
- **Modern Design**: Glass morphism with gradient backgrounds
- **Authentication Modals**: Smooth sign-in/sign-up forms
- **Feature Showcase**: Interactive demonstration of capabilities
- **Security Badges**: Trust indicators and certifications

### Calendar Application
- **Voice Input**: Direct speech-to-calendar functionality
- **Smart Parsing**: Real-time AI processing of natural language
- **Calendar Integration**: Live Google Calendar synchronization
- **Event Management**: Create, edit, and delete calendar events
- **Subscription Dashboard**: Usage tracking and tier management

### Settings Panel
- **Profile Management**: Update personal information
- **Security Settings**: 2FA setup and password changes
- **Subscription Management**: Tier upgrades and billing
- **Connected Accounts**: Manage OAuth connections

## 🔧 API Endpoints

### Authentication
```javascript
POST /api/auth/register      # Create new account
POST /api/auth/login         # Email/password login
GET  /api/auth/verify-email/:token  # Email verification
POST /api/auth/logout        # Secure logout
GET  /auth/google           # Google OAuth flow
GET  /auth/callback         # OAuth callback
```

### User Management
```javascript
GET  /api/user/profile      # Get user profile
PUT  /api/user/profile      # Update profile
GET  /api/user/dashboard    # Usage dashboard
GET  /api/auth/status       # Authentication status
```

### Reminders & Calendar
```javascript
POST /api/reminders         # Create AI-powered reminder
GET  /api/reminders         # Get user reminders
DELETE /api/reminders/:id   # Delete reminder
```

### Subscriptions
```javascript
GET  /api/subscription/pricing     # Get pricing tiers
POST /api/subscription/checkout    # Create checkout session
GET  /api/subscription/status      # Get subscription status
POST /api/subscription/cancel      # Cancel subscription
```

## 💡 Usage Examples

### Natural Language Processing
```
"Team meeting tomorrow at 2pm for 2 hours"
→ Creates: "Team meeting" 
   Date: Tomorrow 2:00 PM - 4:00 PM
   Reminders: Email 15 minutes before

"Call mom next Friday at 3:30pm"
→ Creates: "Call mom"
   Date: Friday 3:30 PM - 4:30 PM
   Reminders: Email 10 minutes before

"Doctor appointment on December 15th at 10am"
→ Creates: "Doctor appointment"
   Date: Dec 15th 10:00 AM - 11:00 AM
   Reminders: Email 1 hour before
```

### Voice Commands
- **"Create reminder..."**: Direct voice input processing
- **"Schedule meeting..."**: Automatic calendar event creation
- **"Set alarm for..."**: Smart reminder scheduling
- **"Book appointment..."**: Professional event management

## 🏗️ Architecture

### Backend Services
```
src/
├── app.ts                 # Main Express application
├── auth.ts               # Authentication service
├── database.ts           # SQLite database management
├── aiParser.ts           # OpenAI integration
├── calendar.ts           # Google Calendar API
├── emailService.ts       # Gmail SMTP service
├── subscriptionService.ts # Stripe integration
└── types/
    └── session.d.ts      # TypeScript definitions
```

### Frontend Pages
```
public/
├── secure-landing.html   # Main landing page
├── app.html             # Calendar application
├── settings.html        # User settings
├── reset-password.html  # Password recovery
└── pricing.html         # Subscription tiers
```

### Database Schema
- **Users**: Authentication and profile data
- **Reminders**: Calendar events and AI metadata
- **Subscriptions**: Billing and usage tracking
- **Sessions**: Secure session management
- **Security Logs**: Audit trail for security events

## 🔧 **Troubleshooting**

### **Authentication Issues**
- **OAuth Redirect Problems**: Session cookies now use `SameSite: 'lax'` for OAuth compatibility
- **Back Button Access**: Ironclad logout protection prevents cached access after logout
- **Session Persistence**: Enhanced session management with `saveUninitialized: true`
- **Login Loops**: Clear browser cache and cookies for `localhost:3000`

### **Email Verification**
- **Gmail Setup**: Requires App Password, not regular Gmail password
- **Email Not Received**: Check spam folder and verify EMAIL_USER/EMAIL_PASS in .env
- **Verification Links**: Console logs backup verification URLs for testing

### **Security Features**
- **Logout Protection**: Multiple security layers prevent unauthorized back button access
- **Session Validation**: Real-time authentication checks on all interactions
- **Cache Prevention**: Anti-cache headers prevent stale page access

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -am 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

### Development Guidelines
- Follow TypeScript best practices
- Add comprehensive error handling
- Test authentication flows thoroughly
- Ensure responsive design
- Add proper logging and monitoring

## 📊 Performance & Monitoring

### Application Metrics
- **Response Times**: Optimized API endpoints
- **Security Monitoring**: Real-time threat detection
- **Usage Analytics**: Subscription tier tracking
- **Error Reporting**: Comprehensive error logging

### Scalability Features
- **Session Management**: Distributed session storage ready
- **Database Optimization**: Indexed queries and connection pooling
- **Caching Strategy**: Redis-ready for high traffic
- **Load Balancing**: Stateless architecture for horizontal scaling

## 🛡️ Security Compliance

### Data Protection
- **GDPR Compliance**: User data rights and privacy
- **Data Encryption**: End-to-end encryption for sensitive data
- **Secure Storage**: BCrypt password hashing
- **Session Security**: Secure cookie configuration

### Security Standards
- **OWASP Top 10**: Protection against common vulnerabilities
- **SOC 2 Ready**: Enterprise security controls
- **SSL/TLS**: Secure communication protocols
- **Regular Updates**: Dependency security monitoring

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenAI](https://openai.com/) for advanced AI text parsing
- [Google Calendar API](https://developers.google.com/calendar) for seamless integration
- [Stripe](https://stripe.com/) for secure payment processing
- [Node.js](https://nodejs.org/) and [TypeScript](https://www.typescriptlang.org/) communities

## 📞 Support

- 🐛 [Report Issues](https://github.com/Nagavenkatasai7/ai-calender-agent/issues)
- 💬 [Start Discussion](https://github.com/Nagavenkatasai7/ai-calender-agent/discussions)
- 📧 Email: support@ai-reminder.com

## 🔒 **Authentication Security System**

### **Multi-Layer Logout Protection**
Our application implements **ironclad authentication security** that completely prevents unauthorized access after logout:

#### **1. Server-Side Session Destruction**
- Complete session invalidation on logout
- Session cookie cleared from browser
- OAuth tokens revoked
- Cache-control headers prevent cached access

#### **2. Client-Side Security Checks**
- **Immediate authentication verification** on page load
- **Real-time session validation** with server
- **Back button protection** with popstate event monitoring
- **Page visibility monitoring** for tab switching detection

#### **3. Anti-Cache Mechanisms**
- Strict cache-control headers: `no-cache, no-store, must-revalidate`
- Browser history manipulation prevention
- Force redirect using `window.location.replace()`

#### **4. Continuous Authentication**
- Authentication checks on every route access
- Session validation on user interaction
- Automatic redirect to login on session expiry

### **Security Testing**
After logout, **ALL** of these methods will force re-authentication:
- ✅ Browser back button
- ✅ Browser forward button  
- ✅ Direct URL typing `/app`
- ✅ Page refresh
- ✅ Tab switching and return
- ✅ Browser bookmark access

---

**Made with ❤️ by Nagavenkata Sai**

*Transform your natural language into organized calendar events with enterprise-grade security and AI-powered intelligence!* ✨ 