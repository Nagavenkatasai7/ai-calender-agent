# 🤖 AI Reminder Agent

A smart reminder application that converts natural language into Google Calendar events using AI-powered text parsing.

![AI Reminder Agent](https://img.shields.io/badge/AI-Powered-blue)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)
![Google Calendar](https://img.shields.io/badge/Google-Calendar-red)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT-orange)

## ✨ Features

### 🎯 Core Functionality
- **Natural Language Processing**: Just type what you want to be reminded about
- **Smart Time Detection**: Understands relative and absolute time expressions
- **Google Calendar Integration**: Automatically creates calendar events
- **AI-Powered Parsing**: Uses OpenAI to extract event details from text
- **Beautiful Web Interface**: Modern, responsive design

### 📅 Smart Event Creation
- **Flexible Time Formats**: "tomorrow at 3pm", "next Friday at 10am", "in 2 hours"
- **Duration Detection**: "meeting for 1 hour", "2-hour workshop"
- **Event Details**: Automatically extracts titles, descriptions, and timing
- **Timezone Support**: Handles timezone-aware scheduling
- **Recurring Events**: Support for recurring reminders

### 💡 Example Usage
```
"Remind me to call mom tomorrow at 3pm"
→ Creates: "Call mom" event tomorrow at 3:00 PM

"Team meeting next Friday at 10am for 2 hours"
→ Creates: "Team meeting" event Friday 10:00 AM - 12:00 PM

"Doctor appointment on June 25th at 2:30pm"
→ Creates: "Doctor appointment" event on June 25th at 2:30 PM
```

## 🚀 Quick Start

### Prerequisites
- Node.js 18+ installed
- Google Cloud Console account
- OpenAI API account (optional but recommended)
- Gmail account for Google Calendar access

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/ai-reminder-agent.git
cd ai-reminder-agent
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Set Up Google OAuth
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable Google Calendar API
4. Create OAuth 2.0 credentials (Web application)
5. Add authorized redirect URIs:
   - `http://localhost:3000/auth/callback`
   - `http://localhost:3000/auth/google/callback`
6. Add authorized JavaScript origins:
   - `http://localhost:3000`

### 4. Configure Environment Variables
Create a `.env` file in the root directory:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback

# OpenAI Configuration
OPENAI_API_KEY=your_openai_api_key_here

# Email Configuration (Optional)
EMAIL_USER=your_email@gmail.com
EMAIL_PASS=your_gmail_app_password

# Stripe Configuration (For Payments)
STRIPE_PUBLISHABLE_KEY=pk_live_51Rd1BwBdnTkIo216KvzF2czJ4d9WKSXwVJ49h0IrHB3XlmzOEbcjxmxpzY7SLOHa1kaDoDypEwxanEwEVKmfYZYG00slhS9UNN
STRIPE_SECRET_KEY=your_stripe_secret_key_here
STRIPE_WEBHOOK_SECRET=your_stripe_webhook_secret_here

# Application Configuration
PORT=3000
NODE_ENV=development
SESSION_SECRET=your_random_session_secret_here
```

### 5. Run the Application
```bash
npm run dev
```

Visit `http://localhost:3000` in your browser! 🎉

## 📖 Detailed Setup Guide

### Google Cloud Console Setup

1. **Create OAuth Client**:
   - Go to APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth client ID"
   - Select "Web application"
   - Add redirect URIs and JavaScript origins as shown above

2. **Enable Required APIs**:
   - Google Calendar API
   - Google+ API (for OAuth)

3. **Configure OAuth Consent Screen**:
   - Add test users (your email addresses)
   - Set publishing status to "Testing" for development

### OpenAI API Setup

1. **Get API Key**:
   - Visit [OpenAI Platform](https://platform.openai.com/)
   - Create an account and get your API key
   - Add billing information for usage

2. **Alternative Free Options**:
   - Hugging Face API
   - Cohere API
   - Local models (configuration in `src/aiParser.ts`)

### Email Configuration (Optional)

For email reminders, you need Gmail App Passwords:

1. Enable 2-Factor Authentication on your Gmail
2. Generate an App Password for the application
3. Use the 16-character App Password (not your regular password)

## 🖥️ Usage

### Web Interface

1. **Connect Google Calendar**: Click the connect button to authenticate
2. **Enter Natural Language**: Type your reminder in the text box
3. **AI Processing**: The system parses your text and extracts event details
4. **Calendar Integration**: Event is automatically created in Google Calendar

### API Endpoints

- `GET /` - Main web interface
- `GET /auth` - Initiate Google OAuth flow
- `GET /auth/callback` - OAuth callback handler
- `POST /add-reminder` - Create new reminder
- `GET /reminders/:userEmail` - Get user's reminders
- `DELETE /reminders/:id` - Delete a reminder
- `GET /health` - Health check endpoint

### Example API Usage

```javascript
// Create a reminder
const response = await fetch('/add-reminder', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    reminderText: "Team meeting tomorrow at 2pm",
    userEmail: "user@example.com"
  })
});
```

## 🔧 Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_CLIENT_ID` | Yes | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Yes | Google OAuth client secret |
| `GOOGLE_REDIRECT_URI` | Yes | OAuth redirect URI |
| `OPENAI_API_KEY` | Recommended | OpenAI API key for AI parsing |
| `EMAIL_USER` | Optional | Gmail address for email reminders |
| `EMAIL_PASS` | Optional | Gmail App Password |
| `STRIPE_PUBLISHABLE_KEY` | Optional | Stripe publishable key for payments |
| `STRIPE_SECRET_KEY` | Optional | Stripe secret key for payments |
| `STRIPE_WEBHOOK_SECRET` | Optional | Stripe webhook secret for webhooks |
| `SESSION_SECRET` | Yes | Random secret for session encryption |
| `PORT` | Optional | Server port (default: 3000) |
| `NODE_ENV` | Optional | Environment (development/production) |

### Advanced Configuration

- **AI Model**: Modify `src/aiParser.ts` to use different AI models
- **Database**: Currently uses JSON file storage, can be upgraded to proper database
- **Email Templates**: Customize in `src/emailService.ts`
- **UI Styling**: Modify `public/index.html` for custom styling

## 🚦 Development

### Available Scripts

```bash
npm run dev      # Start development server with hot reload
npm run build    # Build TypeScript to JavaScript
npm run start    # Start production server
npm run watch    # Watch TypeScript files for changes
```

### Project Structure

```
ai-reminder-agent/
├── src/
│   ├── app.ts          # Main application server
│   ├── calendar.ts     # Google Calendar integration
│   ├── aiParser.ts     # AI-powered text parsing
│   ├── emailService.ts # Email notification service
│   └── database.ts     # Data storage management
├── public/
│   └── index.html      # Web interface
├── .env.example        # Environment variables template
├── package.json        # Dependencies and scripts
└── tsconfig.json       # TypeScript configuration
```

## 🐛 Troubleshooting

### Common Issues

**Authentication Failed**:
- Verify redirect URIs in Google Cloud Console
- Check that OAuth client credentials are correct
- Wait 5-10 minutes after updating Google Cloud settings

**Invalid Client Error**:
- Ensure redirect URIs match exactly
- Verify client ID and secret are correct
- Check that APIs are enabled in Google Cloud Console

**AI Parsing Not Working**:
- Verify OpenAI API key is valid and has credits
- Check API usage limits
- Consider using alternative AI providers

**Calendar Events Not Created**:
- Ensure Google Calendar API is enabled
- Check user has calendar permissions
- Verify OAuth scopes include calendar access

### Debug Mode

Add debug logging by setting:
```env
NODE_ENV=development
DEBUG=true
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and test thoroughly
4. Commit your changes: `git commit -am 'Add feature'`
5. Push to the branch: `git push origin feature-name`
6. Submit a pull request

### Development Guidelines

- Follow TypeScript best practices
- Add proper error handling
- Write descriptive commit messages
- Test all authentication flows
- Ensure responsive design

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [OpenAI](https://openai.com/) for AI text parsing capabilities
- [Google Calendar API](https://developers.google.com/calendar) for calendar integration
- [Node.js](https://nodejs.org/) and [TypeScript](https://www.typescriptlang.org/) communities

## 📞 Support

- Create an [issue](https://github.com/yourusername/ai-reminder-agent/issues) for bug reports
- Start a [discussion](https://github.com/yourusername/ai-reminder-agent/discussions) for questions
- Check existing issues before creating new ones

---

**Made with ❤️ by [Your Name]**

*Transform your natural language into organized calendar events with the power of AI!* 