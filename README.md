# 🎤 AI Voice Calendar Assistant

A revolutionary smart calendar application with **AI-powered voice control**, advanced natural language processing, and enterprise-grade security. Transform your voice commands into organized calendar events with cutting-edge AI technology and seamless Google Calendar integration.

![AI Voice Assistant](https://img.shields.io/badge/AI-Voice%20Powered-purple)
![Node.js](https://img.shields.io/badge/Node.js-18+-green)
![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)
![Google Calendar](https://img.shields.io/badge/Google-Calendar-red)
![OpenAI](https://img.shields.io/badge/OpenAI-GPT-orange)
![Cohere](https://img.shields.io/badge/Cohere-AI-blue)
![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-green)

## 🎯 **Revolutionary AI Voice Features**

### 🎤 **Complete Voice Control**
- **"Create meeting with John tomorrow at 3pm"** → ✅ Event created automatically
- **"Delete my lunch appointment"** → ✅ Event removed from calendar  
- **"What's on my schedule today?"** → ✅ Voice schedule readout
- **"Schedule dinner Friday at 7pm"** → ✅ Full calendar integration

### 🧠 **Advanced AI Processing**
- **Multi-AI Provider Cascade**: OpenAI → DeepSeek → HuggingFace → Cohere fallbacks
- **Intelligent Intent Detection**: Automatically understands create/delete/query commands
- **Natural Language Parsing**: Extracts dates, times, attendees, and locations
- **Context-Aware Responses**: Remembers conversation history and preferences
- **Smart Event Matching**: Finds events to delete using fuzzy matching
- **Real-time Voice Recognition**: Enhanced sensitivity for quiet/low-frequency voices

### 🎨 **Modern Voice Interface**
- **Apple-Style UI**: Glass morphism with elegant transparency effects
- **Real-time Voice Feedback**: Visual indicators during speech recognition
- **AI Health Monitoring**: Live status of all AI services
- **Multi-language Support**: Voice commands in multiple languages
- **Voice Settings Panel**: Customize rate, pitch, volume, and voice selection
- **Conversation History**: Track all voice interactions and responses

## ✨ **Core Features**

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

### 🎯 **Smart Calendar Management**
- **Voice-Controlled Events**: Complete CRUD operations via voice commands
- **Google Calendar Sync**: Real-time bidirectional synchronization
- **Smart Time Detection**: Understands complex time expressions
- **Event Conflict Detection**: AI-powered scheduling optimization
- **Recurring Events**: Voice-activated repeating event creation
- **Smart Reminders**: Intelligent email and push notifications
- **Location Detection**: Automatic venue extraction from voice commands
- **Attendee Management**: Voice-based meeting participant handling

### 💎 **Subscription Tiers**
- **Free Tier**: 10 AI events/month, 1 calendar, basic voice features
- **Pro Tier**: 100 AI events/month, 5 calendars, advanced voice AI
- **Max Tier**: Unlimited events, unlimited calendars, full voice control
- **Stripe Integration**: Secure payment processing and subscription management

### 🤖 **AI Technology Stack**
- **OpenAI GPT**: Primary natural language understanding
- **Cohere AI**: Advanced event parsing and response generation
- **HuggingFace Transformers**: Machine learning model integration
- **DeepSeek API**: Fallback AI processing
- **Web Speech API**: Browser-native voice recognition
- **Speech Synthesis**: Text-to-speech response system

## 🚀 **Voice Commands You Can Use**

### 📅 **Create Events**
```
"Create meeting with Sarah tomorrow at 11am"
"Schedule dentist appointment next Tuesday at 2pm"
"Book team standup daily at 9am"
"Plan lunch with mom this Friday at 12:30"
"Set up client call Monday at 3pm for 1 hour"
```

### 🗑️ **Delete Events**
```
"Delete my dentist appointment"
"Cancel the meeting with John"
"Remove today's lunch"
"Delete all events today"
"Cancel my 3pm appointment"
```

### 📋 **Query Schedule**
```
"What's on my calendar today?"
"Show me tomorrow's schedule"
"What do I have this week?"
"Any meetings this afternoon?"
"When is my next appointment?"
```

### 🎛️ **Voice Settings**
```
"Speak faster" / "Speak slower"
"Use a different voice"
"Lower the volume"
"What can you do?"
```

## 🚀 **Quick Start**

### Prerequisites
- Node.js 18+ installed
- Google Cloud Console account
- OpenAI API account (recommended)
- Cohere API account (recommended)
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

### 4. Configure Environment Variables
Create a `.env` file based on `.env.example`:

```env
# Google OAuth Configuration
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your_google_client_secret
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback

# AI Service Configuration
OPENAI_API_KEY=your_openai_api_key_here
COHERE_API_KEY=your_cohere_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here
HUGGING_FACE_TOKEN=your_huggingface_token_here

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

### 5. Run the Application
```bash
npm start
```

### 6. Access Voice Interface
1. Visit `http://localhost:3000` in your browser
2. Sign in with Google or create an account
3. Navigate to `http://localhost:3000/ai-voice`
4. **Allow microphone access** when prompted
5. Click "Start Listening" and speak your commands! 🎉

## 🎤 **Voice Interface Guide**

### Getting Started
1. **Login Required**: Authentication is required for voice features
2. **Microphone Permission**: Browser will request microphone access
3. **Chrome Recommended**: Best compatibility with Web Speech API
4. **Quiet Environment**: Better recognition in low-noise settings

### Voice Recognition Tips
- **Speak Clearly**: Enunciate words for better recognition
- **Natural Pace**: Normal speaking speed works best
- **Include Details**: Date, time, and event title for creation
- **Be Specific**: When deleting, mention exact event names
- **Try Variations**: If not understood, rephrase your command

### Troubleshooting Voice Issues
- **No Recognition**: Check microphone permissions in browser
- **Low Accuracy**: Ensure quiet environment and clear speech
- **API Errors**: Check AI service API keys in environment variables
- **Browser Issues**: Try Chrome/Edge for best Web Speech API support

## 🏗️ **Architecture**

### AI Voice Processing Pipeline
```
Voice Input → Speech Recognition → Intent Detection → AI Parsing → Calendar Action → Voice Response
```

### Backend Services
```
src/
├── app.ts                    # Main Express application with voice routes
├── aiVoiceInterface.ts       # Comprehensive AI voice controller
├── speechRecognition.ts      # Browser speech recognition service
├── textToSpeech.ts          # Voice response synthesis
├── commandParser.ts         # Natural language command parsing
├── conversationContext.ts   # Context and history management
├── calendarAIAgent.ts       # Calendar-specific AI operations
├── cohereAI.ts              # Cohere AI integration
├── huggingFaceMCP.ts        # HuggingFace model service
├── wakeWordDetector.ts      # Wake word detection
├── auth.ts                  # Enhanced authentication service
├── database.ts              # SQLite database management
├── calendar.ts              # Google Calendar API integration
├── emailService.ts          # Gmail SMTP service
└── subscriptionService.ts   # Stripe integration with voice features
```

### Frontend Pages
```
public/
├── secure-landing.html      # Main landing page
├── app.html                 # Calendar application with voice menu
├── ai-voice-interface.html  # Dedicated voice control interface
├── settings.html            # User settings with voice configuration
└── reset-password.html      # Password recovery
```

### AI Service Integration
- **Multi-Provider Fallback**: Automatic failover between AI services
- **Server-Side Processing**: Voice commands processed on backend
- **Browser Compatibility**: Mock services for server environment
- **Error Handling**: Graceful degradation when AI services fail
- **Health Monitoring**: Real-time status of all AI providers

## 🔧 **API Endpoints**

### Voice Processing
```javascript
POST /api/voice/process      # Process voice command with AI
GET  /api/voice/history      # Get conversation history
POST /api/ai/analyze-command # Analyze voice command intent
GET  /api/ai/capabilities    # Get available AI features
POST /api/ai/health          # Check AI service health
```

### Enhanced Calendar
```javascript
POST /api/reminders         # Create AI-powered reminder (voice-enabled)
GET  /api/reminders         # Get user reminders
DELETE /api/reminders/:id   # Delete reminder (voice-activated)
POST /api/ai/enhance-event  # AI event enhancement
POST /api/ai/translate      # Multi-language support
```

### Authentication & Users
```javascript
POST /api/auth/register      # Create new account
POST /api/auth/login         # Email/password login
GET  /api/auth/verify-email/:token  # Email verification
POST /api/auth/logout        # Secure logout
GET  /auth/google           # Google OAuth flow
GET  /auth/callback         # OAuth callback
GET  /api/user/profile      # Get user profile
PUT  /api/user/profile      # Update profile
```

## 💡 **Advanced Usage Examples**

### Complex Voice Commands
```
"Schedule a team meeting with John, Sarah, and Mike next Monday at 2pm for 2 hours in Conference Room A"
→ Creates event with:
  - Title: "Team meeting"
  - Attendees: John, Sarah, Mike  
  - Date: Next Monday 2:00 PM - 4:00 PM
  - Location: Conference Room A
  - Reminders: 15 minutes before

"Create a recurring daily standup at 9am starting tomorrow"
→ Creates recurring event:
  - Title: "Daily standup"
  - Time: 9:00 AM daily
  - Recurrence: Every weekday
  - Start: Tomorrow
```

### Multi-Language Support
```
"Créer une réunion demain à 14h"     # French
"Crear una cita mañana a las 3pm"    # Spanish  
"明日午後3時にミーティングを作成"        # Japanese
"Создать встречу завтра в 15:00"     # Russian
```

### Smart Query Responses
```
User: "What's on my schedule today?"
AI: "You have 3 events today: 9:00 AM Standup, 2:00 PM Client call, 6:00 PM Dinner with family"

User: "Any conflicts this week?"
AI: "I found a potential conflict on Wednesday - you have meetings at 2pm and 2:30pm"
```

## 🔧 **Configuration**

### Voice Recognition Settings
```javascript
// Browser voice recognition configuration
const speechConfig = {
  continuous: true,           # Keep listening
  interimResults: true,       # Show interim results
  maxAlternatives: 5,         # Multiple recognition options
  lang: 'en-US'              # Language setting
};
```

### AI Provider Priority
```javascript
// Fallback chain for voice processing
1. OpenAI GPT-3.5/4        # Primary AI provider
2. DeepSeek API            # Backup for text analysis  
3. HuggingFace Models      # Open-source fallback
4. Cohere AI               # Advanced NLP backup
5. Pattern Matching        # Basic intent detection
```

### Voice Response Customization
```javascript
// Text-to-speech configuration
const ttsConfig = {
  rate: 1.0,        # Speaking speed
  pitch: 1.0,       # Voice pitch
  volume: 0.8,      # Volume level
  voice: 'natural'  # Voice selection
};
```

## 🛡️ **Security Features**

### Voice Data Protection
- **No Voice Storage**: Audio data processed in real-time only
- **Client-Side Recognition**: Speech processing happens in browser
- **Encrypted Transmission**: All voice data sent over HTTPS
- **Privacy First**: No permanent voice recordings stored

### Authentication Security
- **Session-Based Voice Access**: Voice features require active login
- **Multi-Factor Support**: 2FA integration with voice interface
- **Rate Limiting**: Protection against voice command spam
- **Audit Logging**: All voice interactions logged for security

## 📱 **Browser Compatibility**

### Supported Browsers
- ✅ **Chrome 25+**: Full Web Speech API support
- ✅ **Edge 79+**: Complete voice recognition
- ✅ **Safari 14.1+**: iOS speech recognition support
- ✅ **Firefox 49+**: Limited speech synthesis
- ⚠️ **Mobile**: iOS Safari and Chrome Android supported

### Voice Features by Browser
| Feature | Chrome | Edge | Safari | Firefox |
|---------|--------|------|--------|---------|
| Speech Recognition | ✅ | ✅ | ✅ | ❌ |
| Text-to-Speech | ✅ | ✅ | ✅ | ✅ |
| Wake Words | ✅ | ✅ | ⚠️ | ❌ |
| Voice Commands | ✅ | ✅ | ✅ | ⚠️ |

## 🤖 **AI Service Setup**

### OpenAI Configuration
1. Sign up at [OpenAI](https://platform.openai.com/)
2. Generate API key
3. Add to `.env` as `OPENAI_API_KEY`
4. Recommended for best natural language understanding

### Cohere AI Setup  
1. Sign up at [Cohere](https://cohere.ai/)
2. Generate API key
3. Add to `.env` as `COHERE_API_KEY`
4. Excellent for event parsing and responses

### HuggingFace Setup
1. Sign up at [HuggingFace](https://huggingface.co/)
2. Generate access token
3. Add to `.env` as `HUGGING_FACE_TOKEN`
4. Free tier available for basic usage

### DeepSeek Setup (Optional)
1. Sign up at [DeepSeek](https://platform.deepseek.com/)
2. Generate API key
3. Add to `.env` as `DEEPSEEK_API_KEY`
4. Alternative AI provider for redundancy

## 🔧 **Troubleshooting**

### Common Voice Issues
```
❌ "Microphone not working"
✅ Check browser permissions for localhost:3000
✅ Ensure HTTPS in production
✅ Try Chrome/Edge for best compatibility

❌ "Voice commands not recognized"  
✅ Speak clearly and at normal pace
✅ Check microphone quality and background noise
✅ Verify AI API keys are configured

❌ "AI not responding"
✅ Check API quotas and billing
✅ Verify internet connection
✅ Try fallback providers (multiple AI services configured)

❌ "Calendar events not creating"
✅ Ensure Google OAuth is properly configured
✅ Check Google Calendar API permissions
✅ Verify user is logged in with calendar access
```

### Voice Recognition Optimization
- **Microphone Quality**: Use good quality microphone for best results
- **Background Noise**: Minimize background noise during recognition
- **Speaking Style**: Natural pace, clear enunciation works best
- **Command Structure**: Start with action word (create, delete, show)

## 🤝 **Contributing**

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-voice-enhancement`
3. Make your changes and test voice functionality
4. Commit your changes: `git commit -am 'Add voice feature'`
5. Push to the branch: `git push origin feature-voice-enhancement`
6. Submit a pull request

### Development Guidelines
- Test voice features across multiple browsers
- Follow TypeScript best practices for AI services
- Add comprehensive error handling for voice failures
- Ensure responsive design for voice interface
- Test with various microphone configurations

## 📊 **Performance Metrics**

### Voice Processing Performance
- **Recognition Latency**: < 500ms for command detection
- **AI Processing**: < 2 seconds for complex commands
- **Calendar Integration**: < 1 second for event creation
- **Response Generation**: < 800ms for voice feedback

### Scalability Features
- **Multi-AI Providers**: Automatic failover for high availability
- **Concurrent Voice Sessions**: Support for multiple users
- **Rate Limiting**: Voice command throttling for performance
- **Caching**: AI response caching for common commands

## 📝 **Changelog**

### Version 2.0 - AI Voice Assistant
- 🎤 **Complete voice control** for calendar operations
- 🧠 **Multi-AI provider integration** (OpenAI, Cohere, HuggingFace, DeepSeek)
- 🎨 **Apple-style voice interface** with glass morphism design
- 🔧 **Enhanced error handling** and browser compatibility
- 🌐 **Multi-language voice support** 
- 📱 **Mobile voice recognition** optimization
- 🔒 **Secure voice processing** with privacy protection

### Version 1.0 - Foundation
- 🔐 Enterprise-grade authentication system
- 📅 Google Calendar integration
- 💳 Stripe subscription management
- 📧 Gmail SMTP email system
- 🎨 Modern responsive UI design

## 📄 **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 **Acknowledgments**

- [OpenAI](https://openai.com/) for advanced natural language understanding
- [Cohere](https://cohere.ai/) for powerful text generation and event parsing
- [HuggingFace](https://huggingface.co/) for open-source AI model access
- [Web Speech API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Speech_API) for browser voice recognition
- [Google Calendar API](https://developers.google.com/calendar) for seamless integration
- [Stripe](https://stripe.com/) for secure payment processing

## 📞 **Support & Community**

- 🐛 [Report Issues](https://github.com/Nagavenkatasai7/ai-calender-agent/issues)
- 💬 [Start Discussion](https://github.com/Nagavenkatasai7/ai-calender-agent/discussions)
- 📧 Email: support@ai-voice-calendar.com
- 🎤 Voice Issues: [Voice Troubleshooting Guide](https://github.com/Nagavenkatasai7/ai-calender-agent/wiki/Voice-Troubleshooting)

---

**🎤 "Just speak, and your calendar listens."**

Transform your voice into organized calendar events with the power of AI. Experience the future of calendar management today!

*Made with ❤️ and 🎤 by Nagavenkata Sai* 