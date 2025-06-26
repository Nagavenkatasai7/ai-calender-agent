const fs = require('fs');
const path = require('path');

// Robust serverless function for Vercel with complete web app
module.exports = async function handler(req, res) {
  try {
    console.log(`🚀 Incoming request: ${req.method} ${req.url}`);
    
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

    if (req.method === 'OPTIONS') {
      res.status(200).end();
      return;
    }

    const { method, url } = req;
    console.log(`📍 Processing: ${method} ${url}`);

    // Serve the main web application
    if (url === '/' && method === 'GET') {
      console.log('🏠 Serving main application page');
      
      const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🎤 AI Voice Calendar Assistant</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
        }
        
        .container {
            max-width: 800px;
            padding: 40px;
            text-align: center;
            backdrop-filter: blur(20px);
            background: rgba(255, 255, 255, 0.1);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        h1 {
            font-size: 3rem;
            margin-bottom: 20px;
            background: linear-gradient(45deg, #fff, #f0f0f0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .subtitle {
            font-size: 1.2rem;
            margin-bottom: 40px;
            opacity: 0.9;
        }
        
        .voice-interface {
            margin: 40px 0;
        }
        
        .microphone {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.2);
            border: 3px solid rgba(255, 255, 255, 0.3);
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 auto 30px;
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
        }
        
        .microphone:hover {
            transform: scale(1.1);
            background: rgba(255, 255, 255, 0.3);
        }
        
        .microphone.listening {
            background: rgba(255, 0, 100, 0.3);
            border-color: rgba(255, 0, 100, 0.5);
            animation: pulse 1.5s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
        
        .mic-icon {
            font-size: 40px;
        }
        
        .status {
            margin: 20px 0;
            font-size: 1.1rem;
            min-height: 30px;
        }
        
        .transcript {
            background: rgba(0, 0, 0, 0.2);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            min-height: 60px;
            font-style: italic;
        }
        
        .response {
            background: rgba(0, 0, 0, 0.3);
            padding: 20px;
            border-radius: 10px;
            margin: 20px 0;
            text-align: left;
        }
        
        .suggestions {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            justify-content: center;
            margin: 20px 0;
        }
        
        .suggestion {
            background: rgba(255, 255, 255, 0.2);
            padding: 8px 16px;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .suggestion:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        
        .features {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 40px 0;
        }
        
        .feature {
            background: rgba(255, 255, 255, 0.1);
            padding: 20px;
            border-radius: 15px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }
        
        .feature h3 {
            margin-bottom: 10px;
            font-size: 1.3rem;
        }
        
        .links {
            margin-top: 40px;
            display: flex;
            gap: 20px;
            justify-content: center;
            flex-wrap: wrap;
        }
        
        .link {
            background: rgba(255, 255, 255, 0.2);
            padding: 12px 24px;
            border-radius: 25px;
            text-decoration: none;
            color: white;
            transition: all 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .link:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }
        
        .error {
            color: #ffcccc;
            background: rgba(255, 0, 0, 0.2);
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
        }
        
        @media (max-width: 768px) {
            .container {
                margin: 20px;
                padding: 30px 20px;
            }
            
            h1 {
                font-size: 2rem;
            }
            
            .features {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎤 AI Voice Calendar Assistant</h1>
        <p class="subtitle">Speak naturally to create and manage your calendar events</p>
        
        <div class="voice-interface">
            <div class="microphone" id="microphone">
                <span class="mic-icon">🎤</span>
            </div>
            <div class="status" id="status">Click the microphone to start speaking</div>
            <div class="transcript" id="transcript">Your voice command will appear here...</div>
            <div class="response" id="response" style="display: none;"></div>
            <div class="suggestions" id="suggestions"></div>
        </div>
        
        <div class="features">
            <div class="feature">
                <h3>🗣️ Natural Speech</h3>
                <p>Just speak naturally: "Schedule a meeting with John tomorrow at 3pm"</p>
            </div>
            <div class="feature">
                <h3>🤖 AI Processing</h3>
                <p>Advanced AI understands context and creates accurate calendar events</p>
            </div>
            <div class="feature">
                <h3>📅 Smart Scheduling</h3>
                <p>Automatically detects dates, times, and event details from your speech</p>
            </div>
            <div class="feature">
                <h3>🔄 Real-time</h3>
                <p>Instant voice recognition and immediate calendar integration</p>
            </div>
        </div>
        
        <div class="links">
            <a href="https://nagavenkatasai7.github.io/ai-calender-agent" class="link" target="_blank">
                📱 GitHub Pages Demo
            </a>
            <a href="/api/status" class="link">
                📊 API Status
            </a>
            <a href="https://github.com/Nagavenkatasai7/ai-calender-agent" class="link" target="_blank">
                💻 Source Code
            </a>
        </div>
    </div>

    <script>
        class VoiceCalendarApp {
            constructor() {
                this.recognition = null;
                this.isListening = false;
                this.initializeElements();
                this.initializeSpeechRecognition();
                this.setupEventListeners();
            }
            
            initializeElements() {
                this.microphone = document.getElementById('microphone');
                this.status = document.getElementById('status');
                this.transcript = document.getElementById('transcript');
                this.response = document.getElementById('response');
                this.suggestions = document.getElementById('suggestions');
            }
            
            initializeSpeechRecognition() {
                if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
                    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
                    this.recognition = new SpeechRecognition();
                    
                    this.recognition.continuous = false;
                    this.recognition.interimResults = true;
                    this.recognition.lang = 'en-US';
                    
                    this.recognition.onstart = () => {
                        this.isListening = true;
                        this.microphone.classList.add('listening');
                        this.status.textContent = '🎤 Listening... Speak your calendar command';
                    };
                    
                    this.recognition.onresult = (event) => {
                        let finalTranscript = '';
                        let interimTranscript = '';
                        
                        for (let i = event.resultIndex; i < event.results.length; i++) {
                            const transcript = event.results[i][0].transcript;
                            if (event.results[i].isFinal) {
                                finalTranscript += transcript;
                            } else {
                                interimTranscript += transcript;
                            }
                        }
                        
                        this.transcript.textContent = finalTranscript || interimTranscript || 'Listening...';
                        
                        if (finalTranscript) {
                            this.processVoiceCommand(finalTranscript);
                        }
                    };
                    
                    this.recognition.onend = () => {
                        this.isListening = false;
                        this.microphone.classList.remove('listening');
                        if (!this.transcript.textContent || this.transcript.textContent === 'Listening...') {
                            this.status.textContent = 'Click the microphone to try again';
                            this.transcript.textContent = 'No speech detected. Please try again.';
                        }
                    };
                    
                    this.recognition.onerror = (event) => {
                        this.isListening = false;
                        this.microphone.classList.remove('listening');
                        this.status.textContent = 'Error occurred. Click to try again.';
                        this.transcript.textContent = \`Error: \${event.error}\`;
                        console.error('Speech recognition error:', event.error);
                    };
                } else {
                    this.status.textContent = '❌ Speech recognition not supported in this browser';
                    this.transcript.textContent = 'Please use Chrome, Edge, or Safari for voice features.';
                }
            }
            
            setupEventListeners() {
                this.microphone.addEventListener('click', () => {
                    this.toggleListening();
                });
                
                // Add example suggestions
                this.addSuggestions([
                    "Create meeting tomorrow at 3pm",
                    "Schedule lunch with Sarah next Friday",
                    "What's on my calendar today?",
                    "Delete my dentist appointment"
                ]);
            }
            
            toggleListening() {
                if (!this.recognition) {
                    this.status.textContent = '❌ Speech recognition not available';
                    return;
                }
                
                if (this.isListening) {
                    this.recognition.stop();
                } else {
                    this.transcript.textContent = 'Starting...';
                    this.status.textContent = 'Initializing microphone...';
                    this.recognition.start();
                }
            }
            
            async processVoiceCommand(transcript) {
                try {
                    this.status.textContent = '🤖 Processing your command...';
                    
                    const response = await fetch('/api/voice/process', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ transcript })
                    });
                    
                    const data = await response.json();
                    
                    if (data.success) {
                        this.displayResponse(data.response);
                        this.status.textContent = '✅ Command processed successfully';
                    } else {
                        this.status.textContent = '❌ Failed to process command';
                        this.displayError(data.error || 'Unknown error occurred');
                    }
                } catch (error) {
                    console.error('Error processing voice command:', error);
                    this.status.textContent = '❌ Network error occurred';
                    this.displayError('Failed to connect to voice processing service');
                }
            }
            
            displayResponse(responseData) {
                this.response.style.display = 'block';
                this.response.innerHTML = \`
                    <h3>🤖 AI Response:</h3>
                    <p>\${responseData.text}</p>
                    \${responseData.intent ? \`<p><strong>Intent:</strong> \${responseData.intent}</p>\` : ''}
                \`;
                
                if (responseData.suggestions) {
                    this.addSuggestions(responseData.suggestions);
                }
            }
            
            displayError(error) {
                this.response.style.display = 'block';
                this.response.innerHTML = \`<div class="error">❌ \${error}</div>\`;
            }
            
            addSuggestions(suggestions) {
                this.suggestions.innerHTML = '';
                suggestions.forEach(suggestion => {
                    const suggestionEl = document.createElement('div');
                    suggestionEl.className = 'suggestion';
                    suggestionEl.textContent = suggestion;
                    suggestionEl.addEventListener('click', () => {
                        this.transcript.textContent = suggestion;
                        this.processVoiceCommand(suggestion);
                    });
                    this.suggestions.appendChild(suggestionEl);
                });
            }
        }
        
        // Initialize the app when the page loads
        document.addEventListener('DOMContentLoaded', () => {
            new VoiceCalendarApp();
        });
    </script>
</body>
</html>`;
      
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.status(200).send(htmlContent);
    }

    // Health check endpoint
    if (url === '/health' || url === '/api/health') {
      console.log('✅ Health check requested');
      return res.status(200).json({ 
        status: 'ok', 
        message: '🎤 AI Voice Calendar Assistant - Web App',
        timestamp: new Date().toISOString(),
        version: '2.0.0',
        environment: 'production',
        features: ['voice_recognition', 'ai_processing', 'calendar_integration']
      });
    }

    // Voice processing endpoint
    if (url === '/api/voice/process' && method === 'POST') {
      console.log('🎤 Voice processing requested');
      
      try {
        const { transcript } = req.body || {};
        
        if (!transcript) {
          console.log('❌ No transcript provided');
          return res.status(400).json({
            success: false,
            error: 'Transcript is required',
            received: req.body
          });
        }

        console.log(`🗣️ Processing transcript: "${transcript}"`);

        // Simple intent detection (no external dependencies)
        const intent = detectIntent(transcript);
        console.log(`🎯 Detected intent: ${intent}`);
        
        let response = {
          text: `I understand you want to ${intent}. This is a serverless demo response.`,
          suggestions: ["Try the full app", "Learn more", "Contact support"],
          transcript: transcript,
          intent: intent,
          demo: true
        };

        if (intent === 'create_event') {
          response.text = `✅ I can help you create an event: "${transcript}". For full functionality with Google Calendar integration, please run the complete app locally.`;
          response.suggestions = ["Use Full App (localhost:3000)", "Learn More", "Try Another Command"];
        } else if (intent === 'query_events') {
          response.text = "📅 I can help you check your schedule. For full calendar access, please use the complete application.";
          response.suggestions = ["Use Full App (localhost:3000)", "Today", "This Week"];
        } else if (intent === 'delete_event') {
          response.text = "🗑️ I can help you delete events. For full functionality, please use the complete application.";
          response.suggestions = ["Use Full App (localhost:3000)", "Show Events", "Cancel"];
        }

        console.log('✅ Voice processing successful');
        return res.status(200).json({
          success: true,
          response: response,
          demo: true,
          serverless: true,
          fullAppUrl: "http://localhost:3000",
          message: "This is a serverless demo. For full functionality, run the complete app locally with: npm start"
        });

      } catch (voiceError) {
        console.error('❌ Voice processing error:', voiceError);
        return res.status(500).json({
          success: false,
          error: 'Voice processing failed',
          message: 'Serverless demo error',
          details: voiceError.message
        });
      }
    }

    // API status endpoint
    if (url === '/api/status') {
      console.log('📊 API status requested');
      return res.status(200).json({
        status: 'operational',
        endpoints: {
          webapp: '/',
          health: '/health',
          voiceProcessing: '/api/voice/process',
          status: '/api/status'
        },
        demo: true,
        features: ['web_interface', 'voice_recognition', 'ai_processing'],
        fullApp: 'http://localhost:3000'
      });
    }

    // 404 for other requests
    console.log(`❌ Endpoint not found: ${method} ${url}`);
    return res.status(404).json({
      error: 'Not Found',
      message: 'Endpoint not found',
      availableEndpoints: ['/', '/health', '/api/voice/process', '/api/status'],
      webApp: 'Visit / for the full web application',
      githubPages: 'https://nagavenkatasai7.github.io/ai-calender-agent',
      fullApp: 'http://localhost:3000'
    });

  } catch (error) {
    console.error('🚨 Serverless function error:', error);
    
    // Return a safe error response
    return res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Something went wrong in the serverless function',
      timestamp: new Date().toISOString(),
      details: process.env.NODE_ENV === 'development' ? error.message : 'Error details hidden in production'
    });
  }
};

// Simple intent detection function (no external dependencies)
function detectIntent(transcript) {
  if (!transcript || typeof transcript !== 'string') {
    return 'unknown';
  }
  
  const command = transcript.toLowerCase().trim();
  
  if (command.includes('schedule') || command.includes('create') || command.includes('add') || 
      command.includes('book') || command.includes('plan') || command.includes('set up') ||
      command.includes('meeting') || command.includes('appointment')) {
    return 'create_event';
  }
  
  if (command.includes('what') || command.includes('show') || command.includes('list') || 
      command.includes('my schedule') || command.includes('today') || command.includes('tomorrow') ||
      command.includes('calendar') || command.includes('events')) {
    return 'query_events';
  }
  
  if (command.includes('delete') || command.includes('cancel') || command.includes('remove') ||
      command.includes('clear') || command.includes('erase')) {
    return 'delete_event';
  }
  
  if (command.includes('help') || command.includes('what can you do') || command.includes('commands')) {
    return 'help';
  }
  
  return 'unknown';
}; 