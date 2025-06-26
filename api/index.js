// Robust serverless function for Vercel with proper error handling
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

    // Health check endpoint
    if (url === '/health' || url === '/' || url === '/api/health') {
      console.log('✅ Health check requested');
      return res.status(200).json({ 
        status: 'ok', 
        message: '🎤 AI Voice Calendar Assistant - Serverless Demo',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        environment: 'production'
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
          health: '/health',
          voiceProcessing: '/api/voice/process',
          status: '/api/status'
        },
        demo: true,
        fullApp: 'http://localhost:3000'
      });
    }

    // Default redirect to GitHub Pages for GET requests
    if (method === 'GET') {
      console.log('🔄 Redirecting to GitHub Pages');
      return res.redirect(302, 'https://nagavenkatasai7.github.io/ai-calender-agent');
    }

    // 404 for other requests
    console.log(`❌ Endpoint not found: ${method} ${url}`);
    return res.status(404).json({
      error: 'Not Found',
      message: 'API endpoint not found',
      availableEndpoints: ['/health', '/api/voice/process', '/api/status'],
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