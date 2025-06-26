// Simple serverless function for Vercel
export default function handler(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  const { method, url } = req;

  // Health check
  if (url === '/health' || url === '/') {
    return res.status(200).json({ 
      status: 'ok', 
      message: '🎤 AI Voice Calendar Assistant',
      timestamp: new Date().toISOString(),
      version: '1.0.0'
    });
  }

  // Voice processing endpoint
  if (url === '/api/voice/process' && method === 'POST') {
    try {
      const { transcript } = req.body;
      
      if (!transcript) {
        return res.status(400).json({
          success: false,
          error: 'Transcript is required'
        });
      }

      // Simple intent detection
      const intent = detectIntent(transcript);
      let response = {
        text: `I understand you want to ${intent}. This is a demo response.`,
        suggestions: ["Try the full app", "Learn more", "Contact support"],
        transcript: transcript,
        intent: intent
      };

      if (intent === 'create_event') {
        response.text = `✅ I can help you create an event: "${transcript}". For full functionality, please use the complete app.`;
        response.suggestions = ["Use Full App", "Learn More", "Try Another Command"];
      } else if (intent === 'query_events') {
        response.text = "📅 I can help you check your schedule. For full calendar access, please use the complete app.";
        response.suggestions = ["Use Full App", "Today", "This Week"];
      } else if (intent === 'delete_event') {
        response.text = "🗑️ I can help you delete events. For full functionality, please use the complete app.";
        response.suggestions = ["Use Full App", "Show Events", "Cancel"];
      }

      return res.status(200).json({
        success: true,
        response: response,
        demo: true,
        fullAppUrl: "http://localhost:3000",
        message: "This is a demo. For full functionality, run the complete app locally."
      });

    } catch (error) {
      console.error('Voice processing error:', error);
      return res.status(500).json({
        success: false,
        error: 'Failed to process voice command',
        message: 'Demo service error'
      });
    }
  }

  // Default redirect to GitHub Pages
  if (method === 'GET') {
    return res.redirect(302, 'https://nagavenkatasai7.github.io/ai-calender-agent');
  }

  // 404 for other requests
  return res.status(404).json({
    error: 'Not Found',
    message: 'API endpoint not found',
    availableEndpoints: ['/health', '/api/voice/process'],
    fullApp: 'https://nagavenkatasai7.github.io/ai-calender-agent'
  });
}

// Simple intent detection function
function detectIntent(transcript) {
  const command = transcript.toLowerCase();
  
  if (command.includes('schedule') || command.includes('create') || command.includes('add') || 
      command.includes('book') || command.includes('plan') || command.includes('set up')) {
    return 'create_event';
  }
  
  if (command.includes('what') || command.includes('show') || command.includes('list') || 
      command.includes('my schedule') || command.includes('today') || command.includes('tomorrow')) {
    return 'query_events';
  }
  
  if (command.includes('delete') || command.includes('cancel') || command.includes('remove')) {
    return 'delete_event';
  }
  
  if (command.includes('help') || command.includes('what can you do')) {
    return 'help';
  }
  
  return 'unknown';
} 