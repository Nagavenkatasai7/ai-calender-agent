import { CalendarAIAgent } from './calendarAIAgent';
import { HuggingFaceMCPService, MCPConfiguration } from './huggingFaceMCP';
// import { CohereAIService, CohereConfig } from './cohereAI';
import { SpeechRecognitionService } from './speechRecognition';
import { TextToSpeechService } from './textToSpeech';
import { ConversationContext } from './conversationContext';

export interface AIVoiceConfig {
  huggingFaceToken: string;
  cohereApiKey?: string;
  openAIKey?: string;
  enableAdvancedAI: boolean;
  enableVoiceCommands: boolean;
  enableSmartSuggestions: boolean;
  preferredLanguage: string;
  voiceSettings: {
    rate: number;
    pitch: number;
    volume: number;
    voice?: string;
  };
}

export interface VoiceCommand {
  id: string;
  transcript: string;
  confidence: number;
  intent: string;
  entities: any[];
  timestamp: Date;
  processed: boolean;
  response?: string;
}

export interface AIResponse {
  text: string;
  suggestions: string[];
  actionTaken?: string;
  needsConfirmation?: boolean;
  context?: any;
}

export class AIVoiceInterface {
  private calendarAgent: CalendarAIAgent;
  private hfMCP: HuggingFaceMCPService;
  private cohereAI: any | null = null;
  private speechService: SpeechRecognitionService;
  private ttsService: TextToSpeechService;
  private conversationContext: ConversationContext;
  private config: AIVoiceConfig;
  private isListening: boolean = false;
  private commandHistory: VoiceCommand[] = [];
  private currentLanguage: string = 'en';

  constructor(config: AIVoiceConfig, calendarAPI?: any) {
    this.config = config;
    
    // Initialize services (skip browser-specific ones on server)
    if (typeof window !== 'undefined') {
      this.speechService = new SpeechRecognitionService();
      this.ttsService = new TextToSpeechService();
    } else {
      // Server-side: create mock services that don't use browser APIs
      this.speechService = {
        isSupported: () => false,
        startListening: () => Promise.reject(new Error('Server environment')),
        stopListening: () => {},
      } as any;
      this.ttsService = {
        speak: () => Promise.resolve(),
        setRate: () => {},
        setPitch: () => {},
        setVolume: () => {},
        setVoice: () => {},
      } as any;
      console.log('🖥️ Server environment: Using mock voice services');
    }
    
    this.conversationContext = new ConversationContext();
    this.calendarAgent = new CalendarAIAgent(calendarAPI);
    
    // Initialize HuggingFace MCP
    const mcpConfig: MCPConfiguration = {
      huggingFaceToken: config.huggingFaceToken,
      mcpServerUrl: 'https://huggingface.co/mcp',
      headers: {
        'Authorization': `Bearer ${config.huggingFaceToken}`
      }
    };
    this.hfMCP = new HuggingFaceMCPService(mcpConfig);
    
    // Initialize Cohere AI if API key is provided
    if (config.cohereApiKey) {
      try {
        const { CohereAIService } = require('./cohereAI');
        const cohereConfig = {
          apiKey: config.cohereApiKey,
          model: 'command'
        };
        this.cohereAI = new CohereAIService(cohereConfig);
      } catch (error) {
        console.error('Failed to initialize Cohere AI:', error);
        this.cohereAI = null;
      }
    }
    
    this.currentLanguage = config.preferredLanguage || 'en';
    this.setupVoiceSettings();
    
    console.log('🤖 AI Voice Interface initialized with advanced capabilities');
  }

  private setupVoiceSettings(): void {
    // Configure TTS settings (only if in browser environment)
    if (typeof window !== 'undefined' && this.ttsService) {
      this.ttsService.setRate(this.config.voiceSettings.rate);
      this.ttsService.setPitch(this.config.voiceSettings.pitch);
      this.ttsService.setVolume(this.config.voiceSettings.volume);
      
      if (this.config.voiceSettings.voice) {
        this.ttsService.setVoice(this.config.voiceSettings.voice);
      }
    }
  }

  // Start comprehensive voice listening
  async startListening(): Promise<void> {
    if (this.isListening) {
      console.log('🎤 Already listening...');
      return;
    }

    if (!this.speechService.isSupported()) {
      throw new Error('Speech recognition not supported in this browser');
    }

    this.isListening = true;
    
    try {
      await this.ttsService.speak("Voice assistant activated. How can I help you today?");
      
      // Start continuous listening
      await this.startContinuousListening();
      
    } catch (error) {
      this.isListening = false;
      console.error('Voice listening error:', error);
      throw error;
    }
  }

  private async startContinuousListening(): Promise<void> {
    while (this.isListening) {
      try {
        console.log('🎤 Listening for voice command...');
        
        // Listen for speech with timeout
        const transcript = await Promise.race([
          this.speechService.startListening(),
          new Promise<string>((_, reject) => 
            setTimeout(() => reject(new Error('Listening timeout')), 30000)
          )
        ]);

        if (transcript && transcript.trim().length > 0) {
          await this.processVoiceCommand(transcript);
        }

        // Brief pause between listening sessions
        await new Promise(resolve => setTimeout(resolve, 1000));
        
      } catch (error) {
        if (error instanceof Error && error.message === 'Listening timeout') {
          console.log('🕐 Listening timeout, continuing...');
          continue;
        }
        
        console.error('Continuous listening error:', error);
        // Continue listening despite errors
        await new Promise(resolve => setTimeout(resolve, 2000));
      }
    }
  }

  // Process voice command with AI enhancement
  async processVoiceCommand(transcript: string): Promise<AIResponse> {
    const commandId = `cmd_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    
    const command: VoiceCommand = {
      id: commandId,
      transcript: transcript.trim(),
      confidence: 0.8, // Will be updated by AI analysis
      intent: 'unknown',
      entities: [],
      timestamp: new Date(),
      processed: false
    };

    this.commandHistory.push(command);
    console.log(`🎤 Processing voice command: "${transcript}"`);

    try {
      // Step 1: Enhance command understanding with HuggingFace
      const enhancedCommand = await this.enhanceCommandUnderstanding(command);
      
      // Step 2: Determine if this is a calendar command or general AI query
      const response = await this.routeCommand(enhancedCommand);
      
      // Step 3: Generate AI-powered suggestions
      if (this.config.enableSmartSuggestions) {
        response.suggestions = await this.generateSmartSuggestions(enhancedCommand, response);
      }
      
      // Step 4: Respond with voice
      await this.speakResponse(response);
      
      command.processed = true;
      command.response = response.text;
      
      return response;
      
    } catch (error) {
      console.error('Voice command processing error:', error);
      const errorResponse: AIResponse = {
        text: "I'm sorry, I encountered an error processing your request. Please try again.",
        suggestions: ["Try rephrasing your request", "Check your microphone", "Speak more clearly"]
      };
      
      await this.speakResponse(errorResponse);
      return errorResponse;
    }
  }

  private async enhanceCommandUnderstanding(command: VoiceCommand): Promise<VoiceCommand> {
    if (!this.config.enableAdvancedAI) {
      return command;
    }

    try {
      // Use HuggingFace for intent classification and entity extraction
      const classification = await this.hfMCP.classifyEvent(command.transcript);
      
      // Enhanced intent detection
      const intentPrompt = `Classify this voice command intent:
Command: "${command.transcript}"

Possible intents: create_event, query_events, delete_event, update_event, general_question, navigate_calendar, set_reminder, get_summary, translate_content, ask_question

Intent:`;

      const intentAnalysis = await this.hfMCP.generateText(intentPrompt, {
        maxLength: 20,
        temperature: 0.1
      });

      command.intent = this.extractIntent(intentAnalysis) || classification.category;
      command.confidence = classification.confidence;

      // Extract entities using AI
      const entityPrompt = `Extract entities from this command:
Command: "${command.transcript}"

Extract: dates, times, event titles, locations, people, durations
Format as JSON array:`;

      const entityAnalysis = await this.hfMCP.generateText(entityPrompt, {
        maxLength: 100,
        temperature: 0.2
      });

      try {
        command.entities = JSON.parse(entityAnalysis) || [];
      } catch {
        command.entities = this.extractBasicEntities(command.transcript);
      }

      console.log(`🧠 Enhanced command - Intent: ${command.intent}, Confidence: ${command.confidence}`);
      
    } catch (error) {
      console.error('Command enhancement error:', error);
      // Fallback to basic processing
      command.intent = this.detectBasicIntent(command.transcript);
      command.entities = this.extractBasicEntities(command.transcript);
    }

    return command;
  }

  private async routeCommand(command: VoiceCommand): Promise<AIResponse> {
    const calendarIntents = ['create_event', 'query_events', 'delete_event', 'update_event', 'navigate_calendar', 'set_reminder'];
    
    if (calendarIntents.includes(command.intent)) {
      // Route to calendar agent
      return await this.handleCalendarCommand(command);
    } else {
      // Handle as general AI query
      return await this.handleGeneralQuery(command);
    }
  }

  private async handleCalendarCommand(command: VoiceCommand): Promise<AIResponse> {
    try {
      // Process with calendar agent
      await this.calendarAgent.processTranscript(command.transcript);
      
      // Get context from conversation
      const context = {
        lastCommand: this.conversationContext.getLastCommand(),
        lastEvent: this.conversationContext.getLastEvent(),
        lastQuery: this.conversationContext.getLastQuery()
      };
      
      return {
        text: "I've processed your calendar request.",
        suggestions: this.conversationContext.getSuggestions(),
        actionTaken: command.intent,
        context: context
      };
      
    } catch (error) {
      console.error('Calendar command error:', error);
      return {
        text: "I couldn't process that calendar command. Could you please try again?",
        suggestions: ["Be more specific about dates and times", "Try a simpler command", "Check if you're logged in"]
      };
    }
  }

  private async handleGeneralQuery(command: VoiceCommand): Promise<AIResponse> {
    try {
      let responseText = '';
      const suggestions: string[] = [];

      switch (command.intent) {
        case 'general_question':
          // Use HuggingFace Q&A
          const calendarContext = this.getCalendarContext();
          responseText = await this.hfMCP.answerCalendarQuestion(command.transcript, calendarContext);
          suggestions.push("Ask about your schedule", "Get event summaries", "Check for conflicts");
          break;

        case 'get_summary':
          // Summarize recent events
          const recentEvents = await this.getRecentEvents();
          responseText = await this.hfMCP.summarizeEvents(recentEvents);
          suggestions.push("Get weekly summary", "Check today's agenda", "Review upcoming deadlines");
          break;

        case 'translate_content':
          // Extract target language and text to translate
          const translationData = this.extractTranslationRequest(command.transcript);
          if (translationData) {
            responseText = await this.hfMCP.translateEvent(translationData.text, {
              targetLanguage: translationData.targetLang
            });
          } else {
            responseText = "Please specify what you'd like to translate and to which language.";
          }
          suggestions.push("Translate to Spanish", "Translate to French", "Translate to German");
          break;

        default:
          // General AI conversation
          responseText = await this.hfMCP.generateText(
            `User said: "${command.transcript}". Respond helpfully as a calendar AI assistant.`,
            { maxLength: 100, temperature: 0.7 }
          );
          suggestions.push("Ask about your calendar", "Create an event", "Get your schedule");
      }

      return {
        text: responseText,
        suggestions: suggestions
      };

    } catch (error) {
      console.error('General query error:', error);
      return {
        text: "I can help you with calendar management, event creation, and scheduling questions. What would you like to do?",
        suggestions: ["Create a new event", "Check my schedule", "Set a reminder", "Get help"]
      };
    }
  }

  private async generateSmartSuggestions(command: VoiceCommand, response: AIResponse): Promise<string[]> {
    try {
      const userContext = {
        recentEvents: await this.getRecentEvents(),
        preferences: this.getUserPreferences(),
        currentTime: new Date()
      };

      const aiSuggestions = await this.hfMCP.generateEventSuggestions(userContext);
      
      // Combine with existing suggestions
      const allSuggestions = [...(response.suggestions || []), ...aiSuggestions];
      
      // Remove duplicates and limit to 5
      return [...new Set(allSuggestions)].slice(0, 5);
      
    } catch (error) {
      console.error('Smart suggestions error:', error);
      return response.suggestions || [];
    }
  }

  private async speakResponse(response: AIResponse): Promise<void> {
    if (!this.config.enableVoiceCommands) {
      return;
    }

    try {
      // Translate response if needed
      let textToSpeak = response.text;
      
      if (this.currentLanguage !== 'en') {
        textToSpeak = await this.hfMCP.translateEvent(response.text, {
          targetLanguage: this.currentLanguage
        });
      }

      await this.ttsService.speak(textToSpeak);
      
      // Optionally speak suggestions
      if (response.suggestions && response.suggestions.length > 0 && response.needsConfirmation) {
        const suggestionsText = `Here are some suggestions: ${response.suggestions.slice(0, 3).join(', ')}`;
        await this.ttsService.speak(suggestionsText);
      }
      
    } catch (error) {
      console.error('Speech response error:', error);
    }
  }

  // Stop listening
  stopListening(): void {
    this.isListening = false;
    this.speechService.stopListening();
    console.log('🔇 Voice listening stopped');
  }

  // Process text command (without voice)
  async processTextCommand(text: string): Promise<AIResponse> {
    return await this.processVoiceCommand(text);
  }

  // Get command history
  getCommandHistory(): VoiceCommand[] {
    return this.commandHistory.slice(-10); // Last 10 commands
  }

  // Check if voice is supported
  isVoiceSupported(): boolean {
    return this.speechService.isSupported();
  }

  // Get available AI capabilities
  getAICapabilities() {
    return this.hfMCP.getCapabilities();
  }

  // Health check
  async healthCheck(): Promise<{
    voiceRecognition: boolean;
    textToSpeech: boolean;
    huggingFace: any;
    cohere: any;
    calendar: boolean;
  }> {
    const cohereHealth = this.cohereAI ? await this.cohereAI.healthCheck() : { status: 'not_configured' };
    
    return {
      voiceRecognition: this.speechService.isSupported(),
      textToSpeech: true, // TTS is available if speechSynthesis exists
      huggingFace: await this.hfMCP.healthCheck(),
      cohere: cohereHealth,
      calendar: true // Assume calendar is working if no errors
    };
  }

  // Update configuration
  updateConfig(newConfig: Partial<AIVoiceConfig>): void {
    this.config = { ...this.config, ...newConfig };
    
    if (newConfig.voiceSettings) {
      this.setupVoiceSettings();
    }
    
    if (newConfig.preferredLanguage) {
      this.currentLanguage = newConfig.preferredLanguage;
    }
  }

  // Helper methods
  private extractIntent(aiResponse: string): string | null {
    const intents = ['create_event', 'query_events', 'delete_event', 'update_event', 'general_question', 'navigate_calendar', 'set_reminder', 'get_summary', 'translate_content', 'ask_question'];
    const response = aiResponse.toLowerCase();
    
    return intents.find(intent => response.includes(intent)) || null;
  }

  private detectBasicIntent(transcript: string): string {
    const text = transcript.toLowerCase();
    
    if (text.includes('create') || text.includes('add') || text.includes('schedule')) return 'create_event';
    if (text.includes('what') || text.includes('when') || text.includes('show') || text.includes('list')) return 'query_events';
    if (text.includes('delete') || text.includes('remove') || text.includes('cancel')) return 'delete_event';
    if (text.includes('update') || text.includes('change') || text.includes('modify')) return 'update_event';
    if (text.includes('remind') || text.includes('reminder')) return 'set_reminder';
    if (text.includes('summary') || text.includes('summarize')) return 'get_summary';
    if (text.includes('translate')) return 'translate_content';
    
    return 'general_question';
  }

  private extractBasicEntities(transcript: string): Array<{type: string, value: string}> {
    const entities: Array<{type: string, value: string}> = [];
    const text = transcript.toLowerCase();
    
    // Basic date/time detection
    const timePatterns = [
      /(\d{1,2}):(\d{2})\s*(am|pm)?/gi,
      /(today|tomorrow|yesterday)/gi,
      /(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/gi,
      /(january|february|march|april|may|june|july|august|september|october|november|december)/gi
    ];
    
    timePatterns.forEach(pattern => {
      const matches = text.match(pattern);
      if (matches) {
        entities.push(...matches.map(match => ({ type: 'datetime', value: match })));
      }
    });
    
    return entities;
  }

  private extractTranslationRequest(transcript: string): { text: string; targetLang: string } | null {
    const text = transcript.toLowerCase();
    const langMap: Record<string, string> = {
      'spanish': 'es',
      'french': 'fr',
      'german': 'de',
      'italian': 'it',
      'portuguese': 'pt'
    };
    
    for (const [lang, code] of Object.entries(langMap)) {
      if (text.includes(lang)) {
        // Extract text to translate (basic heuristic)
        const textToTranslate = transcript.split('translate')[1]?.split(lang)[0]?.trim() || transcript;
        return { text: textToTranslate, targetLang: code };
      }
    }
    
    return null;
  }

  private getCalendarContext(): string {
    // This would be implemented to get current calendar context
    return "User's calendar context and recent events...";
  }

  private async getRecentEvents(): Promise<any[]> {
    // This would be implemented to get recent calendar events
    return [];
  }

  private getUserPreferences(): any {
    // This would be implemented to get user preferences
    return {
      preferredMeetingLength: 30,
      workingHours: { start: 9, end: 17 },
      timezone: 'UTC'
    };
  }
} 