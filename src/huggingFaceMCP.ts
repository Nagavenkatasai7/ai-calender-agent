import { HfInference } from '@huggingface/inference';
import axios from 'axios';

export interface MCPConfiguration {
  huggingFaceToken: string;
  mcpServerUrl: string;
  headers?: Record<string, string>;
}

export interface AICapability {
  name: string;
  description: string;
  type: 'text-generation' | 'text-classification' | 'question-answering' | 'summarization' | 'translation' | 'image-classification' | 'automatic-speech-recognition' | 'text-to-speech';
  model: string;
  enabled: boolean;
}

export interface TextGenerationOptions {
  maxLength?: number;
  temperature?: number;
  topP?: number;
  doSample?: boolean;
  returnFullText?: boolean;
}

export interface TranslationOptions {
  sourceLanguage?: string;
  targetLanguage: string;
}

export interface SummarizationOptions {
  maxLength?: number;
  minLength?: number;
}

export class HuggingFaceMCPService {
  private hf: HfInference;
  private mcpConfig: MCPConfiguration;
  private capabilities: AICapability[] = [];

  constructor(config: MCPConfiguration) {
    this.mcpConfig = config;
    this.hf = new HfInference(config.huggingFaceToken);
    this.initializeCapabilities();
  }

  private initializeCapabilities() {
    this.capabilities = [
      {
        name: 'Text Generation',
        description: 'Generate text continuations, creative writing, code completion',
        type: 'text-generation',
        model: 'microsoft/DialoGPT-large',
        enabled: true
      },
      {
        name: 'Smart Summarization',
        description: 'Summarize calendar events, email content, and documents',
        type: 'summarization',
        model: 'facebook/bart-large-cnn',
        enabled: true
      },
      {
        name: 'Event Classification',
        description: 'Classify calendar events by type, priority, and category',
        type: 'text-classification',
        model: 'microsoft/DialoGPT-medium',
        enabled: true
      },
      {
        name: 'Smart Q&A',
        description: 'Answer questions about calendar content and scheduling',
        type: 'question-answering',
        model: 'deepset/roberta-base-squad2',
        enabled: true
      },
      {
        name: 'Multi-language Translation',
        description: 'Translate calendar events and reminders to different languages',
        type: 'translation',
        model: 'Helsinki-NLP/opus-mt-en-es',
        enabled: true
      },
      {
        name: 'Voice Recognition',
        description: 'Convert speech to text for voice commands',
        type: 'automatic-speech-recognition',
        model: 'openai/whisper-base',
        enabled: true
      },
      {
        name: 'Text-to-Speech',
        description: 'Convert calendar notifications to speech',
        type: 'text-to-speech',
        model: 'microsoft/speecht5_tts',
        enabled: true
      }
    ];
  }

  // Text Generation
  async generateText(prompt: string, options: TextGenerationOptions = {}): Promise<string> {
    try {
      const result = await this.hf.textGeneration({
        model: 'microsoft/DialoGPT-large',
        inputs: prompt,
        parameters: {
          max_new_tokens: options.maxLength || 100,
          temperature: options.temperature || 0.7,
          top_p: options.topP || 0.9,
          do_sample: options.doSample !== false,
          return_full_text: options.returnFullText || false
        }
      });

      return typeof result === 'string' ? result : result.generated_text || '';
    } catch (error) {
      console.error('Text generation error:', error);
      throw new Error(`Text generation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Smart Calendar Event Enhancement
  async enhanceCalendarEvent(eventDescription: string): Promise<{
    enhancedTitle: string;
    suggestedCategory: string;
    estimatedDuration: number;
    priority: 'high' | 'medium' | 'low';
    suggestedLocation?: string;
    preparationTime?: number;
  }> {
    try {
      const prompt = `Analyze this calendar event and provide structured enhancements:
Event: "${eventDescription}"

Please suggest:
1. A clear, professional title
2. Event category (meeting, personal, health, work, etc.)
3. Estimated duration in minutes
4. Priority level (high/medium/low)
5. Suggested location if applicable
6. Preparation time needed if applicable

Respond in JSON format.`;

      const response = await this.generateText(prompt, { maxLength: 200, temperature: 0.3 });
      
      // Try to parse JSON response, fallback to manual parsing
      try {
        return JSON.parse(response);
      } catch {
        // Fallback enhancement
        return {
          enhancedTitle: eventDescription.charAt(0).toUpperCase() + eventDescription.slice(1),
          suggestedCategory: this.classifyEventType(eventDescription),
          estimatedDuration: this.estimateEventDuration(eventDescription),
          priority: this.estimatePriority(eventDescription),
          suggestedLocation: this.suggestLocation(eventDescription),
          preparationTime: this.estimatePreparationTime(eventDescription)
        };
      }
    } catch (error) {
      console.error('Event enhancement error:', error);
      // Return basic enhancement
      return {
        enhancedTitle: eventDescription,
        suggestedCategory: 'general',
        estimatedDuration: 60,
        priority: 'medium'
      };
    }
  }

  // Summarize multiple events
  async summarizeEvents(events: any[], options: SummarizationOptions = {}): Promise<string> {
    try {
      const eventText = events.map(event => 
        `${event.title || event.summary} at ${event.start_time || event.startTime}`
      ).join('. ');

      const result = await this.hf.summarization({
        model: 'facebook/bart-large-cnn',
        inputs: `Today's schedule: ${eventText}`,
        parameters: {
          max_length: options.maxLength || 100,
          min_length: options.minLength || 20
        }
      });

      return result.summary_text || eventText;
    } catch (error) {
      console.error('Summarization error:', error);
      return `You have ${events.length} events scheduled today.`;
    }
  }

  // Classify event type
  async classifyEvent(eventText: string): Promise<{
    category: string;
    confidence: number;
    subcategory?: string;
  }> {
    try {
      const result = await this.hf.textClassification({
        model: 'microsoft/DialoGPT-medium',
        inputs: eventText
      });

      if (Array.isArray(result) && result.length > 0) {
        return {
          category: result[0].label || 'general',
          confidence: result[0].score || 0.5,
          subcategory: result[1]?.label
        };
      }

      return { category: 'general', confidence: 0.5 };
    } catch (error) {
      console.error('Classification error:', error);
      return { category: this.classifyEventType(eventText), confidence: 0.5 };
    }
  }

  // Question answering about calendar
  async answerCalendarQuestion(question: string, context: string): Promise<string> {
    try {
      const result = await this.hf.questionAnswering({
        model: 'deepset/roberta-base-squad2',
        inputs: {
          question: question,
          context: context
        }
      });

      return result.answer || "I couldn't find an answer to that question.";
    } catch (error) {
      console.error('Question answering error:', error);
      return "I'm unable to answer that question right now.";
    }
  }

  // Translate event to different language
  async translateEvent(eventText: string, options: TranslationOptions): Promise<string> {
    try {
      // Use different models based on target language
      const modelMap: Record<string, string> = {
        'es': 'Helsinki-NLP/opus-mt-en-es',
        'fr': 'Helsinki-NLP/opus-mt-en-fr',
        'de': 'Helsinki-NLP/opus-mt-en-de',
        'it': 'Helsinki-NLP/opus-mt-en-it',
        'pt': 'Helsinki-NLP/opus-mt-en-pt'
      };

      const model = modelMap[options.targetLanguage] || 'Helsinki-NLP/opus-mt-en-es';

      const result = await this.hf.translation({
        model: model,
        inputs: eventText
      });

      return Array.isArray(result) ? result[0]?.translation_text || eventText : (result as any).translation_text || eventText;
    } catch (error) {
      console.error('Translation error:', error);
      return eventText;
    }
  }

  // Voice command processing with Whisper
  async transcribeAudio(audioBlob: Blob): Promise<string> {
    try {
      const result = await this.hf.automaticSpeechRecognition({
        model: 'openai/whisper-base',
        data: audioBlob
      });

      return result.text || '';
    } catch (error) {
      console.error('Speech recognition error:', error);
      throw new Error('Speech recognition failed');
    }
  }

  // Generate smart suggestions for calendar events
  async generateEventSuggestions(userContext: {
    recentEvents: any[];
    preferences: any;
    currentTime: Date;
  }): Promise<string[]> {
    try {
      const contextText = `User's recent events: ${userContext.recentEvents.map(e => e.title).join(', ')}. 
Current time: ${userContext.currentTime.toISOString()}. 
User preferences: ${JSON.stringify(userContext.preferences)}`;

      const prompt = `Based on this user context, suggest 5 helpful calendar events or reminders they might want to add: ${contextText}`;
      
      const suggestions = await this.generateText(prompt, { maxLength: 200, temperature: 0.8 });
      
      // Parse suggestions into array
      return suggestions.split('\n').filter(s => s.trim().length > 0).slice(0, 5);
    } catch (error) {
      console.error('Suggestion generation error:', error);
      return [
        'Add a daily standup meeting',
        'Schedule weekly review session',
        'Set reminder for lunch break',
        'Plan weekend activities',
        'Schedule exercise time'
      ];
    }
  }

  // Smart conflict detection
  async detectEventConflicts(newEvent: any, existingEvents: any[]): Promise<{
    hasConflict: boolean;
    conflicts: any[];
    suggestions: string[];
  }> {
    try {
      const contextText = `New event: ${newEvent.title} at ${newEvent.startTime}. 
Existing events: ${existingEvents.map(e => `${e.title} at ${e.startTime}`).join(', ')}`;

      const prompt = `Analyze potential conflicts and suggest solutions: ${contextText}`;
      
      const analysis = await this.generateText(prompt, { maxLength: 150, temperature: 0.3 });
      
      // Simple conflict detection logic
      const conflicts = existingEvents.filter(event => {
        const eventStart = new Date(event.startTime || event.start_time);
        const eventEnd = new Date(event.endTime || event.end_time || eventStart.getTime() + 60*60*1000);
        const newStart = new Date(newEvent.startTime);
        const newEnd = new Date(newEvent.endTime || newStart.getTime() + 60*60*1000);

        return (newStart >= eventStart && newStart < eventEnd) || 
               (newEnd > eventStart && newEnd <= eventEnd) ||
               (newStart <= eventStart && newEnd >= eventEnd);
      });

      return {
        hasConflict: conflicts.length > 0,
        conflicts: conflicts,
        suggestions: analysis.split('\n').filter(s => s.trim().length > 0)
      };
    } catch (error) {
      console.error('Conflict detection error:', error);
      return {
        hasConflict: false,
        conflicts: [],
        suggestions: []
      };
    }
  }

  // Get available capabilities
  getCapabilities(): AICapability[] {
    return this.capabilities;
  }

  // Enable/disable capabilities
  toggleCapability(name: string, enabled: boolean): void {
    const capability = this.capabilities.find(c => c.name === name);
    if (capability) {
      capability.enabled = enabled;
    }
  }

  // Health check for HF connection
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'down';
    capabilities: string[];
    error?: string;
  }> {
    try {
      // Test with a simple text generation
      await this.generateText('Hello', { maxLength: 10 });
      
      return {
        status: 'healthy',
        capabilities: this.capabilities.filter(c => c.enabled).map(c => c.name)
      };
    } catch (error) {
      return {
        status: 'down',
        capabilities: [],
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Helper methods for fallback functionality
  private classifyEventType(eventText: string): string {
    const text = eventText.toLowerCase();
    if (text.includes('meeting') || text.includes('call') || text.includes('standup')) return 'meeting';
    if (text.includes('doctor') || text.includes('appointment') || text.includes('dentist')) return 'health';
    if (text.includes('gym') || text.includes('exercise') || text.includes('workout')) return 'fitness';
    if (text.includes('lunch') || text.includes('dinner') || text.includes('breakfast')) return 'food';
    if (text.includes('travel') || text.includes('flight') || text.includes('trip')) return 'travel';
    return 'general';
  }

  private estimateEventDuration(eventText: string): number {
    const text = eventText.toLowerCase();
    if (text.includes('quick') || text.includes('brief')) return 15;
    if (text.includes('meeting') || text.includes('call')) return 30;
    if (text.includes('workshop') || text.includes('training')) return 120;
    if (text.includes('conference') || text.includes('seminar')) return 480;
    return 60;
  }

  private estimatePriority(eventText: string): 'high' | 'medium' | 'low' {
    const text = eventText.toLowerCase();
    if (text.includes('urgent') || text.includes('important') || text.includes('critical')) return 'high';
    if (text.includes('optional') || text.includes('if time') || text.includes('maybe')) return 'low';
    return 'medium';
  }

  private suggestLocation(eventText: string): string | undefined {
    const text = eventText.toLowerCase();
    if (text.includes('call') || text.includes('zoom') || text.includes('teams')) return 'Video Call';
    if (text.includes('office') || text.includes('work')) return 'Office';
    if (text.includes('home')) return 'Home';
    if (text.includes('gym') || text.includes('fitness')) return 'Gym';
    if (text.includes('restaurant') || text.includes('lunch') || text.includes('dinner')) return 'Restaurant';
    return undefined;
  }

  private estimatePreparationTime(eventText: string): number | undefined {
    const text = eventText.toLowerCase();
    if (text.includes('presentation') || text.includes('demo')) return 30;
    if (text.includes('interview') || text.includes('meeting')) return 15;
    if (text.includes('travel') || text.includes('trip')) return 60;
    return undefined;
  }
} 