import { CohereClient } from 'cohere-ai';

export interface CohereConfig {
  apiKey: string;
  model?: string;
}

export interface CohereTextGeneration {
  text: string;
  confidence: number;
  model: string;
}

export class CohereAIService {
  private cohere: CohereClient;
  private config: CohereConfig;

  constructor(config: CohereConfig) {
    this.config = config;
    this.cohere = new CohereClient({
      token: config.apiKey,
    });
    
    console.log('🧠 Cohere AI service initialized');
  }

  // Enhanced text generation for calendar commands
  async generateCalendarResponse(prompt: string, context?: any): Promise<CohereTextGeneration> {
    try {
      const response = await this.cohere.chat({
        model: this.config.model || 'command',
        message: this.buildCalendarPrompt(prompt, context),
        maxTokens: 150,
        temperature: 0.7,
      });

      return {
        text: response.text || '',
        confidence: 0.8,
        model: this.config.model || 'command'
      };
    } catch (error) {
      console.error('Cohere generation error:', error);
      throw new Error(`Cohere generation failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Natural language event parsing
  async parseNaturalLanguageEvent(input: string): Promise<{
    title: string;
    startTime?: Date;
    endTime?: Date;
    location?: string;
    description?: string;
    category?: string;
    confidence: number;
  }> {
    try {
      const prompt = `Parse this natural language event into structured data:

"${input}"

Extract:
- Title (clear, concise)
- Start time (if mentioned)
- End time (if mentioned) 
- Location (if mentioned)
- Description (additional details)
- Category (work, personal, health, etc.)

Respond in JSON format with confidence score.`;

      const response = await this.cohere.chat({
        model: this.config.model || 'command',
        message: prompt,
        maxTokens: 150,
        temperature: 0.2,
      });

      try {
        const parsed = JSON.parse(response.text || '{}');
        return {
          title: parsed.title || input,
          startTime: parsed.startTime ? new Date(parsed.startTime) : undefined,
          endTime: parsed.endTime ? new Date(parsed.endTime) : undefined,
          location: parsed.location,
          description: parsed.description,
          category: parsed.category || 'general',
          confidence: parsed.confidence || 0.7
        };
      } catch (parseError) {
        // Fallback parsing
        return this.fallbackParseEvent(input);
      }
    } catch (error) {
      console.error('Cohere parsing error:', error);
      return this.fallbackParseEvent(input);
    }
  }

  // Check service health
  async healthCheck(): Promise<{
    status: 'healthy' | 'degraded' | 'down';
    model: string;
    capabilities: string[];
    error?: string;
  }> {
    try {
      // Test with a simple chat
      await this.cohere.chat({
        model: this.config.model || 'command',
        message: 'Test',
        maxTokens: 5,
      });

      return {
        status: 'healthy',
        model: this.config.model || 'command',
        capabilities: [
          'text-generation',
          'natural-language-parsing',
          'calendar-assistance'
        ]
      };
    } catch (error) {
      return {
        status: 'down',
        model: this.config.model || 'command',
        capabilities: [],
        error: error instanceof Error ? error.message : String(error)
      };
    }
  }

  // Private helper methods
  private buildCalendarPrompt(prompt: string, context?: any): string {
    const contextStr = context ? `Context: ${JSON.stringify(context)}\n` : '';
    return `${contextStr}You are a helpful calendar assistant. Respond naturally and helpfully to: ${prompt}`;
  }

  private fallbackParseEvent(input: string): any {
    return {
      title: input,
      confidence: 0.5,
      category: 'general'
    };
  }
} 