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
        
        // Ensure dates are properly formatted
        let startTime = undefined;
        let endTime = undefined;
        
        if (parsed.startTime) {
          try {
            startTime = new Date(parsed.startTime).toISOString();
          } catch (e) {
            console.warn('Invalid startTime, using fallback');
          }
        }
        
        if (parsed.endTime) {
          try {
            endTime = new Date(parsed.endTime).toISOString();
          } catch (e) {
            console.warn('Invalid endTime, using fallback');
          }
        }
        
        // If dates are missing, use fallback
        if (!startTime || !endTime) {
          const fallback = this.fallbackParseEvent(input);
          startTime = startTime || fallback.startTime;
          endTime = endTime || fallback.endTime;
        }
        
        return {
          title: parsed.title || input,
          startTime: startTime,
          endTime: endTime,
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
    // Basic pattern matching for date/time extraction
    const now = new Date();
    const tomorrow = new Date(now);
    tomorrow.setDate(tomorrow.getDate() + 1);
    
    // Set default time to 2 PM if no time specified
    let startTime = new Date(tomorrow);
    startTime.setHours(14, 0, 0, 0);
    
    // Look for time patterns
    const timeMatch = input.match(/(\d{1,2}):?(\d{2})?\s*(am|pm|a\.m\.|p\.m\.)/i);
    if (timeMatch) {
      let hours = parseInt(timeMatch[1]);
      const minutes = parseInt(timeMatch[2] || '0');
      const ampm = timeMatch[3].toLowerCase();
      
      if (ampm.includes('p') && hours !== 12) hours += 12;
      if (ampm.includes('a') && hours === 12) hours = 0;
      
      startTime.setHours(hours, minutes, 0, 0);
    }
    
    // Set end time 1 hour later
    const endTime = new Date(startTime);
    endTime.setHours(endTime.getHours() + 1);
    
    // Look for "today" vs "tomorrow"
    if (input.toLowerCase().includes('today')) {
      startTime = new Date(now);
      startTime.setHours(startTime.getHours(), startTime.getMinutes(), 0, 0);
      if (timeMatch) {
        let hours = parseInt(timeMatch[1]);
        const minutes = parseInt(timeMatch[2] || '0');
        const ampm = timeMatch[3].toLowerCase();
        
        if (ampm.includes('p') && hours !== 12) hours += 12;
        if (ampm.includes('a') && hours === 12) hours = 0;
        
        startTime.setHours(hours, minutes, 0, 0);
      }
      endTime.setTime(startTime.getTime() + 60 * 60 * 1000); // 1 hour later
    }
    
    return {
      title: input,
      startTime: startTime.toISOString(),
      endTime: endTime.toISOString(),
      confidence: 0.5,
      category: 'general'
    };
  }
} 