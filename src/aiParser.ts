import OpenAI from 'openai';

export interface ParsedReminder {
  title: string;
  description: string;
  startTime: Date;
  endTime: Date;
  timeZone: string;
  alertMinutes: number[]; // Minutes before event to send alerts (e.g., [60, 120] for 1hr and 2hr before)
  confidence?: number; // AI confidence score (0-1)
}

export class AIReminderParser {
  private openai: OpenAI | null = null;

  constructor() {
    if (process.env.OPENAI_API_KEY) {
      this.openai = new OpenAI({
        apiKey: process.env.OPENAI_API_KEY,
      });
    }
  }

  async parseReminder(reminderText: string): Promise<ParsedReminder> {
    if (this.openai) {
      return this.parseWithOpenAI(reminderText);
    } else {
      // Fallback to simple parsing if no OpenAI key
      return this.parseWithFallback(reminderText);
    }
  }

  private async parseWithOpenAI(reminderText: string): Promise<ParsedReminder> {
    const prompt = `
Parse the following reminder text and extract event details. Return a JSON object with:
- title: Event title (string)
- description: Event description (string)
- startTime: ISO date string
- endTime: ISO date string (1 hour after start if not specified)
- timeZone: Timezone (default to America/New_York)
- alertMinutes: Array of minutes before event to send alerts (e.g., [60] for 1 hour before, [60, 120] for 1 and 2 hours before)

Current date/time: ${new Date().toISOString()}

Extract alert timing from phrases like:
- "remind me 1 hour before" → [60]
- "alert me 2 hours before" → [120]
- "send reminder 30 minutes and 1 hour before" → [30, 60]
- If no alert specified, default to [60] (1 hour before)

Reminder text: "${reminderText}"

Example response:
{
  "title": "Doctor Appointment",
  "description": "Annual checkup with Dr. Smith",
  "startTime": "2024-03-15T14:00:00.000Z",
  "endTime": "2024-03-15T15:00:00.000Z",
  "timeZone": "America/New_York",
  "alertMinutes": [60]
}

Return ONLY the JSON object, no additional text.`;

    try {
      const response = await this.openai!.chat.completions.create({
        model: 'gpt-3.5-turbo', // Using cheaper model
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.1,
        max_tokens: 500,
      });

      const content = response.choices[0].message.content;
      if (!content) throw new Error('No response from OpenAI');

      const parsed = JSON.parse(content);
      
      return {
        title: parsed.title,
        description: parsed.description,
        startTime: new Date(parsed.startTime),
        endTime: new Date(parsed.endTime),
        timeZone: parsed.timeZone,
        alertMinutes: Array.isArray(parsed.alertMinutes) ? parsed.alertMinutes : [60],
        confidence: 0.9, // High confidence for OpenAI parsing
      };
    } catch (error) {
      console.error('Error parsing reminder with OpenAI:', error);
      // Fallback to simple parsing
      return this.parseWithFallback(reminderText);
    }
  }

  private parseWithFallback(reminderText: string): ParsedReminder {
    // Simple regex-based parsing as fallback
    const now = new Date();
    
    // Extract alert timing
    const alertMinutes = this.extractAlertMinutes(reminderText);
    
    // Extract time patterns
    const timePatterns = [
      /(\d{1,2}):(\d{2})\s*(am|pm|AM|PM)/,
      /(\d{1,2})\s*(am|pm|AM|PM)/,
      /(\d{1,2}):(\d{2})/
    ];
    
    let startTime = new Date();
    let foundTime = false;
    
    for (const pattern of timePatterns) {
      const match = reminderText.match(pattern);
      if (match) {
        let hours = parseInt(match[1]);
        const minutes = match[2] ? parseInt(match[2]) : 0;
        const period = match[3] || match[2];
        
        if (period && period.toLowerCase().includes('pm') && hours !== 12) {
          hours += 12;
        } else if (period && period.toLowerCase().includes('am') && hours === 12) {
          hours = 0;
        }
        
        startTime.setHours(hours, minutes, 0, 0);
        foundTime = true;
        break;
      }
    }
    
    // If no specific time found, default to 1 hour from now
    if (!foundTime) {
      startTime = new Date(now.getTime() + 60 * 60 * 1000);
    }
    
    // Extract date patterns
    const datePatterns = [
      /tomorrow/i,
      /next\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/i,
      /(\d{1,2})\/(\d{1,2})/,
      /(\d{1,2})-(\d{1,2})/
    ];
    
    for (const pattern of datePatterns) {
      const match = reminderText.match(pattern);
      if (match) {
        if (match[0].toLowerCase() === 'tomorrow') {
          startTime.setDate(startTime.getDate() + 1);
        } else if (match[1] && this.isDayOfWeek(match[1])) {
          // Set to next occurrence of that day
          const targetDay = this.getDayOfWeek(match[1]);
          const today = now.getDay();
          const daysUntil = (targetDay - today + 7) % 7;
          startTime.setDate(now.getDate() + (daysUntil === 0 ? 7 : daysUntil));
        }
        break;
      }
    }
    
    const endTime = new Date(startTime.getTime() + 60 * 60 * 1000); // 1 hour duration
    
    // Extract clean title (remove all time, date, and command references)
    let title = reminderText
      .replace(/remind me to|remind me|alert me to|alert me|send reminder|schedule/gi, '')
      .replace(/\d{1,2}:\d{2}\s*(am|pm|a\.m\.|p\.m\.)?/gi, '') // Remove time formats
      .replace(/\d{1,2}\s*(am|pm|a\.m\.|p\.m\.)/gi, '') // Remove hour formats
      .replace(/at\s+\d+/gi, '') // Remove "at 6", "at 3" etc
      .replace(/\d+\s*(hour|minute)s?\s*before/gi, '') // Remove alert timing
      .replace(/tomorrow|today|tonight|this\s+evening/gi, '') // Remove date references
      .replace(/next\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday|week|month)/gi, '') // Remove future dates
      .replace(/on\s+(monday|tuesday|wednesday|thursday|friday|saturday|sunday)/gi, '') // Remove day references
      .replace(/\bat\s+/gi, '') // Remove remaining "at" words
      .replace(/\s+p\.m\.|p\.m\.|a\.m\.|a\.m\./gi, '') // Remove period markers
      .replace(/\s+/g, ' ') // Clean up multiple spaces
      .trim();
    
    // Handle edge cases where title becomes empty or too short
    if (!title || title.length < 2) {
      title = 'Reminder';
    }
    
    // Clean up any remaining artifacts
    title = title
      .replace(/^(to\s+|for\s+)/i, '') // Remove leading "to" or "for"
      .replace(/\s+(at|on|in)$/i, '') // Remove trailing prepositions
      .trim();
    
    return {
      title: title.charAt(0).toUpperCase() + title.slice(1),
      description: `Reminder: ${title}`,
      startTime,
      endTime,
      timeZone: 'America/New_York',
      alertMinutes,
      confidence: 0.6, // Lower confidence for fallback parsing
    };
  }
  
  private extractAlertMinutes(text: string): number[] {
    const alertPatterns = [
      /(\d+)\s*hour[s]?\s*before/gi,
      /(\d+)\s*minute[s]?\s*before/gi,
      /(\d+)\s*hr[s]?\s*before/gi,
      /(\d+)\s*min[s]?\s*before/gi
    ];
    
    const alerts: number[] = [];
    
    for (const pattern of alertPatterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        const value = parseInt(match[1]);
        if (pattern.source.includes('hour') || pattern.source.includes('hr')) {
          alerts.push(value * 60);
        } else {
          alerts.push(value);
        }
      }
    }
    
    return alerts.length > 0 ? alerts : [60]; // Default to 1 hour before
  }
  
  private isDayOfWeek(day: string): boolean {
    const days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
    return days.includes(day.toLowerCase());
  }
  
  private getDayOfWeek(day: string): number {
    const days = {
      'sunday': 0, 'monday': 1, 'tuesday': 2, 'wednesday': 3,
      'thursday': 4, 'friday': 5, 'saturday': 6
    };
    return days[day.toLowerCase() as keyof typeof days] || 1;
  }
} 