import OpenAI from 'openai';

export interface ParsedReminder {
  title: string;
  description: string;
  startTime: Date;
  endTime: Date;
  timeZone: string;
  alertMinutes: number[]; // Minutes before event to send alerts (e.g., [60, 120] for 1hr and 2hr before)
  confidence?: number; // AI confidence score (0-1)
  location?: string;
  attendees?: string[];
  recurrenceRule?: string;
  isRecurring?: boolean;
  smartSuggestions?: {
    betterTimes?: string[];
    conflictWarnings?: string[];
    locationSuggestions?: string[];
  };
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

  async parseReminder(reminderText: string, hasAdvancedFeatures: boolean = false): Promise<ParsedReminder> {
    if (this.openai) {
      return hasAdvancedFeatures 
        ? this.parseWithAdvancedAI(reminderText)
        : this.parseWithOpenAI(reminderText);
    } else {
      // Fallback to simple parsing if no OpenAI key
      return this.parseWithFallback(reminderText, hasAdvancedFeatures);
    }
  }

  private async parseWithAdvancedAI(reminderText: string): Promise<ParsedReminder> {
    const prompt = `
You are an advanced AI calendar assistant for Pro subscribers. Parse the following reminder text with sophisticated natural language understanding.

Extract comprehensive event details and return a JSON object with:
- title: Event title (string)
- description: Detailed event description (string)
- startTime: ISO date string
- endTime: ISO date string (intelligently determine duration based on event type)
- timeZone: Timezone (default to America/New_York)
- alertMinutes: Array of minutes before event to send alerts
- location: Physical or virtual location if mentioned (string or null)
- attendees: Array of people mentioned (e.g., ["john@email.com", "Sarah"])
- recurrenceRule: RRULE string if recurring (e.g., "FREQ=WEEKLY;BYDAY=TU")
- isRecurring: Boolean if this is a recurring event
- smartSuggestions: Object with intelligent suggestions

Current date/time: ${new Date().toISOString()}

ADVANCED FEATURES FOR PRO USERS:

1. RECURRING EVENTS - Detect patterns:
   - "every Tuesday" → FREQ=WEEKLY;BYDAY=TU
   - "daily standup" → FREQ=DAILY
   - "monthly review" → FREQ=MONTHLY
   - "quarterly meeting" → FREQ=MONTHLY;INTERVAL=3
   - "every other Friday" → FREQ=WEEKLY;BYDAY=FR;INTERVAL=2

2. SMART DURATION:
   - "meeting" → 60 minutes
   - "standup" → 15 minutes
   - "lunch" → 90 minutes
   - "conference call" → 60 minutes
   - "quick sync" → 30 minutes
   - "presentation" → 45 minutes
   - "workshop" → 120 minutes

3. LOCATION DETECTION:
   - "in conference room A" → "Conference Room A"
   - "at 123 Main St" → "123 Main St"
   - "via Zoom" → "Zoom Meeting"
   - "on Teams" → "Microsoft Teams"
   - "downtown cafe" → "Downtown Cafe"

4. ATTENDEE DETECTION:
   - "with John and Sarah" → ["John", "Sarah"]
   - "team meeting" → suggest adding team members
   - "1:1 with manager" → suggest adding manager

5. SMART SCHEDULING:
   - Suggest better times for common business hours
   - Warn about potential conflicts (lunch time, end of day)
   - Suggest optimal meeting lengths

6. CONTEXT UNDERSTANDING:
   - "standup" implies daily recurring 15-min team meeting
   - "lunch date" implies 90-min social event
   - "doctor appointment" implies 60-min healthcare visit

Alert timing intelligence:
- Important meetings: [15, 60] (15min and 1hr before)
- Social events: [60] (1hr before)
- Daily tasks: [30] (30min before)
- Travel required: [120, 60, 15] (2hr, 1hr, 15min before)

Reminder text: "${reminderText}"

Return ONLY the JSON object with ALL fields, even if null/empty arrays:

{
  "title": "extracted title",
  "description": "detailed description",
  "startTime": "ISO date string",
  "endTime": "ISO date string",
  "timeZone": "America/New_York",
  "alertMinutes": [array of minutes],
  "location": "location or null",
  "attendees": ["array", "of", "attendees"],
  "recurrenceRule": "RRULE string or null",
  "isRecurring": boolean,
  "smartSuggestions": {
    "betterTimes": ["suggestion 1", "suggestion 2"],
    "conflictWarnings": ["warning 1"],
    "locationSuggestions": ["suggestion 1"]
  }
}`;

    try {
      const response = await this.openai!.chat.completions.create({
        model: 'gpt-4', // Using advanced model for Pro users
        messages: [{ role: 'user', content: prompt }],
        temperature: 0.2,
        max_tokens: 800,
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
        location: parsed.location,
        attendees: parsed.attendees || [],
        recurrenceRule: parsed.recurrenceRule,
        isRecurring: parsed.isRecurring || false,
        smartSuggestions: parsed.smartSuggestions || {},
        confidence: 0.95, // Very high confidence for GPT-4 with advanced prompting
      };
    } catch (error) {
      console.error('Error parsing reminder with advanced AI:', error);
      // Fallback to standard OpenAI parsing
      return this.parseWithOpenAI(reminderText);
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
        model: 'gpt-3.5-turbo', // Using cheaper model for free users
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
      return this.parseWithFallback(reminderText, false);
    }
  }

  private parseWithFallback(reminderText: string, hasAdvancedFeatures: boolean): ParsedReminder {
    // Enhanced fallback parsing for Pro users
    const now = new Date();
    
    // Extract alert timing
    const alertMinutes = this.extractAlertMinutes(reminderText);
    
    // Extract recurring patterns (Pro feature)
    let recurrenceRule: string | undefined = undefined;
    let isRecurring = false;
    
    if (hasAdvancedFeatures) {
      const recurringResult = this.extractRecurringPattern(reminderText);
      recurrenceRule = recurringResult.rule;
      isRecurring = recurringResult.isRecurring;
    }
    
    // Extract location (Pro feature)
    const location = hasAdvancedFeatures ? this.extractLocation(reminderText) : undefined;
    
    // Extract attendees (Pro feature)
    const attendees = hasAdvancedFeatures ? this.extractAttendees(reminderText) : [];
    
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
    
    // Smart duration detection (Pro feature)
    const duration = hasAdvancedFeatures ? this.getSmartDuration(reminderText) : 60;
    const endTime = new Date(startTime.getTime() + duration * 60 * 1000);
    
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
      .replace(/every\s+(day|week|month|year|monday|tuesday|wednesday|thursday|friday|saturday|sunday)/gi, '') // Remove recurring words
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
    
    // Generate smart suggestions for Pro users
    const smartSuggestions = hasAdvancedFeatures ? this.generateSmartSuggestions(reminderText, startTime) : undefined;
    
    return {
      title: title.charAt(0).toUpperCase() + title.slice(1),
      description: `Reminder: ${title}`,
      startTime,
      endTime,
      timeZone: 'America/New_York',
      alertMinutes,
      location,
      attendees,
      recurrenceRule,
      isRecurring,
      smartSuggestions,
      confidence: hasAdvancedFeatures ? 0.7 : 0.6, // Higher confidence for Pro parsing
    };
  }

  // Pro feature: Extract recurring patterns
  private extractRecurringPattern(text: string): { rule?: string; isRecurring: boolean } {
    const patterns = {
      'daily': 'FREQ=DAILY',
      'every day': 'FREQ=DAILY',
      'weekly': 'FREQ=WEEKLY',
      'every week': 'FREQ=WEEKLY',
      'monthly': 'FREQ=MONTHLY',
      'every month': 'FREQ=MONTHLY',
      'yearly': 'FREQ=YEARLY',
      'every year': 'FREQ=YEARLY',
      'every monday': 'FREQ=WEEKLY;BYDAY=MO',
      'every tuesday': 'FREQ=WEEKLY;BYDAY=TU',
      'every wednesday': 'FREQ=WEEKLY;BYDAY=WE',
      'every thursday': 'FREQ=WEEKLY;BYDAY=TH',
      'every friday': 'FREQ=WEEKLY;BYDAY=FR',
      'every saturday': 'FREQ=WEEKLY;BYDAY=SA',
      'every sunday': 'FREQ=WEEKLY;BYDAY=SU',
      'every other week': 'FREQ=WEEKLY;INTERVAL=2',
      'biweekly': 'FREQ=WEEKLY;INTERVAL=2',
      'quarterly': 'FREQ=MONTHLY;INTERVAL=3'
    };

    const lowerText = text.toLowerCase();
    for (const [pattern, rule] of Object.entries(patterns)) {
      if (lowerText.includes(pattern)) {
        return { rule, isRecurring: true };
      }
    }

    return { isRecurring: false };
  }

  // Pro feature: Extract location information
  private extractLocation(text: string): string | undefined {
    const locationPatterns = [
      /(?:at|in|@)\s+([^,\n]+(?:room|office|building|street|st|ave|avenue|blvd|boulevard|rd|road|conference|meeting))/i,
      /(?:via|on|using)\s+(zoom|teams|skype|slack|google meet|webex)/i,
      /(?:at|@)\s+(\d+[^,\n]*(?:street|st|ave|avenue|blvd|boulevard|rd|road))/i
    ];

    for (const pattern of locationPatterns) {
      const match = text.match(pattern);
      if (match) {
        return match[1].trim();
      }
    }

    return undefined;
  }

  // Pro feature: Extract attendees
  private extractAttendees(text: string): string[] {
    const attendeePatterns = [
      /(?:with|and)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/g,
      /(?:invite|including)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/g,
      /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g
    ];

    const attendees: string[] = [];
    
    for (const pattern of attendeePatterns) {
      const matches = text.matchAll(pattern);
      for (const match of matches) {
        if (match[1] && !attendees.includes(match[1])) {
          attendees.push(match[1].trim());
        }
      }
    }

    return attendees;
  }

  // Pro feature: Smart duration detection
  private getSmartDuration(text: string): number {
    const durationPatterns = {
      'standup': 15,
      'quick sync': 30,
      'sync': 30,
      'check-in': 30,
      'lunch': 90,
      'dinner': 120,
      'coffee': 60,
      'meeting': 60,
      'call': 60,
      'presentation': 45,
      'demo': 45,
      'workshop': 120,
      'training': 120,
      'conference': 480,
      'interview': 60,
      '1:1': 30,
      'one on one': 30,
      'review': 60,
      'planning': 90,
      'retrospective': 90,
      'retro': 90
    };

    const lowerText = text.toLowerCase();
    for (const [keyword, duration] of Object.entries(durationPatterns)) {
      if (lowerText.includes(keyword)) {
        return duration;
      }
    }

    return 60; // Default 1 hour
  }

  // Pro feature: Generate smart suggestions
  private generateSmartSuggestions(text: string, startTime: Date): ParsedReminder['smartSuggestions'] {
    const suggestions: ParsedReminder['smartSuggestions'] = {
      betterTimes: [],
      conflictWarnings: [],
      locationSuggestions: []
    };

    const hour = startTime.getHours();
    const day = startTime.getDay();

    // Time suggestions
    if (hour < 9) {
      suggestions.betterTimes?.push('Consider scheduling after 9 AM for better attendance');
    }
    if (hour > 17) {
      suggestions.betterTimes?.push('Evening meetings may have lower attendance');
    }
    if (hour >= 12 && hour <= 13) {
      suggestions.conflictWarnings?.push('This conflicts with typical lunch time');
    }

    // Weekend warnings
    if (day === 0 || day === 6) {
      suggestions.conflictWarnings?.push('Weekend meeting - consider rescheduling to weekday');
    }

    // Location suggestions based on meeting type
    const lowerText = text.toLowerCase();
    if (lowerText.includes('standup') || lowerText.includes('sync')) {
      suggestions.locationSuggestions?.push('Consider a video call for quick syncs');
    }
    if (lowerText.includes('lunch') || lowerText.includes('coffee')) {
      suggestions.locationSuggestions?.push('Consider a nearby cafe or restaurant');
    }
    if (lowerText.includes('presentation') || lowerText.includes('demo')) {
      suggestions.locationSuggestions?.push('Book a conference room with presentation equipment');
    }

    return suggestions;
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