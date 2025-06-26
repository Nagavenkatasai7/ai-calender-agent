export interface CalendarCommand {
  action: 'create' | 'update' | 'delete' | 'query' | 'navigate' | 'unknown';
  data: any;
  confidence: number;
  originalText: string;
}

export interface EventData {
  title?: string;
  date?: Date;
  time?: string;
  startTime?: Date;
  endTime?: Date;
  duration?: number;
  location?: string;
  description?: string;
  category?: string;
}

export class CommandParser {
  private wakeWords = ['hey calendar', 'calendar', 'schedule', 'remind me'];
  
  parseCommand(transcript: string): CalendarCommand | null {
    const lowerText = transcript.toLowerCase().trim();
    console.log('🧠 Parsing command:', lowerText);

    // Check for wake words (optional - can be disabled for direct commands)
    if (!this.containsWakeWord(lowerText) && this.requiresWakeWord()) {
      return null;
    }

    // Remove wake words from the command
    const cleanText = this.removeWakeWords(lowerText);

    // Parse different command types
    if (this.isCreateCommand(cleanText)) {
      return this.parseCreateCommand(cleanText, transcript);
    }

    if (this.isQueryCommand(cleanText)) {
      return this.parseQueryCommand(cleanText, transcript);
    }

    if (this.isDeleteCommand(cleanText)) {
      return this.parseDeleteCommand(cleanText, transcript);
    }

    if (this.isNavigationCommand(cleanText)) {
      return this.parseNavigationCommand(cleanText, transcript);
    }

    if (this.isUpdateCommand(cleanText)) {
      return this.parseUpdateCommand(cleanText, transcript);
    }

    return {
      action: 'unknown',
      data: { text: cleanText },
      confidence: 0.1,
      originalText: transcript
    };
  }

  private containsWakeWord(text: string): boolean {
    return this.wakeWords.some(word => text.includes(word));
  }

  private requiresWakeWord(): boolean {
    // For now, return false to allow direct commands
    return false;
  }

  private removeWakeWords(text: string): string {
    let cleanText = text;
    this.wakeWords.forEach(word => {
      cleanText = cleanText.replace(new RegExp(word, 'gi'), '').trim();
    });
    return cleanText.replace(/^[,\s]+/, ''); // Remove leading commas and spaces
  }

  // Command type detection
  private isCreateCommand(text: string): boolean {
    const createKeywords = [
      'schedule', 'create', 'add', 'book', 'plan', 'set up', 'arrange',
      'meeting', 'appointment', 'event', 'reminder', 'call', 'lunch',
      'dinner', 'meeting with', 'conference', 'workshop'
    ];
    return createKeywords.some(keyword => text.includes(keyword));
  }

  private isQueryCommand(text: string): boolean {
    const queryKeywords = [
      'what', 'when', 'show', 'list', 'tell me', 'what\'s', 'check',
      'do i have', 'am i free', 'my schedule', 'today', 'tomorrow',
      'this week', 'next week', 'find', 'search'
    ];
    return queryKeywords.some(keyword => text.includes(keyword));
  }

  private isDeleteCommand(text: string): boolean {
    const deleteKeywords = [
      'cancel', 'delete', 'remove', 'clear', 'drop', 'unschedule',
      'cancel my', 'delete my', 'remove my'
    ];
    return deleteKeywords.some(keyword => text.includes(keyword));
  }

  private isNavigationCommand(text: string): boolean {
    const navKeywords = [
      'go to', 'show me', 'navigate to', 'jump to', 'open',
      'display', 'view'
    ];
    return navKeywords.some(keyword => text.includes(keyword));
  }

  private isUpdateCommand(text: string): boolean {
    const updateKeywords = [
      'change', 'modify', 'update', 'edit', 'move', 'reschedule',
      'shift', 'postpone', 'advance'
    ];
    return updateKeywords.some(keyword => text.includes(keyword));
  }

  // Command parsing methods
  private parseCreateCommand(text: string, original: string): CalendarCommand {
    const eventData = this.extractEventData(text);
    
    return {
      action: 'create',
      data: eventData,
      confidence: this.calculateConfidence(text, 'create'),
      originalText: original
    };
  }

  private parseQueryCommand(text: string, original: string): CalendarCommand {
    const queryData = this.extractQueryData(text);
    
    return {
      action: 'query',
      data: queryData,
      confidence: this.calculateConfidence(text, 'query'),
      originalText: original
    };
  }

  private parseDeleteCommand(text: string, original: string): CalendarCommand {
    const deleteData = this.extractDeleteData(text);
    
    return {
      action: 'delete',
      data: deleteData,
      confidence: this.calculateConfidence(text, 'delete'),
      originalText: original
    };
  }

  private parseNavigationCommand(text: string, original: string): CalendarCommand {
    const navData = this.extractNavigationData(text);
    
    return {
      action: 'navigate',
      data: navData,
      confidence: this.calculateConfidence(text, 'navigate'),
      originalText: original
    };
  }

  private parseUpdateCommand(text: string, original: string): CalendarCommand {
    const updateData = this.extractUpdateData(text);
    
    return {
      action: 'update',
      data: updateData,
      confidence: this.calculateConfidence(text, 'update'),
      originalText: original
    };
  }

  // Data extraction methods
  private extractEventData(text: string): EventData {
    const title = this.extractTitle(text);
    const dateTime = this.extractDateTime(text);
    const location = this.extractLocation(text);
    const duration = this.extractDuration(text);

    return {
      title,
      ...dateTime,
      location,
      duration,
      description: text,
      category: this.inferCategory(title)
    };
  }

  private extractTitle(text: string): string {
    // Remove command words and extract the main subject
    const patterns = [
      /(?:schedule|create|add|book|plan|set up|arrange)\s+(?:a\s+)?(.+?)(?:\s+at|\s+on|\s+for|\s+tomorrow|\s+today|\s+next|\s+this|$)/i,
      /(.+?)(?:\s+at|\s+on|\s+for|\s+tomorrow|\s+today|\s+next|\s+this|$)/i
    ];

    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        let title = match[1].trim();
        // Clean up common words
        title = title.replace(/^(a|an|the)\s+/i, '');
        title = title.replace(/\s+(meeting|appointment|event|call|session)$/i, ' $1');
        return this.capitalizeTitle(title);
      }
    }

    return 'New Event';
  }

  private extractDateTime(text: string): { startTime?: Date; endTime?: Date; date?: Date; time?: string } {
    const now = new Date();
    let startTime: Date | undefined;
    let endTime: Date | undefined;

    // Time patterns
    const timePattern = /(?:at\s+)?(\d{1,2}):?(\d{2})?\s*(am|pm)?/i;
    const timeMatch = text.match(timePattern);

    // Date patterns
    const datePatterns = [
      /(tomorrow)/i,
      /(today)/i,
      /(next\s+\w+)/i,
      /(this\s+\w+)/i,
      /on\s+(\w+)/i,
      /(\w+day)/i
    ];

    let targetDate = new Date(now);
    
    for (const pattern of datePatterns) {
      const match = text.match(pattern);
      if (match) {
        targetDate = this.parseRelativeDate(match[1].toLowerCase(), now);
        break;
      }
    }

    if (timeMatch) {
      const hour = parseInt(timeMatch[1]);
      const minute = parseInt(timeMatch[2] || '0');
      const period = timeMatch[3]?.toLowerCase();

      let hour24 = hour;
      if (period === 'pm' && hour !== 12) hour24 += 12;
      if (period === 'am' && hour === 12) hour24 = 0;

      startTime = new Date(targetDate);
      startTime.setHours(hour24, minute, 0, 0);

      // Default 1-hour duration
      endTime = new Date(startTime);
      endTime.setHours(startTime.getHours() + 1);
    } else {
      // Default to next hour if no time specified
      startTime = new Date(targetDate);
      startTime.setHours(now.getHours() + 1, 0, 0, 0);
      endTime = new Date(startTime);
      endTime.setHours(startTime.getHours() + 1);
    }

    return {
      startTime,
      endTime,
      date: targetDate,
      time: timeMatch ? timeMatch[0] : undefined
    };
  }

  private parseRelativeDate(dateStr: string, baseDate: Date): Date {
    const result = new Date(baseDate);

    if (dateStr === 'today') {
      return result;
    }

    if (dateStr === 'tomorrow') {
      result.setDate(result.getDate() + 1);
      return result;
    }

    if (dateStr.startsWith('next ')) {
      const day = dateStr.replace('next ', '');
      return this.getNextWeekday(day, result);
    }

    if (dateStr.startsWith('this ')) {
      const day = dateStr.replace('this ', '');
      return this.getThisWeekday(day, result);
    }

    if (dateStr.endsWith('day')) {
      return this.getNextWeekday(dateStr, result);
    }

    return result;
  }

  private getNextWeekday(dayName: string, baseDate: Date): Date {
    const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const targetDay = days.indexOf(dayName.toLowerCase());
    
    if (targetDay === -1) return baseDate;

    const result = new Date(baseDate);
    const currentDay = result.getDay();
    let daysToAdd = targetDay - currentDay;
    
    if (daysToAdd <= 0) {
      daysToAdd += 7; // Next week
    }
    
    result.setDate(result.getDate() + daysToAdd);
    return result;
  }

  private getThisWeekday(dayName: string, baseDate: Date): Date {
    const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const targetDay = days.indexOf(dayName.toLowerCase());
    
    if (targetDay === -1) return baseDate;

    const result = new Date(baseDate);
    const currentDay = result.getDay();
    const daysToAdd = targetDay - currentDay;
    
    result.setDate(result.getDate() + daysToAdd);
    return result;
  }

  private extractLocation(text: string): string | undefined {
    const locationPatterns = [
      /(?:at|in|@)\s+([^,\n]+?)(?:\s+at\s+\d|\s+on\s+|$)/i,
      /location\s+([^,\n]+)/i
    ];

    for (const pattern of locationPatterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        return match[1].trim();
      }
    }

    return undefined;
  }

  private extractDuration(text: string): number | undefined {
    const durationPatterns = [
      /for\s+(\d+)\s*(hour|hr|h)s?/i,
      /for\s+(\d+)\s*(minute|min|m)s?/i,
      /(\d+)\s*(hour|hr|h)s?\s+long/i,
      /(\d+)\s*(minute|min|m)s?\s+long/i
    ];

    for (const pattern of durationPatterns) {
      const match = text.match(pattern);
      if (match) {
        const value = parseInt(match[1]);
        const unit = match[2].toLowerCase();
        
        if (unit.startsWith('h')) {
          return value * 60; // Convert to minutes
        } else {
          return value; // Already in minutes
        }
      }
    }

    return undefined;
  }

  private extractQueryData(text: string): any {
    const queryData: any = {};

    // Date queries
    if (text.includes('today')) {
      queryData.date = new Date();
    } else if (text.includes('tomorrow')) {
      const tomorrow = new Date();
      tomorrow.setDate(tomorrow.getDate() + 1);
      queryData.date = tomorrow;
    } else if (text.includes('this week')) {
      queryData.period = 'week';
    } else if (text.includes('next week')) {
      queryData.period = 'next_week';
    }

    // Query type
    if (text.includes('free') || text.includes('available')) {
      queryData.type = 'availability';
    } else {
      queryData.type = 'events';
    }

    return queryData;
  }

  private extractDeleteData(text: string): any {
    // Try to extract event identifier
    const patterns = [
      /(?:cancel|delete|remove)\s+(?:my\s+)?(.+?)(?:\s+today|\s+tomorrow|\s+on|\s+at|$)/i,
      /(?:cancel|delete|remove)\s+(.+)/i
    ];

    for (const pattern of patterns) {
      const match = text.match(pattern);
      if (match && match[1]) {
        return {
          identifier: match[1].trim(),
          type: 'title_search'
        };
      }
    }

    return { type: 'prompt_selection' };
  }

  private extractNavigationData(text: string): any {
    const navData: any = {};

    if (text.includes('today')) {
      navData.target = 'today';
    } else if (text.includes('tomorrow')) {
      navData.target = 'tomorrow';
    } else if (text.includes('week')) {
      navData.target = 'week';
    } else if (text.includes('month')) {
      navData.target = 'month';
    }

    return navData;
  }

  private extractUpdateData(text: string): any {
    // This would be more complex in a real implementation
    return {
      type: 'general_update',
      text: text
    };
  }

  private inferCategory(title: string): string {
    const categories: { [key: string]: string[] } = {
      'meeting': ['meeting', 'call', 'conference', 'standup', 'sync'],
      'appointment': ['appointment', 'doctor', 'dentist', 'checkup'],
      'personal': ['lunch', 'dinner', 'birthday', 'anniversary'],
      'work': ['review', 'presentation', 'deadline', 'project'],
      'social': ['party', 'hangout', 'drinks', 'coffee']
    };

    const lowerTitle = title.toLowerCase();
    
    for (const [category, keywords] of Object.entries(categories)) {
      if (keywords.some(keyword => lowerTitle.includes(keyword))) {
        return category;
      }
    }

    return 'general';
  }

  private capitalizeTitle(title: string): string {
    return title.split(' ')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(' ');
  }

  private calculateConfidence(text: string, action: string): number {
    let confidence = 0.5; // Base confidence

    // Increase confidence based on specific keywords
    const actionKeywords = {
      'create': ['schedule', 'create', 'add', 'book', 'plan'],
      'query': ['what', 'when', 'show', 'list', 'tell me'],
      'delete': ['cancel', 'delete', 'remove'],
      'navigate': ['go to', 'show me', 'navigate'],
      'update': ['change', 'modify', 'update', 'reschedule']
    };

    const keywords = actionKeywords[action as keyof typeof actionKeywords] || [];
    const keywordCount = keywords.filter(keyword => text.includes(keyword)).length;
    confidence += keywordCount * 0.1;

    // Increase confidence if time/date is specified
    if (/\d{1,2}:?\d{0,2}\s*(am|pm)?/.test(text)) {
      confidence += 0.2;
    }

    if (/(today|tomorrow|next|this)/.test(text)) {
      confidence += 0.1;
    }

    return Math.min(confidence, 1.0);
  }
} 