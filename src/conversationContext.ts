export interface ConversationState {
  lastCommand?: string;
  lastEvent?: any;
  lastQuery?: any;
  pendingConfirmation?: {
    action: string;
    data: any;
    timestamp: Date;
  };
  conversationHistory: ConversationEntry[];
}

export interface ConversationEntry {
  timestamp: Date;
  userInput: string;
  assistantResponse: string;
  action?: string;
  success?: boolean;
}

export class ConversationContext {
  private state: ConversationState;
  private maxHistoryLength = 10;

  constructor() {
    this.state = {
      conversationHistory: []
    };
  }

  // Conversation history management
  addToHistory(userInput: string, assistantResponse: string, action?: string, success?: boolean) {
    const entry: ConversationEntry = {
      timestamp: new Date(),
      userInput,
      assistantResponse,
      action,
      success
    };

    this.state.conversationHistory.unshift(entry);
    
    // Keep only recent entries
    if (this.state.conversationHistory.length > this.maxHistoryLength) {
      this.state.conversationHistory = this.state.conversationHistory.slice(0, this.maxHistoryLength);
    }
  }

  getRecentHistory(count: number = 3): ConversationEntry[] {
    return this.state.conversationHistory.slice(0, count);
  }

  // Command context
  setLastCommand(command: string) {
    this.state.lastCommand = command;
  }

  getLastCommand(): string | undefined {
    return this.state.lastCommand;
  }

  // Event context
  setLastEvent(event: any) {
    this.state.lastEvent = event;
  }

  getLastEvent(): any {
    return this.state.lastEvent;
  }

  // Query context
  setLastQuery(query: any) {
    this.state.lastQuery = query;
  }

  getLastQuery(): any {
    return this.state.lastQuery;
  }

  // Confirmation handling
  setPendingConfirmation(action: string, data: any) {
    this.state.pendingConfirmation = {
      action,
      data,
      timestamp: new Date()
    };
  }

  getPendingConfirmation(): { action: string; data: any; timestamp: Date } | undefined {
    return this.state.pendingConfirmation;
  }

  clearPendingConfirmation() {
    this.state.pendingConfirmation = undefined;
  }

  // Check if confirmation has expired (5 minutes)
  isConfirmationExpired(): boolean {
    if (!this.state.pendingConfirmation) return false;
    
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    return this.state.pendingConfirmation.timestamp < fiveMinutesAgo;
  }

  // Context-aware command interpretation
  interpretFollowUpCommand(command: string): {
    isFollowUp: boolean;
    interpretedCommand?: string;
    context?: any;
  } {
    const lowerCommand = command.toLowerCase().trim();

    // Handle confirmations
    if (this.state.pendingConfirmation && !this.isConfirmationExpired()) {
      if (this.isConfirmation(lowerCommand)) {
        return {
          isFollowUp: true,
          interpretedCommand: 'confirm',
          context: this.state.pendingConfirmation
        };
      }
      
      if (this.isDenial(lowerCommand)) {
        return {
          isFollowUp: true,
          interpretedCommand: 'deny',
          context: this.state.pendingConfirmation
        };
      }
    }

    // Handle pronoun references
    if (this.containsPronouns(lowerCommand)) {
      return this.resolvePronounReference(lowerCommand);
    }

    // Handle time modifications
    if (this.isTimeModification(lowerCommand)) {
      return this.resolveTimeModification(lowerCommand);
    }

    // Handle continuation commands
    if (this.isContinuation(lowerCommand)) {
      return this.resolveContinuation(lowerCommand);
    }

    return { isFollowUp: false };
  }

  private isConfirmation(command: string): boolean {
    const confirmWords = [
      'yes', 'yeah', 'yep', 'sure', 'okay', 'ok', 'confirm', 'correct',
      'that\'s right', 'sounds good', 'perfect', 'go ahead', 'proceed'
    ];
    return confirmWords.some(word => command.includes(word));
  }

  private isDenial(command: string): boolean {
    const denyWords = [
      'no', 'nope', 'cancel', 'never mind', 'forget it', 'stop',
      'don\'t', 'not right', 'incorrect', 'wrong'
    ];
    return denyWords.some(word => command.includes(word));
  }

  private containsPronouns(command: string): boolean {
    const pronouns = ['it', 'this', 'that', 'them', 'these', 'those'];
    return pronouns.some(pronoun => 
      new RegExp(`\\b${pronoun}\\b`, 'i').test(command)
    );
  }

  private resolvePronounReference(command: string): {
    isFollowUp: boolean;
    interpretedCommand?: string;
    context?: any;
  } {
    if (!this.state.lastEvent) {
      return { isFollowUp: false };
    }

    // Replace pronouns with actual event reference
    let resolvedCommand = command;
    const pronouns = ['it', 'this', 'that'];
    
    for (const pronoun of pronouns) {
      const regex = new RegExp(`\\b${pronoun}\\b`, 'gi');
      if (regex.test(resolvedCommand)) {
        resolvedCommand = resolvedCommand.replace(regex, `"${this.state.lastEvent.title}"`);
        break;
      }
    }

    return {
      isFollowUp: true,
      interpretedCommand: resolvedCommand,
      context: { lastEvent: this.state.lastEvent }
    };
  }

  private isTimeModification(command: string): boolean {
    const timeModWords = [
      'move', 'change', 'reschedule', 'shift', 'postpone', 'advance',
      'earlier', 'later', 'before', 'after'
    ];
    return timeModWords.some(word => command.includes(word));
  }

  private resolveTimeModification(command: string): {
    isFollowUp: boolean;
    interpretedCommand?: string;
    context?: any;
  } {
    if (!this.state.lastEvent) {
      return { isFollowUp: false };
    }

    return {
      isFollowUp: true,
      interpretedCommand: `reschedule "${this.state.lastEvent.title}" ${command}`,
      context: { lastEvent: this.state.lastEvent, action: 'reschedule' }
    };
  }

  private isContinuation(command: string): boolean {
    const continuationWords = [
      'and', 'also', 'plus', 'additionally', 'furthermore',
      'then', 'next', 'after that'
    ];
    return continuationWords.some(word => command.startsWith(word));
  }

  private resolveContinuation(command: string): {
    isFollowUp: boolean;
    interpretedCommand?: string;
    context?: any;
  } {
    // Remove continuation words and treat as new command
    const cleanCommand = command.replace(/^(and|also|plus|additionally|furthermore|then|next|after that)\s+/i, '');
    
    return {
      isFollowUp: true,
      interpretedCommand: cleanCommand,
      context: { isContinuation: true }
    };
  }

  // Smart suggestions based on context
  getSuggestions(): string[] {
    const suggestions: string[] = [];

    // Suggest follow-up actions for recent events
    if (this.state.lastEvent) {
      suggestions.push(`Edit "${this.state.lastEvent.title}"`);
      suggestions.push(`Delete "${this.state.lastEvent.title}"`);
      suggestions.push(`Reschedule "${this.state.lastEvent.title}"`);
    }

    // Suggest common queries
    const recentHistory = this.getRecentHistory(3);
    if (!recentHistory.some(entry => entry.action === 'query')) {
      suggestions.push("What's on my schedule today?");
      suggestions.push("Show me tomorrow's events");
    }

    // Suggest based on time of day
    const hour = new Date().getHours();
    if (hour >= 9 && hour <= 17) {
      suggestions.push("Schedule a meeting");
      suggestions.push("Block time for focus work");
    } else if (hour >= 17 && hour <= 21) {
      suggestions.push("Plan dinner");
      suggestions.push("Schedule personal time");
    }

    return suggestions.slice(0, 5); // Return max 5 suggestions
  }

  // Reset context (useful for new conversation sessions)
  reset() {
    this.state = {
      conversationHistory: []
    };
  }

  // Export/import context for persistence
  exportContext(): string {
    return JSON.stringify(this.state);
  }

  importContext(contextData: string) {
    try {
      const imported = JSON.parse(contextData);
      this.state = {
        ...imported,
        conversationHistory: imported.conversationHistory.map((entry: any) => ({
          ...entry,
          timestamp: new Date(entry.timestamp)
        }))
      };
    } catch (error) {
      console.error('Failed to import conversation context:', error);
    }
  }
} 