import { SpeechRecognitionService } from './speechRecognition';
import { TextToSpeechService } from './textToSpeech';
import { CommandParser, CalendarCommand } from './commandParser';
import { ConversationContext } from './conversationContext';
import { WakeWordDetector } from './wakeWordDetector';

export class CalendarAIAgent {
  private speechService: SpeechRecognitionService;
  private ttsService: TextToSpeechService;
  private commandParser: CommandParser;
  private conversationContext: ConversationContext;
  private wakeWordDetector: WakeWordDetector;
  private isProcessing: boolean = false;
  private calendarAPI: any; // Will be injected

  constructor(calendarAPI?: any) {
    this.speechService = new SpeechRecognitionService();
    this.ttsService = new TextToSpeechService();
    this.commandParser = new CommandParser();
    this.conversationContext = new ConversationContext();
    this.wakeWordDetector = new WakeWordDetector();
    this.calendarAPI = calendarAPI;

    console.log('🤖 Calendar AI Agent initialized');
  }

  // Set calendar API adapter
  setCalendarAPI(calendarAPI: any) {
    this.calendarAPI = calendarAPI;
  }

  // Process single voice command
  async processVoiceCommand(): Promise<void> {
    if (this.isProcessing) {
      await this.ttsService.speak("I'm still processing your previous command. Please wait.");
      return;
    }

    this.isProcessing = true;

    try {
      console.log('🎤 Starting voice command processing...');
      
      // Listen for speech
      const transcript = await this.speechService.startListening();
      console.log('📝 Transcript:', transcript);

      await this.processTranscript(transcript);

    } catch (error) {
      console.error('Voice command error:', error);
      await this.ttsService.reportError('I couldn\'t understand your command. Please try again.');
    } finally {
      this.isProcessing = false;
    }
  }

  // Process transcript (can be called directly or from voice)
  async processTranscript(transcript: string): Promise<void> {
    // Check for follow-up commands first
    const followUp = this.conversationContext.interpretFollowUpCommand(transcript);
    
    let commandToProcess = transcript;
    
    if (followUp.isFollowUp) {
      if (followUp.interpretedCommand === 'confirm') {
        await this.handleConfirmation(true);
        return;
      } else if (followUp.interpretedCommand === 'deny') {
        await this.handleConfirmation(false);
        return;
      } else if (followUp.interpretedCommand) {
        commandToProcess = followUp.interpretedCommand;
      }
    }

    // Parse the command
    const command = this.commandParser.parseCommand(commandToProcess);
    
    if (!command) {
      await this.ttsService.askForClarification("I didn't understand that command.");
      return;
    }

    console.log('🧠 Parsed command:', command);

    // Store command in context
    this.conversationContext.setLastCommand(commandToProcess);

    // Execute the command
    await this.executeCommand(command);
  }

  // Execute parsed command
  private async executeCommand(command: CalendarCommand): Promise<void> {
    try {
      switch (command.action) {
        case 'create':
          await this.handleCreateEvent(command);
          break;
        case 'query':
          await this.handleQueryEvents(command);
          break;
        case 'delete':
          await this.handleDeleteEvent(command);
          break;
        case 'navigate':
          await this.handleNavigation(command);
          break;
        case 'update':
          await this.handleUpdateEvent(command);
          break;
        default:
          await this.ttsService.askForClarification("I'm not sure how to handle that command.");
      }
    } catch (error) {
      console.error('Command execution error:', error);
      await this.ttsService.reportError('I encountered an error while processing your request.');
    }
  }

  // Event creation
  private async handleCreateEvent(command: CalendarCommand): Promise<void> {
    const eventData = command.data;
    
    // Validate required data
    if (!eventData.title || !eventData.startTime) {
      await this.ttsService.askForClarification("I need a title and time for the event. Please provide more details.");
      return;
    }

    // Confirm before creating
    const confirmationMessage = `I'll create "${eventData.title}" on ${this.formatDate(eventData.startTime)} at ${this.formatTime(eventData.startTime)}. Should I proceed?`;
    
    await this.ttsService.speak(confirmationMessage);
    
    // Set pending confirmation
    this.conversationContext.setPendingConfirmation('create', eventData);
  }

  // Event querying
  private async handleQueryEvents(command: CalendarCommand): Promise<void> {
    const queryData = command.data;
    
    try {
      let events = [];
      
      if (queryData.date) {
        events = await this.calendarAPI.getEventsForDate(queryData.date);
      } else if (queryData.period === 'week') {
        events = await this.calendarAPI.getEventsForWeek();
      } else {
        events = await this.calendarAPI.getTodaysEvents();
      }

      if (events.length === 0) {
        await this.ttsService.speak("You have no events scheduled for that time.");
      } else {
        const eventList = events.map((event: any) => 
          `${event.title} at ${this.formatTime(new Date(event.start_time || event.startTime))}`
        ).join(', ');
        
        await this.ttsService.speak(`You have ${events.length} events: ${eventList}`);
      }

      // Store query result in context
      this.conversationContext.setLastQuery(queryData);

    } catch (error) {
      console.error('Query events error:', error);
      await this.ttsService.reportError('I couldn\'t retrieve your events right now.');
    }
  }

  // Event deletion
  private async handleDeleteEvent(command: CalendarCommand): Promise<void> {
    const deleteData = command.data;
    
    try {
      if (deleteData.type === 'title_search') {
        // Find events matching the identifier
        const events = await this.calendarAPI.searchEvents(deleteData.identifier);
        
        if (events.length === 0) {
          await this.ttsService.speak(`I couldn't find any events matching "${deleteData.identifier}".`);
          return;
        }
        
        if (events.length === 1) {
          // Confirm deletion
          const event = events[0];
          await this.ttsService.speak(`I found "${event.title}". Should I delete it?`);
          this.conversationContext.setPendingConfirmation('delete', { eventId: event.id, eventTitle: event.title });
        } else {
          // Multiple matches - ask for clarification
          const eventList = events.map((e: any, i: number) => `${i + 1}. ${e.title}`).join(', ');
          await this.ttsService.speak(`I found ${events.length} events: ${eventList}. Which one should I delete?`);
        }
      } else {
        await this.ttsService.askForClarification("Please specify which event you'd like to delete.");
      }
    } catch (error) {
      console.error('Delete event error:', error);
      await this.ttsService.reportError('I couldn\'t delete the event right now.');
    }
  }

  // Navigation
  private async handleNavigation(command: CalendarCommand): Promise<void> {
    const navData = command.data;
    
    try {
      if (navData.target) {
        await this.calendarAPI.navigateTo(navData.target);
        await this.ttsService.speak(`Navigated to ${navData.target}.`);
      } else {
        await this.ttsService.askForClarification("Where would you like me to navigate?");
      }
    } catch (error) {
      console.error('Navigation error:', error);
      await this.ttsService.reportError('I couldn\'t navigate to that view.');
    }
  }

  // Event updating
  private async handleUpdateEvent(command: CalendarCommand): Promise<void> {
    const updateData = command.data;
    
    await this.ttsService.speak("Event updating is not yet implemented. Please specify what you'd like to change.");
  }

  // Handle confirmations
  private async handleConfirmation(confirmed: boolean): Promise<void> {
    const pending = this.conversationContext.getPendingConfirmation();
    
    if (!pending) {
      await this.ttsService.speak("There's nothing to confirm right now.");
      return;
    }

    if (this.conversationContext.isConfirmationExpired()) {
      await this.ttsService.speak("That confirmation has expired. Please try your command again.");
      this.conversationContext.clearPendingConfirmation();
      return;
    }

    if (confirmed) {
      await this.executeConfirmedAction(pending);
    } else {
      await this.ttsService.speak("Okay, I've cancelled that action.");
    }

    this.conversationContext.clearPendingConfirmation();
  }

  // Execute confirmed actions
  private async executeConfirmedAction(pending: any): Promise<void> {
    try {
      switch (pending.action) {
        case 'create':
          const event = await this.calendarAPI.createEvent(pending.data);
          await this.ttsService.confirmAction(`Event "${pending.data.title}" created`);
          this.conversationContext.setLastEvent(event);
          break;
          
        case 'delete':
          await this.calendarAPI.deleteEvent(pending.data.eventId);
          await this.ttsService.confirmAction(`Event "${pending.data.eventTitle}" deleted`);
          break;
          
        default:
          await this.ttsService.speak("Action completed.");
      }
    } catch (error) {
      console.error('Confirmed action error:', error);
      await this.ttsService.reportError('I encountered an error while completing that action.');
    }
  }

  // Utility methods
  private formatDate(date: Date): string {
    const today = new Date();
    const tomorrow = new Date(today);
    tomorrow.setDate(tomorrow.getDate() + 1);

    if (this.isSameDay(date, today)) {
      return 'today';
    } else if (this.isSameDay(date, tomorrow)) {
      return 'tomorrow';
    } else {
      return date.toLocaleDateString('en-US', { 
        weekday: 'long', 
        month: 'long', 
        day: 'numeric' 
      });
    }
  }

  private formatTime(date: Date): string {
    return date.toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit', 
      hour12: true 
    });
  }

  private isSameDay(date1: Date, date2: Date): boolean {
    return date1.getFullYear() === date2.getFullYear() &&
           date1.getMonth() === date2.getMonth() &&
           date1.getDate() === date2.getDate();
  }

  // Public interface methods
  async startListening(): Promise<void> {
    await this.processVoiceCommand();
  }

  startWakeWordDetection(): void {
    this.wakeWordDetector.start((transcript) => {
      this.processTranscript(transcript);
    });
  }

  stopWakeWordDetection(): void {
    this.wakeWordDetector.stop();
  }

  async greet(): Promise<void> {
    await this.ttsService.greet();
  }

  getSuggestions(): string[] {
    return this.conversationContext.getSuggestions();
  }

  isSupported(): boolean {
    return this.speechService.isSupported();
  }
} 