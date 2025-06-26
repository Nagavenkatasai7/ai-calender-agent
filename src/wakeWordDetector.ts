import { SpeechRecognitionService } from './speechRecognition';

export class WakeWordDetector {
  private speechService: SpeechRecognitionService;
  private isActive: boolean = false;
  private wakeWords = ['hey calendar', 'calendar', 'ok calendar'];
  private onWakeWordDetected?: (transcript: string) => void;

  constructor() {
    this.speechService = new SpeechRecognitionService();
  }

  start(onWakeWordDetected: (transcript: string) => void) {
    this.onWakeWordDetected = onWakeWordDetected;
    this.isActive = true;
    this.startListening();
  }

  stop() {
    this.isActive = false;
    this.speechService.stopListening();
  }

  private async startListening() {
    if (!this.isActive) return;

    try {
      // Listen for speech continuously
      document.addEventListener('speechResult', this.handleSpeechResult.bind(this));
      await this.speechService.startContinuousListening();
    } catch (error) {
      console.error('Wake word detection error:', error);
      // Retry after delay
      setTimeout(() => {
        if (this.isActive) {
          this.startListening();
        }
      }, 2000);
    }
  }

  private handleSpeechResult(event: any) {
    const transcript = event.detail.transcript.toLowerCase();
    
    if (this.containsWakeWord(transcript)) {
      console.log('🎯 Wake word detected:', transcript);
      
      // Extract command after wake word
      const command = this.extractCommand(transcript);
      
      if (this.onWakeWordDetected) {
        this.onWakeWordDetected(command || transcript);
      }
    }
  }

  private containsWakeWord(transcript: string): boolean {
    return this.wakeWords.some(wakeWord => {
      return this.fuzzyMatch(transcript, wakeWord);
    });
  }

  private fuzzyMatch(text: string, target: string): boolean {
    // Simple fuzzy matching - can be improved with more sophisticated algorithms
    const words = text.split(' ');
    const targetWords = target.split(' ');
    
    // Check if all target words are present in order (allowing gaps)
    let targetIndex = 0;
    for (const word of words) {
      if (targetIndex < targetWords.length && 
          this.isWordSimilar(word, targetWords[targetIndex])) {
        targetIndex++;
      }
    }
    
    return targetIndex === targetWords.length;
  }

  private isWordSimilar(word1: string, word2: string): boolean {
    // Simple similarity check - exact match or starts with
    return word1 === word2 || 
           word1.startsWith(word2) || 
           word2.startsWith(word1);
  }

  private extractCommand(transcript: string): string {
    // Remove wake words and return the remaining command
    let command = transcript;
    
    for (const wakeWord of this.wakeWords) {
      const index = command.indexOf(wakeWord);
      if (index !== -1) {
        command = command.substring(index + wakeWord.length).trim();
        break;
      }
    }
    
    return command;
  }

  isListening(): boolean {
    return this.isActive && this.speechService.isCurrentlyListening();
  }
} 