// Add type definitions for Speech Recognition
declare global {
  interface Window {
    SpeechRecognition: any;
    webkitSpeechRecognition: any;
  }
}

export class SpeechRecognitionService {
  private recognition: any | null = null;
  private isListening: boolean = false;
  private isContinuous: boolean = false;

  constructor() {
    this.initializeRecognition();
  }

  private initializeRecognition() {
    // Check if we're in a browser environment
    if (typeof window === 'undefined') {
      console.log('Speech Recognition: Running in server environment, skipping initialization');
      return;
    }

    const SpeechRecognition = (window as any).SpeechRecognition || (window as any).webkitSpeechRecognition;
    
    if (!SpeechRecognition) {
      console.error('Speech Recognition not supported in this browser');
      return;
    }

    this.recognition = new SpeechRecognition();
    this.setupRecognition();
  }

  private setupRecognition() {
    if (!this.recognition) return;

    // Enhanced settings for better low-frequency voice detection
    this.recognition.continuous = false;
    this.recognition.interimResults = true; // Enable interim results for better responsiveness
    this.recognition.lang = 'en-US';
    this.recognition.maxAlternatives = 5; // More alternatives for better recognition
    
    // Enhanced audio processing settings
    if ('audioCapture' in this.recognition) {
      this.recognition.audioCapture = true;
    }
    
    // Set service parameters for better voice detection
    if ('serviceURI' in this.recognition) {
      this.recognition.serviceURI = null; // Use default service
    }
    
    console.log('🎤 Enhanced speech recognition configured for low-frequency voices');
  }

  async startListening(continuous: boolean = false): Promise<string> {
    if (!this.recognition) {
      throw new Error('Speech Recognition not available');
    }

    this.isContinuous = continuous;
    
    return new Promise((resolve, reject) => {
      if (!this.recognition) return reject('Speech Recognition not available');

      this.recognition.continuous = continuous;

      this.recognition.onresult = (event: any) => {
        let finalTranscript = '';
        let interimTranscript = '';

        // Process all results to capture low-volume speech
        for (let i = event.resultIndex; i < event.results.length; i++) {
          const result = event.results[i];
          const transcript = result[0].transcript.trim();
          
          if (result.isFinal) {
            finalTranscript += transcript;
            console.log('🎤 Final speech recognized:', transcript);
          } else {
            interimTranscript += transcript;
            console.log('🎤 Interim speech detected:', transcript);
          }
        }

        // Use final transcript if available, otherwise use interim for responsiveness
        const bestTranscript = finalTranscript || interimTranscript;
        
        if (bestTranscript && bestTranscript.length > 0) {
          if (!continuous) {
            resolve(bestTranscript);
          } else {
            // For continuous mode, we'll handle results differently
            this.handleContinuousResult(bestTranscript);
          }
        }
      };

      this.recognition.onerror = (event: any) => {
        console.error('Speech recognition error:', event.error);
        this.isListening = false;
        
        if (event.error === 'no-speech') {
          reject('No speech detected. Please try again.');
        } else if (event.error === 'network') {
          reject('Network error. Please check your connection.');
        } else {
          reject(`Speech recognition error: ${event.error}`);
        }
      };

      this.recognition.onend = () => {
        this.isListening = false;
        console.log('🎤 Speech recognition ended');
        
        if (continuous && this.isContinuous) {
          // Restart for continuous listening
          setTimeout(() => {
            if (this.isContinuous) {
              this.startContinuousListening();
            }
          }, 100);
        }
      };

      this.recognition.onstart = () => {
        this.isListening = true;
        console.log('🎤 Speech recognition started');
      };

      try {
        this.recognition.start();
      } catch (error) {
        console.error('Failed to start speech recognition:', error);
        reject(error);
      }
    });
  }

  private handleContinuousResult(transcript: string) {
    // Emit custom event for continuous results
    const event = new CustomEvent('speechResult', { 
      detail: { transcript } 
    });
    document.dispatchEvent(event);
  }

  startContinuousListening() {
    if (!this.recognition) return;
    
    this.isContinuous = true;
    this.startListening(true).catch(error => {
      console.error('Continuous listening error:', error);
      // Retry after a delay
      setTimeout(() => {
        if (this.isContinuous) {
          this.startContinuousListening();
        }
      }, 2000);
    });
  }

  stopListening() {
    if (this.recognition && this.isListening) {
      this.isContinuous = false;
      this.recognition.stop();
    }
  }

  isCurrentlyListening(): boolean {
    return this.isListening;
  }

  isSupported(): boolean {
    return this.recognition !== null;
  }

  // Get available languages
  getAvailableLanguages(): string[] {
    return [
      'en-US', 'en-GB', 'en-AU', 'en-CA', 'en-IN',
      'es-ES', 'es-MX', 'fr-FR', 'de-DE', 'it-IT',
      'pt-BR', 'ru-RU', 'ja-JP', 'ko-KR', 'zh-CN'
    ];
  }

  setLanguage(language: string) {
    if (this.recognition) {
      this.recognition.lang = language;
    }
  }
} 