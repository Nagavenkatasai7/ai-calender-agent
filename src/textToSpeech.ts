export class TextToSpeechService {
  private synth: SpeechSynthesis | null = null;
  private voice: SpeechSynthesisVoice | null = null;
  private rate: number = 1;
  private pitch: number = 1;
  private volume: number = 0.8;

  constructor() {
    // Check if we're in a browser environment
    if (typeof window === 'undefined') {
      console.log('Text-to-Speech: Running in server environment, skipping initialization');
      return;
    }
    
    this.synth = window.speechSynthesis;
    this.initializeVoice();
  }

  private initializeVoice() {
    if (!this.synth) return;
    
    // Wait for voices to load
    if (this.synth.getVoices().length === 0) {
      this.synth.onvoiceschanged = () => {
        this.selectBestVoice();
      };
    } else {
      this.selectBestVoice();
    }
  }

  private selectBestVoice() {
    if (!this.synth) return;
    const voices = this.synth.getVoices();
    
    // Prefer female English voices for assistant-like experience
    const preferredVoices = [
      'Samantha', 'Alex', 'Victoria', 'Allison', 'Ava',
      'Google US English', 'Microsoft Zira', 'Microsoft Hazel'
    ];

    for (const prefName of preferredVoices) {
      const voice = voices.find(v => v.name.includes(prefName));
      if (voice) {
        this.voice = voice;
        console.log('🔊 Selected voice:', voice.name);
        return;
      }
    }

    // Fallback to any English voice
    this.voice = voices.find(voice => voice.lang.startsWith('en')) || voices[0];
    if (this.voice) {
      console.log('🔊 Fallback voice selected:', this.voice.name);
    }
  }

  async speak(text: string, options?: {
    rate?: number;
    pitch?: number;
    volume?: number;
    interrupt?: boolean;
  }): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.synth) {
        reject(new Error('Text-to-speech not available in server environment'));
        return;
      }

      // Stop current speech if interrupt is true (default)
      if (options?.interrupt !== false) {
        this.stop();
      }

      const utterance = new SpeechSynthesisUtterance(text);
      
      if (this.voice) {
        utterance.voice = this.voice;
      }
      
      utterance.rate = options?.rate || this.rate;
      utterance.pitch = options?.pitch || this.pitch;
      utterance.volume = options?.volume || this.volume;

      utterance.onend = () => {
        console.log('🔊 Speech completed:', text);
        resolve();
      };

      utterance.onerror = (event) => {
        console.error('🔊 Speech error:', event.error);
        reject(new Error(`Speech synthesis error: ${event.error}`));
      };

      utterance.onstart = () => {
        console.log('🔊 Started speaking:', text);
      };

      try {
        this.synth.speak(utterance);
      } catch (error) {
        console.error('🔊 Failed to start speech:', error);
        reject(error);
      }
    });
  }

  stop() {
    if (this.synth?.speaking) {
      this.synth.cancel();
    }
  }

  isSpeaking(): boolean {
    return this.synth?.speaking || false;
  }

  // Set voice parameters
  setRate(rate: number) {
    this.rate = Math.max(0.1, Math.min(10, rate));
  }

  setPitch(pitch: number) {
    this.pitch = Math.max(0, Math.min(2, pitch));
  }

  setVolume(volume: number) {
    this.volume = Math.max(0, Math.min(1, volume));
  }

  // Get available voices
  getAvailableVoices(): SpeechSynthesisVoice[] {
    return this.synth?.getVoices() || [];
  }

  setVoice(voiceName: string) {
    if (!this.synth) return;
    
    const voices = this.synth.getVoices();
    const selectedVoice = voices.find(voice => 
      voice.name === voiceName || voice.name.includes(voiceName)
    );
    
    if (selectedVoice) {
      this.voice = selectedVoice;
      console.log('🔊 Voice changed to:', selectedVoice.name);
    }
  }

  // Quick response methods for common scenarios
  async confirmAction(action: string) {
    await this.speak(`✅ ${action} completed successfully.`);
  }

  async reportError(error: string) {
    await this.speak(`❌ Sorry, I encountered an error: ${error}`);
  }

  async askForClarification(message: string) {
    await this.speak(`🤔 ${message} Could you please clarify?`);
  }

  async greet() {
    const greetings = [
      "Hello! I'm your calendar assistant. How can I help you today?",
      "Hi there! Ready to manage your calendar with voice commands?",
      "Good day! I'm here to help you with your calendar. What would you like to do?"
    ];
    
    const greeting = greetings[Math.floor(Math.random() * greetings.length)];
    await this.speak(greeting);
  }
} 