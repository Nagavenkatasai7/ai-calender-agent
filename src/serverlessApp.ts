import express, { Request, Response } from 'express';
import session from 'express-session';
import path from 'path';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import { Database, User } from './database';
import { AIReminderParser } from './aiParser';
import { CalendarService } from './calendar';
import { EmailService } from './emailService';
import { SubscriptionService } from './subscriptionService';
import { AuthService, AuthConfig } from './auth';
import { HuggingFaceMCPService } from './huggingFaceMCP';

dotenv.config();

// Extend session interface locally
declare module 'express-session' {
  interface SessionData {
    userEmail?: string;
    userId?: string;
    tokens?: {
      access_token?: string;
      refresh_token?: string;
      scope?: string;
      token_type?: string;
      expiry_date?: number;
    };
    pendingTwoFactor?: boolean;
    twoFactorUserId?: string;
    twoFactorVerified?: boolean;
    sessionId?: string;
    loginTime?: Date;
    lastActivity?: Date;
  }
}

export class ServerlessAIReminderApp {
  private app: express.Application;
  private database: Database;
  private aiParser: AIReminderParser;
  private calendarService: CalendarService;
  private emailService: EmailService;
  private subscriptionService: SubscriptionService;
  private authService: AuthService;
  private oauth2Client: OAuth2Client;
  private hfMCPService: HuggingFaceMCPService | null = null;
  private cohereService: any | null = null;

  constructor() {
    this.app = express();
    
    // Initialize services
    this.database = new Database();
    this.aiParser = new AIReminderParser();
    this.calendarService = new CalendarService();
    this.emailService = new EmailService();
    this.subscriptionService = new SubscriptionService(this.database);
    
    // Initialize enhanced auth service
    const authConfig: AuthConfig = {
      jwtSecret: process.env.JWT_SECRET || 'ai-reminder-jwt-secret-change-in-production',
      sessionSecret: process.env.SESSION_SECRET || 'ai-reminder-session-secret',
      bcryptRounds: 12,
      maxLoginAttempts: 5,
      lockoutTime: 15 * 60 * 1000, // 15 minutes
      sessionTimeout: 24 * 60 * 60 * 1000, // 24 hours
      requireTwoFactor: false // Can be enabled per user
    };
    this.authService = new AuthService(this.database, authConfig);
    
    // Initialize OAuth2 client
    this.oauth2Client = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );

    this.setupMiddleware();
    this.setupRoutes();
  }

  private setupMiddleware() {
    // Security headers
    this.app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "https://js.stripe.com", "https://checkout.stripe.com"],
          styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
          fontSrc: ["'self'", "https://fonts.gstatic.com"],
          imgSrc: ["'self'", "data:", "https:"],
          connectSrc: ["'self'", "https://api.stripe.com"],
          frameSrc: ["https://js.stripe.com", "https://hooks.stripe.com", "https://checkout.stripe.com"]
        }
      }
    }));

    // Apply custom security headers
    this.app.use(this.authService.createSecurityHeadersMiddleware());

    // Rate limiting
    const limiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100, // limit each IP to 100 requests per windowMs
      message: 'Too many requests from this IP, please try again later.'
    });
    this.app.use(limiter);

    // Body parsing
    this.app.use(express.json({ limit: '10mb' }));
    this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
    
    // Session configuration
    this.app.use(session({
      secret: process.env.SESSION_SECRET || 'ai-reminder-secret-key',
      resave: false,
      saveUninitialized: true,
      name: 'ai-reminder-session',
      cookie: { 
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'lax'
      }
    }));
  }

  private setupRoutes() {
    // Health check
    this.app.get('/health', (req: Request, res: Response) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // Serverless voice processing - no browser APIs
    this.app.post('/api/voice/process', async (req: Request, res: Response) => {
      try {
        const { transcript } = req.body;
        
        if (!transcript || transcript.trim().length === 0) {
          return res.status(400).json({
            success: false,
            error: 'Voice transcript is required'
          });
        }

        console.log(`🎤 Processing voice command: "${transcript}"`);

        // Simple server-side processing without browser APIs
        const intent = this.detectBasicIntent(transcript);
        let response: any = {
          text: "I understand your request.",
          suggestions: [],
          transcript: transcript,
          intent: intent
        };

        if (intent === 'create_event') {
          // Try to use Cohere for parsing
          try {
            if (process.env.COHERE_API_KEY) {
              if (!this.cohereService) {
                const { CohereAIService } = require('./cohereAI');
                this.cohereService = new CohereAIService({
                  apiKey: process.env.COHERE_API_KEY
                });
              }
              
              const eventParsing = await this.cohereService.parseNaturalLanguageEvent(transcript);
              
              if (eventParsing.confidence > 0.4 && eventParsing.startTime && eventParsing.endTime) {
                // Success - event has valid dates
                response = {
                  text: `✅ I can create an event: "${eventParsing.title}" for ${new Date(eventParsing.startTime).toLocaleDateString()}`,
                  suggestions: ["Confirm creation", "Modify details", "Cancel"],
                  actionTaken: 'event_parsed',
                  eventDetails: eventParsing
                };
              } else {
                response = {
                  text: "I need more details to create the event. Please specify the date and time.",
                  suggestions: [
                    "Try: 'Create meeting tomorrow at 3pm'",
                    "Try: 'Schedule dinner Friday at 7pm'"
                  ]
                };
              }
            }
          } catch (error) {
            console.error('Cohere parsing error:', error);
            response.text = "I understand you want to create an event. Please provide more details.";
          }
        } else if (intent === 'query_events') {
          response.text = "I can help you check your schedule. What time period are you interested in?";
          response.suggestions = ["Today", "Tomorrow", "This week"];
        } else if (intent === 'delete_event') {
          response.text = "I can help you delete an event. Which event would you like to remove?";
          response.suggestions = ["Show my events first", "Cancel"];
        } else {
          response.text = "I'm here to help with your calendar. You can ask me to create events, check your schedule, or delete events.";
          response.suggestions = [
            "Create a new event",
            "Check my schedule", 
            "Delete an event"
          ];
        }

        res.json({
          success: true,
          response: response,
          timestamp: new Date().toISOString()
        });

      } catch (error) {
        console.error('❌ Voice processing error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to process voice command',
          details: error instanceof Error ? error.message : String(error)
        });
      }
    });

    // All other routes
    this.app.all('*', (req: Request, res: Response) => {
      res.redirect('https://nagavenkatasai7.github.io/ai-calender-agent');
    });
  }

  // Basic intent detection
  private detectBasicIntent(transcript: string): string {
    const command = transcript.toLowerCase();
    
    if (command.includes('schedule') || command.includes('create') || command.includes('add') || 
        command.includes('book') || command.includes('plan') || command.includes('set up')) {
      return 'create_event';
    }
    
    if (command.includes('what') || command.includes('show') || command.includes('list') || 
        command.includes('my schedule') || command.includes('today') || command.includes('tomorrow')) {
      return 'query_events';
    }
    
    if (command.includes('delete') || command.includes('cancel') || command.includes('remove')) {
      return 'delete_event';
    }
    
    if (command.includes('help') || command.includes('what can you do')) {
      return 'help';
    }
    
    return 'unknown';
  }

  public getApp(): express.Application {
    return this.app;
  }
}

// Export for Vercel
const serverlessApp = new ServerlessAIReminderApp();
export default serverlessApp.getApp(); 