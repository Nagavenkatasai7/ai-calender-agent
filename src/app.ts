import express, { Request, Response } from 'express';
import session from 'express-session';
import path from 'path';
import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';
import dotenv from 'dotenv';
import { Database, User } from './database';
import { AIReminderParser } from './aiParser';
import { CalendarService } from './calendar';
import { EmailService } from './emailService';
import { SubscriptionService } from './subscriptionService';

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
  }
}

export class AIReminderApp {
  private app: express.Application;
  private database: Database;
  private aiParser: AIReminderParser;
  private calendarService: CalendarService;
  private emailService: EmailService;
  private subscriptionService: SubscriptionService;
  private oauth2Client: OAuth2Client;
  private port: number;

  constructor() {
    this.app = express();
    this.port = parseInt(process.env.PORT || '3000');
    
    // Initialize services
    this.database = new Database();
    this.aiParser = new AIReminderParser();
    this.calendarService = new CalendarService();
    this.emailService = new EmailService();
    this.subscriptionService = new SubscriptionService(this.database);
    
    // Initialize OAuth2 client
    this.oauth2Client = new OAuth2Client(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );

    this.setupMiddleware();
    this.setupRoutes();
    this.startReminderScheduler();
  }

  private setupMiddleware() {
    this.app.use(express.json());
    this.app.use(express.static('public'));
    this.app.use(session({
      secret: process.env.SESSION_SECRET || 'ai-reminder-secret-key',
      resave: false,
      saveUninitialized: false,
      cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // 24 hours
    }));
  }

  private setupRoutes() {
    // Landing page
    this.app.get('/', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
    });

    // Pricing page
    this.app.get('/pricing', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'pricing.html'));
    });

    // Login page
    this.app.get('/login', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'login.html'));
    });

    // Calendar app (requires authentication)
    this.app.get('/app', this.requireAuth.bind(this), (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'app.html'));
    });

    // API Routes
    this.setupAuthRoutes();
    this.setupReminderRoutes();
    this.setupSubscriptionRoutes();
    this.setupUserRoutes();
  }

  private setupAuthRoutes() {
    // Start Google OAuth flow
    this.app.get('/auth/google', (req: Request, res: Response) => {
      const { plan } = req.query;
      
      const authUrl = this.oauth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: [
          'https://www.googleapis.com/auth/userinfo.email',
          'https://www.googleapis.com/auth/userinfo.profile',
          'https://www.googleapis.com/auth/calendar'
        ],
        prompt: 'consent',
        state: plan ? JSON.stringify({ plan }) : undefined
      });
      res.redirect(authUrl);
    });

    // Handle OAuth callback
    this.app.get('/auth/callback', async (req: Request, res: Response) => {
      try {
        const { code } = req.query;
        if (!code) {
          return res.status(400).send('Authorization code not found');
        }

        const { tokens } = await this.oauth2Client.getToken(code as string);
        this.oauth2Client.setCredentials(tokens);

        // Get user profile
        const oauth2 = google.oauth2({ version: 'v2', auth: this.oauth2Client });
        const { data: profile } = await oauth2.userinfo.get();

        if (!profile.email) {
          return res.status(400).send('Email not found in profile');
        }

        // Create or get user
        let user = await this.database.getUserByEmail(profile.email);
        if (!user) {
          user = await this.database.createUser(profile.email, profile.name || undefined);
          console.log(`✅ New user created: ${user.email} (${user.subscription_tier} tier)`);
        } else {
          console.log(`✅ Existing user authenticated: ${user.email} (${user.subscription_tier} tier)`);
        }

        // Store session
        req.session.userEmail = profile.email;
        req.session.tokens = {
          access_token: tokens.access_token || undefined,
          refresh_token: tokens.refresh_token || undefined,
          scope: tokens.scope || undefined,
          token_type: tokens.token_type || undefined,
          expiry_date: tokens.expiry_date || undefined
        };
        req.session.userId = user.id;

        // Check if user came from pricing page with a plan selection
        const { state } = req.query;
        if (state) {
          try {
            const stateData = JSON.parse(state as string);
            if (stateData.plan && ['pro', 'max'].includes(stateData.plan)) {
              // Create checkout session and redirect to payment
              const checkoutUrl = await this.subscriptionService.createCheckoutSession(user.id, stateData.plan);
              return res.redirect(checkoutUrl);
            }
          } catch (error) {
            console.error('Error parsing state:', error);
          }
        }

        // Redirect to calendar app
        res.redirect('/app');
      } catch (error) {
        console.error('OAuth callback error:', error);
        res.status(500).send('Authentication failed');
      }
    });

    // Logout
    this.app.post('/auth/logout', (req: Request, res: Response) => {
      req.session.destroy(() => {
        res.json({ success: true });
      });
    });
  }

  private setupReminderRoutes() {
    // Create reminder with subscription checks
    this.app.post('/api/reminders', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const { reminderText } = req.body;
        const userEmail = req.session.userEmail!;
        const userId = req.session.userId!;

        if (!reminderText || reminderText.trim().length === 0) {
          return res.status(400).json({
            success: false,
            error: 'Reminder text is required'
          });
        }

        // Check if user can create AI events
        const canCreate = await this.subscriptionService.canUserCreateAIEvent(userId);
        if (!canCreate.allowed) {
          return res.status(403).json({
            success: false,
            error: canCreate.reason,
            needsUpgrade: true
          });
        }

        // Parse reminder with AI
        const parsedReminder = await this.aiParser.parseReminder(reminderText);
        
        // Get user's default calendar
        const calendars = await this.database.getUserCalendars(userId);
        const defaultCalendar = calendars.find(c => c.is_default) || calendars[0];
        
        if (!defaultCalendar) {
          return res.status(500).json({
            success: false,
            error: 'No calendar found for user'
          });
        }

        // Create calendar reminders based on parsed alert times
        const calendarReminders = parsedReminder.alertMinutes.map(minutes => ({
          method: 'email' as const,
          minutes
        }));

        // Create calendar event
        const tokens = req.session.tokens!;
        this.oauth2Client.setCredentials(tokens);
        
        const eventData = {
          summary: parsedReminder.title,
          description: parsedReminder.description,
          start: {
            dateTime: parsedReminder.startTime.toISOString(),
            timeZone: 'America/New_York',
          },
          end: {
            dateTime: parsedReminder.endTime.toISOString(),
            timeZone: 'America/New_York',
          },
          reminders: {
            useDefault: false,
            overrides: calendarReminders,
          },
        };

        const calendarResponse = await this.calendarService.createEvent({
          title: parsedReminder.title,
          description: parsedReminder.description,
          startTime: parsedReminder.startTime,
          endTime: parsedReminder.endTime,
          timeZone: 'America/New_York',
          reminders: {
            useDefault: false,
            overrides: calendarReminders
          }
        }, userEmail);

        // Store reminder in database
        const reminder = await this.database.addReminder({
          user_id: userId,
          calendar_id: defaultCalendar.id,
          title: parsedReminder.title,
          description: parsedReminder.description,
          startTime: parsedReminder.startTime,
          endTime: parsedReminder.endTime,
          timezone: 'America/New_York',
          alertMinutes: parsedReminder.alertMinutes,
          created_via: 'ai',
          ai_confidence: parsedReminder.confidence,
          original_input: reminderText,
          calendarEventId: calendarResponse?.id
        });

        // Track usage
        await this.database.trackUsage(userId, 'ai_event_created');

        res.json({
          success: true,
          message: `✅ Reminder created: "${reminder.title}"`,
          reminder: {
            id: reminder.id,
            title: reminder.title,
            description: reminder.description,
            startTime: reminder.startTime,
            endTime: reminder.endTime,
            timezone: reminder.timezone
          },
          calendarEvent: calendarResponse ? {
            id: calendarResponse.id,
            htmlLink: calendarResponse.htmlLink,
            summary: calendarResponse.summary
          } : null,
          parsedDetails: parsedReminder
        });

      } catch (error) {
        console.error('Error creating reminder:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to create reminder'
        });
      }
    });

    // Get reminders
    this.app.get('/api/reminders', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        const user = await this.database.getUserByEmail(userEmail);
        
        if (!user) {
          return res.status(404).json({ success: false, error: 'User not found' });
        }

        const reminders = await this.database.getUserReminders(user.id);
        res.json({ success: true, reminders });
      } catch (error) {
        console.error('Error fetching reminders:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch reminders' });
      }
    });
  }

  private setupSubscriptionRoutes() {
    // Get pricing tiers
    this.app.get('/api/subscription/pricing', (req: Request, res: Response) => {
      const tiers = this.subscriptionService.getPricingTiers();
      res.json({ success: true, tiers });
    });

    // Create checkout session
    this.app.post('/api/subscription/checkout', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const { tierId } = req.body;
        const userId = req.session.userId!;

        if (!tierId || !['pro', 'max'].includes(tierId)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid tier ID'
          });
        }

        const checkoutUrl = await this.subscriptionService.createCheckoutSession(userId, tierId);
        
        res.json({
          success: true,
          checkoutUrl
        });
      } catch (error) {
        console.error('Error creating checkout session:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to create checkout session'
        });
      }
    });

    // Get subscription status
    this.app.get('/api/subscription/status', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const status = await this.subscriptionService.getUserSubscriptionStatus(userId);
        
        res.json({
          success: true,
          subscription: status
        });
      } catch (error) {
        console.error('Error fetching subscription status:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch subscription status'
        });
      }
    });

    // Manual subscription upgrade (for testing)
    this.app.post('/api/subscription/upgrade', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const { tierId } = req.body;
        const userId = req.session.userId!;

        if (!tierId || !['pro', 'max'].includes(tierId)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid tier ID'
          });
        }

        await this.subscriptionService.upgradeUserSubscription(userId, tierId);
        
        res.json({
          success: true,
          message: `Successfully upgraded to ${tierId} tier!`
        });
      } catch (error) {
        console.error('Error upgrading subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to upgrade subscription'
        });
      }
    });

    // Stripe webhook
    this.app.post('/api/subscription/webhook', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
      // Webhook handling would go here
      res.status(200).send('OK');
    });
  }

  private setupUserRoutes() {
    // Get user dashboard data
    this.app.get('/api/user/dashboard', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const dashboard = await this.subscriptionService.createUsageDashboard(userId);
        
        res.json({
          success: true,
          ...dashboard
        });
      } catch (error) {
        console.error('Error fetching dashboard:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch dashboard'
        });
      }
    });

    // Get user subscription info
    this.app.get('/api/user/subscription', this.requireAuth.bind(this), async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const user = await this.database.getUserById(userId);
        
        if (!user) {
          return res.status(404).json({ success: false, error: 'User not found' });
        }

        // Check if trial is still active
        const isTrialActive = user.subscription_status === 'trial' && 
          user.trial_ends_at && new Date() < new Date(user.trial_ends_at);

        res.json({
          success: true,
          tier: user.subscription_tier,
          status: user.subscription_status,
          isTrialActive,
          trialEndsAt: user.trial_ends_at
        });
      } catch (error) {
        console.error('Error fetching subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch subscription'
        });
      }
    });
  }

  private requireAuth(req: Request, res: Response, next: any) {
    if (!req.session.userEmail || !req.session.userId) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }
    next();
  }

  private startReminderScheduler() {
    // Check for pending reminders every minute
    setInterval(async () => {
      try {
        console.log('Checking for pending reminders...');
        const reminders = await this.database.getPendingReminders();
        
        for (const { reminder, alertMinutes } of reminders) {
          try {
            await this.emailService.sendReminder({
              to: reminder.user_id, // Will need to get email from user_id
              eventDetails: {
                title: reminder.title,
                description: reminder.description,
                startTime: reminder.startTime
              },
              minutesBefore: alertMinutes
            });
            
            // Mark alert as sent
            await this.database.markAlertSent(reminder.id, alertMinutes);
            console.log(`✅ Reminder sent for: ${reminder.title}`);
          } catch (error) {
            console.error(`❌ Failed to send reminder for ${reminder.title}:`, error);
          }
        }
      } catch (error) {
        console.error('❌ Error in reminder scheduler:', error);
      }
    }, 60 * 1000); // Check every minute
  }

  public start() {
    this.app.listen(this.port, () => {
      console.log(`🚀 AI Reminder Agent running on port ${this.port}`);
      console.log(`📱 Visit http://localhost:${this.port} to get started`);
      console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
      
      // Configuration status
      console.log('📋 Configuration Status:');
      console.log(`   Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? '✅' : '❌'}`);
      console.log(`   OpenAI API: ${process.env.OPENAI_API_KEY ? '✅' : '❌'}`);
      console.log(`   Email Service: ${process.env.EMAIL_USER ? '✅' : '❌'}`);
      console.log(`   Stripe Payments: ${process.env.STRIPE_PUBLISHABLE_KEY ? '✅' : '❌'}`);
      
      if (process.env.STRIPE_PUBLISHABLE_KEY) {
        console.log('💳 Stripe Configuration:');
        console.log(`   Publishable Key: ${process.env.STRIPE_PUBLISHABLE_KEY.substring(0, 20)}...`);
        console.log(`   Secret Key: ${process.env.STRIPE_SECRET_KEY ? 'sk_***' : 'Not set'}`);
      }
      
      if (process.env.GOOGLE_CLIENT_ID) {
        console.log('🔍 OAuth Debug Info:');
        console.log(`   Client ID: ${process.env.GOOGLE_CLIENT_ID.substring(0, 20)}...`);
        console.log(`   Client Secret: ${process.env.GOOGLE_CLIENT_SECRET ? 'GOCSPX-***' : 'Not set'}`);
        console.log(`   Redirect URI: ${process.env.GOOGLE_REDIRECT_URI}`);
      }
    });
  }
}

// Start the application
const app = new AIReminderApp();
app.start(); 
