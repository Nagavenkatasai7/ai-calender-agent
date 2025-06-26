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
import { AIVoiceInterface, AIVoiceConfig } from './aiVoiceInterface';
import { HuggingFaceMCPService } from './huggingFaceMCP';
// import { CohereAIService } from './cohereAI';

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

export class AIReminderApp {
  private app: express.Application;
  private database: Database;
  private aiParser: AIReminderParser;
  private calendarService: CalendarService;
  private emailService: EmailService;
  private subscriptionService: SubscriptionService;
  private authService: AuthService;
  private oauth2Client: OAuth2Client;
  private aiVoiceInterface: AIVoiceInterface | null = null;
  private hfMCPService: HuggingFaceMCPService | null = null;
  private cohereService: any | null = null;
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
    this.startReminderScheduler();
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

    // Stricter rate limiting for auth endpoints
    const authLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 5, // limit each IP to 5 auth requests per windowMs
      message: 'Too many authentication attempts, please try again later.'
    });

    this.app.use('/api/auth', authLimiter);

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
    // Public routes
    this.setupPublicRoutes();
    
    // Authentication routes
    this.setupAuthRoutes();
    
    // Protected API routes
    this.setupProtectedRoutes();
    
    // Admin routes (if needed)
    this.setupAdminRoutes();
    
    // Serve static files after custom routes to prevent conflicts
    this.app.use(express.static('public'));
  }

  private setupPublicRoutes() {
    // Secure landing page
    this.app.get('/', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'secure-landing.html'));
    });

    // Legacy routes redirect to secure landing
    this.app.get('/index', (req: Request, res: Response) => {
      res.redirect('/');
    });

    this.app.get('/landing', (req: Request, res: Response) => {
      res.redirect('/');
    });

    // Pricing page (redirect to landing page with pricing anchor)
    this.app.get('/pricing', (req: Request, res: Response) => {
      res.redirect('/#pricing');
    });

    // Health check
    this.app.get('/health', (req: Request, res: Response) => {
      res.json({ status: 'ok', timestamp: new Date().toISOString() });
    });

    // Auth status check (not rate limited)
    this.app.get('/api/auth/status', (req: Request, res: Response) => {
      try {
        if (!req.session.userId || !req.session.userEmail) {
          return res.json({
            authenticated: false,
            user: null
          });
        }

        res.json({
          authenticated: true,
          user: {
            id: req.session.userId,
            email: req.session.userEmail,
            session: 'active'
          }
        });
      } catch (error) {
        console.error('Auth status check error:', error);
        res.status(500).json({
          authenticated: false,
          error: 'Failed to check authentication status'
        });
      }
    });

    // Debug session info
    this.app.get('/api/debug/session', (req: Request, res: Response) => {
      res.json({
        sessionID: req.sessionID,
        session: {
          userEmail: req.session.userEmail,
          userId: req.session.userId,
          hasTokens: !!req.session.tokens,
          pendingTwoFactor: req.session.pendingTwoFactor,
          twoFactorVerified: req.session.twoFactorVerified
        },
        cookies: req.headers.cookie,
        timestamp: new Date().toISOString()
      });
    });

    // Holidays API (for Excel 6.0 compatibility)
    this.app.get('/api/holidays', (req: Request, res: Response) => {
      const { year, country } = req.query;
      const currentYear = year ? parseInt(year as string) : new Date().getFullYear();
      const countryCode = (country as string) || 'US';
      
      // Basic US holidays for Excel 6.0 compatibility
      const holidays = [
        { date: `${currentYear}-01-01`, name: 'New Year\'s Day', country: 'US' },
        { date: `${currentYear}-01-15`, name: 'Martin Luther King Jr. Day', country: 'US' },
        { date: `${currentYear}-02-19`, name: 'Presidents\' Day', country: 'US' },
        { date: `${currentYear}-05-27`, name: 'Memorial Day', country: 'US' },
        { date: `${currentYear}-07-04`, name: 'Independence Day', country: 'US' },
        { date: `${currentYear}-09-02`, name: 'Labor Day', country: 'US' },
        { date: `${currentYear}-10-14`, name: 'Columbus Day', country: 'US' },
        { date: `${currentYear}-11-11`, name: 'Veterans Day', country: 'US' },
        { date: `${currentYear}-11-28`, name: 'Thanksgiving Day', country: 'US' },
        { date: `${currentYear}-12-25`, name: 'Christmas Day', country: 'US' }
      ];

      // Filter by country if specified
      const filteredHolidays = countryCode === 'US' ? holidays : 
        holidays.filter(h => h.country === countryCode);

      res.json({
        year: currentYear,
        country: countryCode,
        holidays: filteredHolidays,
        format: 'Excel 6.0 Compatible',
        total: filteredHolidays.length
      });
    });

    // Password reset page
    this.app.get('/reset-password', (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'reset-password.html'));
    });

    // Calendar app (protected)
    this.app.get('/app', (req: Request, res: Response) => {
      console.log('🔍 App access attempt - Session status:', {
        userEmail: req.session.userEmail,
        userId: req.session.userId,
        sessionID: req.sessionID,
        hasTokens: !!req.session.tokens
      });

      if (!req.session.userEmail && !req.session.userId) {
        console.log('❌ App access denied - no session');
        return res.redirect('/?error=auth_required');
      }
      
      console.log('✅ App access granted');
      res.sendFile(path.join(__dirname, '..', 'public', 'app.html'));
    });

    // Settings page (protected)
    this.app.get('/settings', (req: Request, res: Response) => {
      if (!req.session.userEmail && !req.session.userId) {
        return res.status(401).json({
          success: false,
          error: 'Authentication required'
        });
      }
      res.sendFile(path.join(__dirname, '..', 'public', 'settings.html'));
    });
  }

  private setupAuthRoutes() {
    // Email/Password Registration (Simplified)
    this.app.post('/api/auth/register', async (req: Request, res: Response) => {
      try {
        const { name, email, password } = req.body;

        if (!name || !email || !password) {
          return res.status(400).json({
            success: false,
            error: 'Name, email and password are required'
          });
        }

        // Basic password validation
        if (password.length < 8) {
          return res.status(400).json({
            success: false,
            error: 'Password must be at least 8 characters long'
          });
        }

        // Check if user already exists
        const existingUser = await this.database.getUserByEmail(email);
        if (existingUser) {
          return res.status(400).json({
            success: false,
            error: 'User already exists with this email'
          });
        }

        // Create user (simplified approach)
        const user = await this.database.createUser(email, name);
        
        // Hash password and update
        const hashedPassword = await this.authService.hashPassword(password);
        await this.database.updateUserPassword(user.id, hashedPassword);
        
        // Generate and store email verification token
        const verification = this.authService.generateEmailVerificationToken();
        await this.database.updateEmailVerificationToken(user.id, verification.token, verification.expires);
        
        // Log the verification URL for debugging
        const baseUrl = req.protocol + '://' + req.get('host');
        const verificationUrl = `${baseUrl}/api/auth/verify-email/${verification.token}`;
        console.log(`\n✅ Account created for ${email}`);
        console.log(`📧 Verification URL: ${verificationUrl}\n`);
        
        // Try to send verification email
        let emailSent = false;
        try {
          await this.emailService.sendVerificationEmail(email, name, verification.token);
          emailSent = true;
          console.log(`✅ Verification email sent to ${email}`);
        } catch (emailError) {
          console.error('❌ Failed to send verification email:', emailError instanceof Error ? emailError.message : String(emailError));
          console.log('⚠️  User can still verify using the URL above');
        }
        
        // Inform user to verify their email
        res.json({
          success: true,
          message: emailSent 
            ? 'Account created successfully! Please check your email to verify your account.'
            : 'Account created successfully! Email service is temporarily unavailable. Please contact support for verification.',
          verificationUrl: !emailSent ? verificationUrl : undefined // Include URL if email failed
        });

      } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to create account: ' + (error instanceof Error ? error.message : String(error))
        });
      }
    });

    // Email/Password Login
    this.app.post('/api/auth/login', async (req: Request, res: Response) => {
      try {
        const { email, password } = req.body;

        if (!email || !password) {
          return res.status(400).json({
            success: false,
            error: 'Email and password are required'
          });
        }

        // Check rate limiting
        const rateLimitCheck = await this.authService.checkRateLimit(email);
        if (!rateLimitCheck.allowed) {
          return res.status(429).json({
            success: false,
            error: rateLimitCheck.reason,
            retryAfter: rateLimitCheck.retryAfter
          });
        }

        // Get user
        const user = await this.database.getUserByEmail(email);
        if (!user || !user.password_hash) {
          this.authService.recordFailedAttempt(email);
          return res.status(401).json({
            success: false,
            error: 'Invalid email or password'
          });
        }

        // Verify password
        const passwordValid = await this.authService.verifyPassword(password, user.password_hash);
        if (!passwordValid) {
          this.authService.recordFailedAttempt(email);
          return res.status(401).json({
            success: false,
            error: 'Invalid email or password'
          });
        }

        // Check email verification
        if (!user.email_verified) {
          return res.status(401).json({
            success: false,
            error: 'Please verify your email address before logging in'
          });
        }

        // Check 2FA requirement
        if (user.two_factor_enabled) {
          req.session.pendingTwoFactor = true;
          req.session.twoFactorUserId = user.id;
          
          return res.json({
            success: true,
            requiresTwoFactor: true,
            userId: user.id
          });
        }

        // Create secure session
        await this.authService.createSecureSession(req, user);
        this.authService.recordSuccessfulLogin(email);

        // Update last login
        await this.database.updateLastLogin(user.id);

        res.json({
          success: true,
          message: 'Login successful',
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            subscription_tier: user.subscription_tier
          }
        });

      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
          success: false,
          error: 'Login failed'
        });
      }
    });

    // Two-Factor Authentication verification
    this.app.post('/api/auth/verify-2fa', async (req: Request, res: Response) => {
      try {
        const { token, backupCode } = req.body;
        const userId = req.session.twoFactorUserId;

        if (!req.session.pendingTwoFactor || !userId) {
          return res.status(400).json({
            success: false,
            error: 'No pending 2FA verification'
          });
        }

        const user = await this.database.getUserById(userId);
        if (!user || !user.two_factor_enabled) {
          return res.status(400).json({
            success: false,
            error: 'Invalid 2FA setup'
          });
        }

        let verificationValid = false;

        if (token && user.two_factor_secret) {
          // Verify TOTP token
          verificationValid = this.authService.verifyTwoFactorToken(user.two_factor_secret, token);
        } else if (backupCode && user.two_factor_backup_codes) {
          // Verify backup code
          const backupCodes = JSON.parse(user.two_factor_backup_codes);
          const backupResult = this.authService.verifyBackupCode(backupCodes, backupCode);
          
          if (backupResult.valid) {
            verificationValid = true;
            // Update remaining backup codes
            await this.database.updateTwoFactorBackupCodes(user.id, JSON.stringify(backupResult.remainingCodes));
          }
        }

        if (!verificationValid) {
          return res.status(401).json({
            success: false,
            error: 'Invalid verification code'
          });
        }

        // Clear 2FA session data
        req.session.pendingTwoFactor = false;
        req.session.twoFactorUserId = undefined;
        req.session.twoFactorVerified = true;

        // Create secure session
        await this.authService.createSecureSession(req, user);
        this.authService.recordSuccessfulLogin(user.email);

        res.json({
          success: true,
          message: '2FA verification successful',
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            subscription_tier: user.subscription_tier
          }
        });

      } catch (error) {
        console.error('2FA verification error:', error);
        res.status(500).json({
          success: false,
          error: '2FA verification failed'
        });
      }
    });

    // Google OAuth flow (enhanced)
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

    // Google OAuth callback (enhanced)
    this.app.get('/auth/callback', async (req: Request, res: Response) => {
      try {
        const { code } = req.query;
        if (!code) {
          return res.status(400).send('Authorization code not found');
        }

        // CRITICAL FIX: Clear any existing OAuth credentials to prevent contamination
        console.log('🧹 Clearing any existing OAuth credentials to prevent user contamination');
        this.oauth2Client.setCredentials({});

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
          // Mark as email verified for OAuth users
          await this.database.markEmailVerified(user.id);
          console.log(`✅ New OAuth user created: ${user.email} (${user.subscription_tier} tier)`);
        } else {
          console.log(`✅ Existing OAuth user authenticated: ${user.email} (${user.subscription_tier} tier)`);
          
          // Auto-sync subscription with Stripe on login
          console.log('🔄 Auto-syncing subscription with Stripe on login...');
          try {
            const synced = await this.subscriptionService.syncUserSubscriptionWithStripe(user.email);
            if (synced) {
              console.log(`✅ Subscription synced for ${user.email} on login`);
              // Refresh user data after sync
              user = await this.database.getUserByEmail(user.email) || user;
              console.log(`🔄 Updated user subscription status: ${user.subscription_tier} tier`);
            }
          } catch (syncError) {
            console.error('⚠️ Failed to sync subscription on login:', syncError);
            // Continue with login even if sync fails
          }
        }

        // CRITICAL FIX: Properly destroy and regenerate session to prevent data contamination  
        const originalSessionId = req.sessionID;
        console.log(`🧹 Clearing session data for user switch: ${originalSessionId}`);
        
        // Use promisified session destruction for proper async handling
        await new Promise<void>((resolve, reject) => {
          req.session.destroy((err) => {
            if (err) {
              console.warn('⚠️ Session destruction failed:', err);
              return reject(err);
            }
            console.log('✅ Session destroyed successfully');
            resolve();
          });
        });
        
        // Regenerate a completely new session
        await new Promise<void>((resolve, reject) => {
          req.session.regenerate((err) => {
            if (err) {
              console.error('❌ Session regeneration failed:', err);
              return reject(err);
            }
            console.log(`🔐 New session created: ${req.sessionID} for user: ${user.email}`);
            resolve();
          });
        });
        
        // Set session variables directly for compatibility
        req.session.userEmail = user.email;
        req.session.userId = user.id;

        // Try to create secure session (but don't let it fail the OAuth flow)
        try {
          await this.authService.createSecureSession(req, user);
        } catch (secureSessionError) {
          console.warn('Secure session creation failed, but continuing with basic session:', secureSessionError);
        }

        // Store OAuth tokens
        req.session.tokens = {
          access_token: tokens.access_token || undefined,
          refresh_token: tokens.refresh_token || undefined,
          scope: tokens.scope || undefined,
          token_type: tokens.token_type || undefined,
          expiry_date: tokens.expiry_date || undefined
        };

        // Clear the shared OAuth client credentials after storing in session
        console.log('🧹 Clearing shared OAuth client after token storage');
        this.oauth2Client.setCredentials({});

        // Update last login
        await this.database.updateLastLogin(user.id);

        // Check if user came from pricing page with a plan selection
        const { state } = req.query;
        if (state) {
          try {
            const stateData = JSON.parse(state as string);
            if (stateData.plan && ['pro', 'max'].includes(stateData.plan)) {
              const checkoutUrl = await this.subscriptionService.createCheckoutSession(user.id, stateData.plan);
              return res.redirect(checkoutUrl);
            }
          } catch (error) {
            console.error('Error parsing state:', error);
          }
        }

        // Debug session before redirect
        console.log('✅ OAuth successful - Session created:', {
          userId: req.session.userId,
          userEmail: req.session.userEmail,
          hasTokens: !!req.session.tokens,
          sessionId: req.sessionID
        });

        // Ensure session is persisted before redirecting
        req.session.save((err) => {
          if (err) {
            console.error('Session save error after OAuth:', err);
            // Redirect anyway, but session may not persist if save failed
          }
          // Redirect to calendar app
          res.redirect('/app');
        });
      } catch (error) {
        console.error('OAuth callback error:', error);
        res.status(500).send('Authentication failed');
      }
    });

    // Email verification with auto-login and redirect to calendar
    this.app.get('/api/auth/verify-email/:token', async (req: Request, res: Response) => {
      try {
        const { token } = req.params;
        const user = await this.database.getUserByVerificationToken(token);
        if (!user) {
          console.warn('Invalid or expired verification token:', token);
          return res.redirect('/?error=invalid_verification');
        }
        // Mark email verified
        await this.database.markEmailVerified(user.id);
        console.log(`✅ Email verified for user: ${user.email}`);
        
        // Auto-login: set session and create secure session
        req.session.userEmail = user.email;
        req.session.userId = user.id;
        try {
          await this.authService.createSecureSession(req, user as any);
          this.authService.recordSuccessfulLogin(user.email);
        } catch (sessionError) {
          console.warn('Secure session creation after email verification failed:', sessionError);
        }
        // Persist session and redirect to calendar app
        req.session.save((err) => {
          if (err) {
            console.error('Session save error after email verification:', err);
          }
          return res.redirect('/app?verified=true');
        });
      } catch (error) {
        console.error('Email verification error:', error);
        return res.redirect('/?error=verification_failed');
      }
    });

    // Resend verification email
    this.app.post('/api/auth/resend-verification', async (req: Request, res: Response) => {
      try {
        const { email } = req.body;

        if (!email) {
          return res.status(400).json({
            success: false,
            error: 'Email address is required'
          });
        }

        // Get user
        const user = await this.database.getUserByEmail(email);
        if (!user) {
          // Don't reveal if user exists or not for security
          return res.json({
            success: true,
            message: 'If an account with this email exists and is unverified, a verification email has been sent.'
          });
        }

        // Check if already verified
        if (user.email_verified) {
          return res.status(400).json({
            success: false,
            error: 'This email address is already verified'
          });
        }

        // Generate new verification token
        const verification = this.authService.generateEmailVerificationToken();
        await this.database.updateEmailVerificationToken(user.id, verification.token, verification.expires);

        // Try to send verification email
        try {
          await this.emailService.sendVerificationEmail(user.email, user.name || 'User', verification.token);
          console.log(`✅ Verification email resent to ${user.email}`);
          
          res.json({
            success: true,
            message: 'Verification email sent! Please check your inbox and spam folder.'
          });
        } catch (emailError) {
          console.error('❌ Failed to resend verification email:', emailError);
          
          // Provide fallback verification URL for development
          const baseUrl = req.protocol + '://' + req.get('host');
          const verificationUrl = `${baseUrl}/api/auth/verify-email/${verification.token}`;
          console.log(`📧 Verification URL: ${verificationUrl}`);
          
          res.status(500).json({
            success: false,
            error: 'Failed to send verification email. Please contact support.',
            verificationUrl: process.env.NODE_ENV === 'development' ? verificationUrl : undefined
          });
        }
      } catch (error) {
        console.error('Resend verification error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to resend verification email'
        });
      }
    });

    // Password reset request
    this.app.post('/api/auth/forgot-password', async (req: Request, res: Response) => {
      try {
        const { email } = req.body;

        if (!email) {
          return res.status(400).json({
            success: false,
            error: 'Email is required'
          });
        }

        const user = await this.database.getUserByEmail(email);
        if (!user) {
          // Don't reveal if user exists
          return res.json({
            success: true,
            message: 'If an account with this email exists, you will receive a password reset link.'
          });
        }

        const resetToken = this.authService.generatePasswordResetToken();
        await this.database.updatePasswordResetToken(user.id, resetToken.token, resetToken.expires);

        await this.emailService.sendPasswordResetEmail(email, user.name || 'User', resetToken.token);

        res.json({
          success: true,
          message: 'If an account with this email exists, you will receive a password reset link.'
        });

      } catch (error) {
        console.error('Password reset request error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to process password reset request'
        });
      }
    });

    // Password reset
    this.app.post('/api/auth/reset-password', async (req: Request, res: Response) => {
      try {
        const { token, password } = req.body;

        if (!token || !password) {
          return res.status(400).json({
            success: false,
            error: 'Token and password are required'
          });
        }

        // Validate password strength
        const passwordCheck = this.authService.validatePasswordStrength(password);
        if (!passwordCheck.valid) {
          return res.status(400).json({
            success: false,
            error: 'Password does not meet security requirements',
            issues: passwordCheck.issues
          });
        }

        const user = await this.database.getUserByPasswordResetToken(token);
        if (!user) {
          return res.status(400).json({
            success: false,
            error: 'Invalid or expired reset token'
          });
        }

        const hashedPassword = await this.authService.hashPassword(password);
        await this.database.updateUserPassword(user.id, hashedPassword);
        await this.database.clearPasswordResetToken(user.id);

        res.json({
          success: true,
          message: 'Password reset successfully. You can now log in with your new password.'
        });

      } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({
          success: false,
          error: 'Password reset failed'
        });
      }
    });

    // Logout
    this.app.post('/api/auth/logout', async (req: Request, res: Response) => {
      try {
        // Log the logout attempt
        console.log('🚪 Logout attempt for session:', req.session.sessionId || 'unknown');
        
        // CRITICAL FIX: Clear OAuth credentials to prevent contamination
        console.log('🧹 Clearing OAuth credentials on logout');
        this.oauth2Client.setCredentials({});
        
        // Clear session server-side
        await this.authService.invalidateSession(req);
        
        // Clear the session cookie on client-side
        res.clearCookie('ai-reminder-session', {
          path: '/',
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax'
        });
        
        // Set cache headers to prevent cached access
        res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        
        console.log('✅ Logout successful - session destroyed and cookie cleared');
        res.json({ success: true, message: 'Logged out successfully' });
      } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({
          success: false,
          error: 'Logout failed'
        });
      }
    });
  }

  private setupProtectedRoutes() {
    // Use the enhanced auth middleware with email verification for all protected routes
    // OAuth users are automatically marked as verified, so this won't affect them
    const authMiddleware = this.authService.createAuthMiddleware({
      requireEmailVerification: true
    });

    // Calendar app (requires authentication)
    this.app.get('/app', authMiddleware, (req: Request, res: Response) => {
      console.log('🔍 App access attempt - Session status:', {
        userEmail: req.session.userEmail,
        userId: req.session.userId,
        sessionID: req.session.sessionId || req.sessionID,
        hasTokens: !!req.session.tokens
      });
      
      // Add cache headers to prevent cached access after logout
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
      
      console.log('✅ App access granted');
      res.sendFile(path.join(__dirname, '..', 'public', 'app.html'));
    });

    // Settings page (requires authentication)
    this.app.get('/settings', authMiddleware, (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'settings.html'));
    });

    // AI Voice Interface page (requires authentication)
    this.app.get('/ai-voice', authMiddleware, (req: Request, res: Response) => {
      res.sendFile(path.join(__dirname, '..', 'public', 'ai-voice-interface.html'));
    });

    // User profile and settings routes (using enhanced auth with email verification)
    this.setupUserRoutes(authMiddleware);
    
    // Calendar and reminder routes (using enhanced auth with email verification)
    this.setupReminderRoutes(authMiddleware);
    
    // AI Voice routes (using enhanced auth with email verification)
    this.setupAIVoiceRoutes(authMiddleware);
    
    // Subscription routes (using enhanced auth with email verification)
    this.setupSubscriptionRoutes(authMiddleware);
  }

  private setupUserRoutes(authMiddleware: any) {
    // Get user profile
    this.app.get('/api/user/profile', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        const user = await this.database.getUserByEmail(userEmail);
        
        if (!user) {
          return res.status(404).json({
            success: false,
            error: 'User not found'
          });
        }
        
        res.json({
          success: true,
          user: {
            id: user.id,
            email: user.email,
            name: user.name,
            subscription_tier: user.subscription_tier,
            subscription_status: user.subscription_status,
            email_verified: user.email_verified || true, // OAuth users are verified by default
            two_factor_enabled: user.two_factor_enabled || false,
            created_at: user.created_at,
            last_login: user.last_login,
            settings: user.settings
          }
        });
      } catch (error) {
        console.error('Get profile error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to get user profile'
        });
      }
    });

    // Update user profile
    this.app.put('/api/user/profile', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        const user = await this.database.getUserByEmail(userEmail);
        
        if (!user) {
          return res.status(404).json({
            success: false,
            error: 'User not found'
          });
        }

        const { name, settings } = req.body;
        await this.database.updateUserProfile(user.id, { name, settings });

        res.json({
          success: true,
          message: 'Profile updated successfully'
        });
      } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to update profile'
        });
      }
    });

    // Get connected accounts (simplified for compatibility)
    this.app.get('/api/user/connected-accounts', authMiddleware, async (req: Request, res: Response) => {
      try {
        // For now, just return empty array since OAuth integration is working
        res.json({
          success: true,
          accounts: []
        });
      } catch (error) {
        console.error('Get connected accounts error:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to get connected accounts'
        });
      }
    });

    // Dashboard data
    this.app.get('/api/user/dashboard', authMiddleware, async (req: Request, res: Response) => {
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

    // Get user's feature summary (Pro vs Free features)
    this.app.get('/api/user/features', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const featureSummary = await this.subscriptionService.getUserFeatureSummary(userId);
        
        if (!featureSummary) {
          return res.status(404).json({
            success: false,
            error: 'User not found'
          });
        }

        res.json({
          success: true,
          features: featureSummary
        });
      } catch (error) {
        console.error('Error fetching user features:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch features'
        });
      }
    });
  }

  private setupReminderRoutes(authMiddleware: any) {
    // Create reminder with subscription checks
    this.app.post('/api/reminders', authMiddleware, async (req: Request, res: Response) => {
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
            needsUpgrade: canCreate.needsUpgrade || false,
            currentTier: canCreate.currentTier,
            recommendedTier: canCreate.recommendedTier,
            upgradeMessage: canCreate.upgradeMessage,
            upgradeUrl: canCreate.recommendedTier ? `/#pricing` : undefined
          });
        }

        // Check if user can access advanced NLP features
        const hasAdvancedNLP = await this.subscriptionService.canUseAdvancedNLP(userId);
        console.log(`🧠 Advanced NLP available for user: ${hasAdvancedNLP.allowed}`);

        // Check recurring events permission for Pro users
        const canCreateRecurring = await this.subscriptionService.canCreateRecurringEvents(userId);
        console.log(`🔄 Recurring events available for user: ${canCreateRecurring.allowed}`);

        // Parse reminder with AI (fallback included)
        console.log('🤖 Parsing reminder with AI:', reminderText);
        console.log(`🔧 Using ${hasAdvancedNLP.allowed ? 'Advanced' : 'Basic'} AI parsing`);
        
        const parsedReminder = await this.aiParser.parseReminder(reminderText, hasAdvancedNLP.allowed);
        console.log('✅ Parsed reminder:', parsedReminder);

        // Pro feature validation: Check if user tried to create recurring event without permission
        if (parsedReminder.isRecurring && !canCreateRecurring.allowed) {
          return res.status(403).json({
            success: false,
            error: canCreateRecurring.reason,
            needsUpgrade: true,
            feature: 'recurring_events',
            upgradeMessage: 'Upgrade to Pro for recurring events like "every Tuesday" or "daily standup"',
            upgradeUrl: '/#pricing'
          });
        }

        // Show smart suggestions for Pro users
        if (hasAdvancedNLP.allowed && parsedReminder.smartSuggestions) {
          console.log('💡 Smart suggestions generated:', parsedReminder.smartSuggestions);
        }
        
        // Get user's calendars
        let calendars = [];
        let defaultCalendar = null;
        try {
          calendars = await this.database.getUserCalendars(userId);
          defaultCalendar = calendars.find(c => c.is_default) || calendars[0];
        } catch (error: any) {
          console.log('⚠️ No calendars found in database, creating virtual calendar:', error?.message);
        }

        // Create calendar reminders based on parsed alert times
        const calendarReminders = parsedReminder.alertMinutes.map(minutes => ({
          method: 'email' as const,
          minutes
        }));

        // Try to create calendar event, but don't fail if it doesn't work
        let calendarResponse = null;
        try {
          const tokens = req.session.tokens;
          if (tokens) {
            // CRITICAL FIX: Create isolated OAuth client for this user to prevent contamination
            console.log('🔐 Creating isolated OAuth client for calendar event creation');
            const userOAuth2Client = new google.auth.OAuth2(
              process.env.GOOGLE_CLIENT_ID,
              process.env.GOOGLE_CLIENT_SECRET,
              process.env.GOOGLE_REDIRECT_URI
            );
            userOAuth2Client.setCredentials(tokens);
            
            // Create calendar service with isolated client
            const userCalendarService = new CalendarService();
            await userCalendarService.authenticate(tokens);
            
            calendarResponse = await userCalendarService.createEvent({
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
            console.log('✅ Calendar event created:', calendarResponse?.id);
          } else {
            console.log('⚠️ No OAuth tokens available, skipping Google Calendar creation');
          }
        } catch (error: any) {
          console.error('⚠️ Calendar event creation failed, continuing without it:', error?.message);
        }

        // Store reminder in database
        const reminder = await this.database.addReminder({
          user_id: userId,
          calendar_id: defaultCalendar?.id || 'virtual',
          title: parsedReminder.title,
          description: parsedReminder.description,
          startTime: parsedReminder.startTime,
          endTime: parsedReminder.endTime,
          timezone: 'America/New_York',
          alertMinutes: parsedReminder.alertMinutes,
          created_via: 'ai',
          ai_confidence: parsedReminder.confidence,
          original_input: reminderText,
          recurrence_rule: parsedReminder.recurrenceRule,
          attendees: parsedReminder.attendees,
          location: parsedReminder.location,
          calendarEventId: calendarResponse?.id
        });

        // Track usage
        await this.database.trackUsage(userId, 'ai_event_created');

        // Prepare enhanced response for Pro users
        const response: any = {
          success: true,
          message: `✅ Reminder created: "${reminder.title}"`,
          reminder: {
            id: reminder.id,
            title: reminder.title,
            description: reminder.description,
            startTime: reminder.startTime,
            endTime: reminder.endTime,
            timezone: reminder.timezone,
            alertMinutes: reminder.alertMinutes,
            ...(hasAdvancedNLP.allowed && {
              location: parsedReminder.location,
              attendees: parsedReminder.attendees,
              isRecurring: parsedReminder.isRecurring,
              recurrenceRule: parsedReminder.recurrenceRule
            })
          },
          calendarEvent: calendarResponse ? {
            id: calendarResponse.id,
            htmlLink: calendarResponse.htmlLink,
            summary: calendarResponse.summary
          } : null,
          parsedDetails: parsedReminder
        };

        // Add Pro features to response
        if (hasAdvancedNLP.allowed) {
          response.proFeatures = {
            advancedNLP: true,
            smartSuggestions: parsedReminder.smartSuggestions,
            recurringEvents: canCreateRecurring.allowed,
            featureUpgrades: {
              smartScheduling: true,
              locationDetection: !!parsedReminder.location,
              attendeeDetection: parsedReminder.attendees && parsedReminder.attendees.length > 0,
              durationOptimization: true
            }
          };
        } else {
          response.upgradePrompts = {
            recurringEvents: !canCreateRecurring.allowed ? 'Upgrade to Pro for recurring events' : null,
            advancedNLP: 'Upgrade to Pro for advanced natural language processing',
            smartSuggestions: 'Upgrade to Pro for smart scheduling suggestions'
          };
        }

        res.json(response);

      } catch (error) {
        console.error('Error creating reminder:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to create reminder'
        });
      }
    });

    // Get reminders
    this.app.get('/api/reminders', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        const reminders = await this.database.getUserReminders(userEmail);
        
        res.json({ success: true, reminders });
      } catch (error) {
        console.error('Error fetching reminders:', error);
        res.status(500).json({ success: false, error: 'Failed to fetch reminders' });
      }
    });

    // OpenAI command analysis endpoint for voice commands
    this.app.post('/api/ai/analyze-command', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { transcript, context } = req.body;
        
        if (!transcript) {
          return res.status(400).json({ error: 'Transcript is required' });
        }

        console.log('🤖 Analyzing voice command:', transcript);
        
        // Create a detailed prompt for command analysis
        const analysisPrompt = `
You are a smart calendar assistant. Analyze this voice command and extract the intent and details.

Voice Command: "${transcript}"
Current Context: ${JSON.stringify(context)}

Respond with a JSON object containing:
{
    "intent": "create_event|query_events|delete_event|navigate|help|unknown",
    "confidence": 0.0-1.0,
    "response": "Natural response to user",
    "eventDetails": {  // Only for create_event
        "title": "Event title",
        "startTime": "ISO date string",
        "endTime": "ISO date string",
        "location": "Location if mentioned",
        "description": "Any additional details"
    },
    "queryType": "today|tomorrow|this_week|specific_time|general",  // Only for query_events
    "eventToDelete": "Event name to delete",  // Only for delete_event
    "navigationType": "today|tomorrow|view_change",  // Only for navigate
    "viewType": "day|week|month",  // Only for view_change navigation
    "needsConfirmation": true/false,
    "summary": "Brief summary of what will be done",
    "emptyResponse": "Response when no events found",
    "errorResponse": "Response when operation fails",
    "originalCommand": "${transcript}"
}

Examples:
- "Schedule a meeting tomorrow at 3 PM" → intent: "create_event"
- "What's on my calendar today?" → intent: "query_events", queryType: "today"
- "Delete my dentist appointment" → intent: "delete_event", eventToDelete: "dentist appointment"
- "Go to tomorrow" → intent: "navigate", navigationType: "tomorrow"
- "Switch to week view" → intent: "navigate", navigationType: "view_change", viewType: "week"

Be natural and conversational in responses. If unclear, set intent to "unknown" and ask for clarification.
`;

        try {
          // Use OpenAI to analyze the command via a custom analysis method
          const analysis = await this.analyzeCommandWithOpenAI(transcript, analysisPrompt);
          console.log('🧠 AI Analysis Result:', analysis);
          res.json(analysis);

        } catch (openaiError) {
          console.error('OpenAI analysis failed:', openaiError);
          
          // Try Cohere as backup
          try {
            if (process.env.COHERE_API_KEY) {
              if (!this.cohereService) {
                const { CohereAIService } = require('./cohereAI');
                this.cohereService = new CohereAIService({
                  apiKey: process.env.COHERE_API_KEY
                });
              }
              
              console.log('🤖 Using Cohere AI for command analysis...');
              const cohereAnalysis = await this.cohereService.generateCalendarResponse(
                `Analyze this voice command and provide intent: "${transcript}". Respond with JSON: {"intent": "create_event|query_events|delete_event|navigate|help", "confidence": 0.0-1.0, "response": "Natural response"}`
              );
              
              try {
                const parsed = JSON.parse(cohereAnalysis.text);
                res.json({
                  ...parsed,
                  originalCommand: transcript,
                  aiProvider: 'cohere'
                });
                return;
              } catch (parseError) {
                console.log('Cohere response not JSON, using text response');
              }
            }
          } catch (cohereError) {
            console.error('Cohere analysis failed:', cohereError);
          }
          
          // Fallback to basic pattern matching
          const fallbackAnalysis = {
            intent: this.detectBasicIntent(transcript),
            confidence: 0.5,
            response: "I'll help you with that request.",
            originalCommand: transcript,
            aiProvider: 'fallback'
          };
          
          res.json(fallbackAnalysis);
        }

      } catch (error) {
        console.error('❌ Command analysis error:', error);
        res.status(500).json({ 
          error: 'Failed to analyze command',
          details: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    });
  }

  // OpenAI command analysis method with DeepSeek fallback
  private async analyzeCommandWithOpenAI(transcript: string, prompt: string): Promise<any> {
    // Try OpenAI first
    const openaiKey = process.env.OPENAI_API_KEY;
    console.log('🔑 OpenAI API Key status:', openaiKey ? `Set (${openaiKey.substring(0, 10)}...)` : 'Not set');
    
    if (openaiKey) {
      try {
        const OpenAI = require('openai');
        const openai = new OpenAI({
          apiKey: openaiKey,
        });

        const response = await openai.chat.completions.create({
          model: 'gpt-3.5-turbo',
          messages: [
            {
              role: 'system',
              content: 'You are a helpful calendar assistant that analyzes voice commands and extracts structured information. Always respond with valid JSON.'
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.3,
          max_tokens: 800
        });

        const analysisText = response.choices[0]?.message?.content?.trim();
        
        if (analysisText) {
          try {
            return JSON.parse(analysisText);
          } catch (parseError) {
            console.warn('Failed to parse OpenAI response, trying DeepSeek...');
          }
        }
      } catch (error) {
        console.warn('OpenAI API failed, trying DeepSeek...', error);
      }
    }

    // Fallback to DeepSeek
    const deepseekKey = process.env.DEEPSEEK_API_KEY;
    if (deepseekKey) {
      console.log('🤖 Using DeepSeek API as fallback...');
      
      try {
        const response = await fetch('https://api.deepseek.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${deepseekKey}`,
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            model: 'deepseek-chat',
            messages: [
              {
                role: 'system',
                content: 'You are a helpful calendar assistant that analyzes voice commands and extracts structured information. Always respond with valid JSON.'
              },
              {
                role: 'user',
                content: prompt
              }
            ],
            max_tokens: 800,
            temperature: 0.3
          }),
        });

        if (response.ok) {
          const data = await response.json();
          const analysisText = data.choices[0]?.message?.content?.trim();
          
          if (analysisText) {
            try {
              return JSON.parse(analysisText);
            } catch (parseError) {
              console.error('Failed to parse DeepSeek response as JSON:', analysisText);
            }
          }
        } else {
          const errorData = await response.text();
          console.error('DeepSeek API Error:', response.status, errorData);
        }
      } catch (error) {
        console.error('DeepSeek API error:', error);
      }
    } else {
      console.log('⚠️ DeepSeek API key not configured, trying HuggingFace...');
    }

    // Try Hugging Face as final AI fallback
    const hfToken = process.env.HUGGING_FACE_TOKEN;
    if (!hfToken) {
      console.log('⚠️ HuggingFace token not configured, skipping HF fallback');
      // Final fallback to basic intent detection
      return {
        intent: this.detectBasicIntent(transcript),
        confidence: 0.5,
        response: "I'll help you with that.",
        originalCommand: transcript
      };
    }
    console.log('🤗 Using Hugging Face API as final AI fallback...');
    
    try {
      const response = await fetch('https://api-inference.huggingface.co/models/microsoft/DialoGPT-medium', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${hfToken}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          inputs: `You are a calendar assistant. Analyze this voice command and respond with JSON containing: intent (create_event, query_events, delete_event, navigate, help), confidence (0-1), and response. Command: "${transcript}"`
        }),
      });

      if (response.ok) {
        const data = await response.json();
        console.log('🤗 Hugging Face response:', data);
        
        // Try to extract structured response from HF
        if (data && data.length > 0 && data[0].generated_text) {
          const generatedText = data[0].generated_text;
          try {
            // Try to parse as JSON
            const jsonMatch = generatedText.match(/\{.*\}/s);
            if (jsonMatch) {
              return JSON.parse(jsonMatch[0]);
            }
          } catch (parseError) {
            console.log('HF response not JSON, using basic parsing...');
          }
        }
      } else {
        console.error('Hugging Face API Error:', response.status);
      }
    } catch (error) {
      console.error('Hugging Face API error:', error);
    }

    // Final fallback to basic intent detection
    console.log('🔄 Falling back to basic pattern matching...');
    return {
      intent: this.detectBasicIntent(transcript),
      confidence: 0.5,
      response: "I'll help you with that.",
      originalCommand: transcript
    };
  }

  // Basic intent detection fallback
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
    
    if (command.includes('go to') || command.includes('navigate') || command.includes('view')) {
      return 'navigate';
    }
    
    if (command.includes('help') || command.includes('what can you do')) {
      return 'help';
    }
    
    return 'unknown';
  }

  // Create calendar event from parsed voice command
  private async createEventFromParsing(eventParsing: any, userId: string, userEmail: string, tokens: any): Promise<{success: boolean, eventId?: string, calendarEventId?: string, error?: string}> {
    try {
      // Get user's calendars
      let calendars = [];
      let defaultCalendar = null;
      try {
        calendars = await this.database.getUserCalendars(userId);
        defaultCalendar = calendars.find(c => c.is_default) || calendars[0];
      } catch (error: any) {
        console.log('⚠️ No calendars found in database, creating virtual calendar:', error?.message);
      }

      // Create calendar reminders based on default alert time
      const calendarReminders = [{
        method: 'email' as const,
        minutes: 15 // Default 15 minute reminder
      }];

      // Try to create Google Calendar event
      let calendarResponse = null;
      try {
        if (tokens) {
          // Create isolated OAuth client for this user
          console.log('🔐 Creating isolated OAuth client for calendar event creation');
          const userOAuth2Client = new google.auth.OAuth2(
            process.env.GOOGLE_CLIENT_ID,
            process.env.GOOGLE_CLIENT_SECRET,
            process.env.GOOGLE_REDIRECT_URI
          );
          userOAuth2Client.setCredentials(tokens);
          
          // Create calendar service with isolated client
          const userCalendarService = new CalendarService();
          await userCalendarService.authenticate(tokens);
          
          calendarResponse = await userCalendarService.createEvent({
            title: eventParsing.title,
            description: eventParsing.description || `Event created via voice command`,
            startTime: eventParsing.startTime,
            endTime: eventParsing.endTime,
            timeZone: 'America/New_York',
            reminders: {
              useDefault: false,
              overrides: calendarReminders
            }
          }, userEmail);
          console.log('✅ Google Calendar event created:', calendarResponse?.id);
        } else {
          console.log('⚠️ No OAuth tokens available, skipping Google Calendar creation');
        }
      } catch (error: any) {
        console.error('⚠️ Calendar event creation failed, continuing without it:', error?.message);
      }

      // Store reminder in database
      const reminder = await this.database.addReminder({
        user_id: userId,
        calendar_id: defaultCalendar?.id || 'virtual',
        title: eventParsing.title,
        description: eventParsing.description || `Event created via voice command`,
        startTime: eventParsing.startTime,
        endTime: eventParsing.endTime,
        timezone: 'America/New_York',
        alertMinutes: [15], // Default 15 minute reminder
        created_via: 'ai',
        ai_confidence: eventParsing.confidence,
        original_input: `Voice: ${eventParsing.originalText || 'Voice command'}`,
        attendees: eventParsing.attendees || [],
        location: eventParsing.location,
        calendarEventId: calendarResponse?.id
      });

      // Track usage
      await this.database.trackUsage(userId, 'voice_event_created');

      return {
        success: true,
        eventId: reminder.id,
        calendarEventId: calendarResponse?.id
      };

    } catch (error) {
      console.error('Error creating event from voice:', error);
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred'
      };
    }
  }

  // Delete event based on voice command
  private async deleteEventFromVoice(transcript: string, userId: string, userEmail: string): Promise<{success: boolean, message: string, deletedCount?: number}> {
    try {
      // Get user's reminders
      const reminders = await this.database.getUserReminders(userEmail);
      
      if (reminders.length === 0) {
        return {
          success: false,
          message: "You don't have any events to delete."
        };
      }

      // Extract event identifier from transcript
      const command = transcript.toLowerCase();
      let eventToDelete = null;
      let deletedCount = 0;

      // Look for specific event mentions
      for (const reminder of reminders) {
        const title = reminder.title.toLowerCase();
        
        // Check if the transcript mentions this event
        if (command.includes(title) || title.includes(command.replace(/delete|cancel|remove/gi, '').trim())) {
          eventToDelete = reminder;
          break;
        }
      }

      // If no specific event found, look for time-based deletion
      if (!eventToDelete) {
        if (command.includes('today')) {
          const today = new Date();
          today.setHours(0, 0, 0, 0);
          const tomorrow = new Date(today);
          tomorrow.setDate(tomorrow.getDate() + 1);
          
          const todayEvents = reminders.filter(r => {
            const eventDate = new Date(r.startTime);
            return eventDate >= today && eventDate < tomorrow;
          });
          
          if (todayEvents.length > 0) {
                         // Delete all today's events
             for (const event of todayEvents) {
               await this.database.deleteReminder(event.id, userEmail);
               deletedCount++;
             }
            
            return {
              success: true,
              message: `Deleted ${deletedCount} event(s) for today.`,
              deletedCount
            };
          }
        }
      }

      if (eventToDelete) {
        // Delete the specific event
        await this.database.deleteReminder(eventToDelete.id, userEmail);
        
        // Try to delete from Google Calendar if it exists
        try {
          if (eventToDelete.calendarEventId) {
            // This would need proper calendar service implementation
            console.log(`🗑️ Would delete Google Calendar event: ${eventToDelete.calendarEventId}`);
          }
        } catch (error) {
          console.error('Failed to delete from Google Calendar:', error);
        }

        await this.database.trackUsage(userId, 'voice_event_deleted');
        
        return {
          success: true,
          message: `Deleted event: "${eventToDelete.title}"`,
          deletedCount: 1
        };
      }

      return {
        success: false,
        message: "I couldn't find that event. Please be more specific about which event to delete."
      };

    } catch (error) {
      console.error('Error deleting event from voice:', error);
      return {
        success: false,
        message: "Sorry, I couldn't delete the event. Please try again."
      };
    }
  }

  // Query events based on voice command
  private async queryEventsFromVoice(transcript: string, userId: string, userEmail: string): Promise<{message: string, events: any[]}> {
    try {
      const command = transcript.toLowerCase();
      const reminders = await this.database.getUserReminders(userEmail);
      
      let filteredEvents = reminders;
      let timeDescription = "";

      // Filter based on time references
      if (command.includes('today')) {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const tomorrow = new Date(today);
        tomorrow.setDate(tomorrow.getDate() + 1);
        
        filteredEvents = reminders.filter(r => {
          const eventDate = new Date(r.startTime);
          return eventDate >= today && eventDate < tomorrow;
        });
        timeDescription = "today";
      } else if (command.includes('tomorrow')) {
        const tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        tomorrow.setHours(0, 0, 0, 0);
        const dayAfter = new Date(tomorrow);
        dayAfter.setDate(dayAfter.getDate() + 1);
        
        filteredEvents = reminders.filter(r => {
          const eventDate = new Date(r.startTime);
          return eventDate >= tomorrow && eventDate < dayAfter;
        });
        timeDescription = "tomorrow";
      } else if (command.includes('this week')) {
        const now = new Date();
        const startOfWeek = new Date(now);
        startOfWeek.setDate(now.getDate() - now.getDay());
        startOfWeek.setHours(0, 0, 0, 0);
        const endOfWeek = new Date(startOfWeek);
        endOfWeek.setDate(startOfWeek.getDate() + 7);
        
        filteredEvents = reminders.filter(r => {
          const eventDate = new Date(r.startTime);
          return eventDate >= startOfWeek && eventDate < endOfWeek;
        });
        timeDescription = "this week";
      }

      // Generate response message
      let message = "";
      if (filteredEvents.length === 0) {
        message = timeDescription 
          ? `You have no events scheduled for ${timeDescription}.`
          : "You have no events in your calendar.";
      } else {
        const eventList = filteredEvents
          .sort((a, b) => new Date(a.startTime).getTime() - new Date(b.startTime).getTime())
          .slice(0, 5) // Limit to 5 events
          .map(event => {
            const date = new Date(event.startTime);
            const time = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
            const day = timeDescription === "this week" ? date.toLocaleDateString([], { weekday: 'short' }) : "";
            return `${day} ${time}: ${event.title}`.trim();
          })
          .join(', ');

        const moreText = filteredEvents.length > 5 ? ` and ${filteredEvents.length - 5} more` : "";
        
        message = timeDescription
          ? `You have ${filteredEvents.length} event(s) ${timeDescription}: ${eventList}${moreText}.`
          : `You have ${filteredEvents.length} event(s): ${eventList}${moreText}.`;
      }

      await this.database.trackUsage(userId, 'voice_schedule_queried');

      return {
        message,
        events: filteredEvents.slice(0, 10) // Return up to 10 events
      };

    } catch (error) {
      console.error('Error querying events from voice:', error);
      return {
        message: "Sorry, I couldn't retrieve your schedule. Please try again.",
        events: []
      };
    }
  }

  private setupAIVoiceRoutes(authMiddleware: any) {
    // Process voice command with enhanced AI
    this.app.post('/api/voice/process', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { transcript, config, hfToken } = req.body;
        const userId = req.session.userId!;
        const userEmail = req.session.userEmail!;

        if (!transcript || transcript.trim().length === 0) {
          return res.status(400).json({
            success: false,
            error: 'Voice transcript is required'
          });
        }

        console.log(`🎤 Processing voice command for ${userEmail}: "${transcript}"`);

        // Initialize AI services if needed
        if (!this.hfMCPService && hfToken) {
          try {
            this.hfMCPService = new HuggingFaceMCPService({
              huggingFaceToken: hfToken,
              mcpServerUrl: 'https://huggingface.co/mcp'
            });
            console.log('✅ HuggingFace MCP service initialized');
          } catch (error) {
            console.error('❌ Failed to initialize HF MCP service:', error);
          }
        }

        // Server-side voice processing - no browser APIs needed
        let response: any = {
          text: "I'll help you with that request.",
          suggestions: [],
          transcript: transcript
        };

        // Analyze command intent and execute actions
        try {
          // First, determine the intent using AI or pattern matching
          const intent = this.detectBasicIntent(transcript);
          console.log(`🎯 Detected intent: ${intent}`);

          if (intent === 'create_event') {
            // Parse the event details using AI
            if (process.env.COHERE_API_KEY) {
              if (!this.cohereService) {
                const { CohereAIService } = require('./cohereAI');
                this.cohereService = new CohereAIService({
                  apiKey: process.env.COHERE_API_KEY
                });
              }
              
              console.log('🤖 Using Cohere AI to parse event details...');
              const eventParsing = await this.cohereService.parseNaturalLanguageEvent(transcript);
              
              if (eventParsing.confidence > 0.4) {
                console.log('📅 Creating calendar event:', eventParsing);
                
                // Actually create the event
                const createResult = await this.createEventFromParsing(eventParsing, userId, userEmail, req.session.tokens);
                
                if (createResult.success) {
                  response = {
                    text: `✅ Created event: "${eventParsing.title}" for ${new Date(eventParsing.startTime).toLocaleDateString()} at ${new Date(eventParsing.startTime).toLocaleTimeString()}`,
                    suggestions: [
                      "Create another event",
                      "View my schedule",
                      "Edit this event",
                      "Set a reminder"
                    ],
                    actionTaken: 'event_created',
                    eventId: createResult.eventId,
                    calendarEventId: createResult.calendarEventId
                  };
                } else {
                  response = {
                    text: `❌ Sorry, I couldn't create the event. ${createResult.error}`,
                    suggestions: [
                      "Try rephrasing the request",
                      "Be more specific about the date and time",
                      "Check if you're logged in to Google Calendar"
                    ],
                    actionTaken: 'event_creation_failed'
                  };
                }
              } else {
                response = {
                  text: "I understand you want to create an event, but I need more details. Please specify the title, date, and time.",
                  suggestions: [
                    "Try: 'Create meeting with John tomorrow at 3pm'",
                    "Try: 'Schedule dinner Friday at 7pm'",
                    "Try: 'Book appointment next Tuesday at 2pm'"
                  ]
                };
              }
            } else {
              response.text = "I'd like to help you create an event. Please provide more details like the title, date, and time.";
            }
          } else if (intent === 'delete_event') {
            // Handle event deletion
            console.log('🗑️ Processing delete request...');
            const deleteResult = await this.deleteEventFromVoice(transcript, userId, userEmail);
            
            if (deleteResult.success) {
              response = {
                text: `✅ ${deleteResult.message}`,
                suggestions: [
                  "Delete another event",
                  "View my schedule",
                  "Create a new event"
                ],
                actionTaken: 'event_deleted',
                deletedCount: deleteResult.deletedCount
              };
            } else {
              response = {
                text: `❌ ${deleteResult.message}`,
                suggestions: [
                  "Try being more specific about which event to delete",
                  "Say the exact event title",
                  "View your schedule first"
                ],
                actionTaken: 'delete_failed'
              };
            }
          } else if (intent === 'query_events') {
            // Handle schedule queries
            console.log('📋 Processing schedule query...');
            const queryResult = await this.queryEventsFromVoice(transcript, userId, userEmail);
            
            response = {
              text: queryResult.message,
              suggestions: [
                "Create a new event",
                "Delete an event",
                "View tomorrow's schedule"
              ],
              actionTaken: 'events_queried',
              events: queryResult.events
            };
          } else {
            // Use Cohere for general responses
            if (process.env.COHERE_API_KEY) {
              if (!this.cohereService) {
                const { CohereAIService } = require('./cohereAI');
                this.cohereService = new CohereAIService({
                  apiKey: process.env.COHERE_API_KEY
                });
              }
              
              console.log('🤖 Using Cohere AI for general response...');
              const cohereResponse = await this.cohereService.generateCalendarResponse(
                `User said: "${transcript}". Provide a helpful response about their calendar request.`
              );
              response.text = cohereResponse.text || "I'm here to help with your calendar. You can ask me to create events, delete events, or check your schedule.";
            } else {
              response.text = "I'm here to help with your calendar. You can ask me to create events, delete events, or check your schedule.";
            }
            
            response.suggestions = [
              "Create a new event",
              "Check my schedule",
              "Delete an event",
              "What can you do?"
            ];
          }
        } catch (error) {
          console.error('Voice command processing error:', error);
          response = {
            text: "I'm having trouble processing that request. Please try again or be more specific.",
            suggestions: [
              "Try: 'Create meeting tomorrow at 3pm'",
              "Try: 'What's on my schedule today?'",
              "Try: 'Delete my lunch appointment'"
            ]
          };
        }

        // Track usage
        await this.database.trackUsage(userId, 'voice_command_processed');

        res.json({
          success: true,
          response: response,
          transcript: transcript,
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

    // Get AI capabilities
    this.app.get('/api/ai/capabilities', authMiddleware, async (req: Request, res: Response) => {
      try {
        const capabilities = this.hfMCPService ? this.hfMCPService.getCapabilities() : [];
        
        res.json({
          success: true,
          capabilities: capabilities,
          voiceSupported: true,
          huggingFaceConnected: !!this.hfMCPService
        });
      } catch (error) {
        console.error('Error fetching AI capabilities:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch AI capabilities'
        });
      }
    });

    // Health check for AI services
    this.app.post('/api/ai/health', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { token } = req.body;
        
        let hfHealth: any = { status: 'down', error: 'Not initialized' };
        
        if (token) {
          try {
            if (!this.hfMCPService) {
              this.hfMCPService = new HuggingFaceMCPService({
                huggingFaceToken: token,
                mcpServerUrl: 'https://huggingface.co/mcp'
              });
            }
            
            hfHealth = await this.hfMCPService.healthCheck();
          } catch (error) {
            hfHealth = { 
              status: 'down', 
              error: error instanceof Error ? error.message : String(error),
              capabilities: []
            };
          }
        }

        // Check Cohere if available
        let cohereHealth: any = { status: 'not_configured' };
        if (process.env.COHERE_API_KEY) {
          try {
            if (!this.cohereService) {
              const { CohereAIService } = require('./cohereAI');
              this.cohereService = new CohereAIService({
                apiKey: process.env.COHERE_API_KEY
              });
            }
            cohereHealth = await this.cohereService.healthCheck();
          } catch (error) {
            cohereHealth = {
              status: 'down',
              error: error instanceof Error ? error.message : String(error)
            };
          }
        }

        res.json({
          success: true,
          health: {
            huggingFace: hfHealth,
            cohere: cohereHealth,
            openAI: process.env.OPENAI_API_KEY ? 'available' : 'not_configured',
            voiceInterface: 'server_mode'
          }
        });
      } catch (error) {
        console.error('Error checking AI health:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to check AI health'
        });
      }
    });

    // Enhance calendar event with AI
    this.app.post('/api/ai/enhance-event', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { eventDescription } = req.body;
        
        if (!eventDescription) {
          return res.status(400).json({
            success: false,
            error: 'Event description is required'
          });
        }

        if (!this.hfMCPService) {
          return res.status(400).json({
            success: false,
            error: 'AI service not available. Please configure HuggingFace token.'
          });
        }

        const enhancement = await this.hfMCPService.enhanceCalendarEvent(eventDescription);
        
        res.json({
          success: true,
          original: eventDescription,
          enhanced: enhancement
        });
      } catch (error) {
        console.error('Error enhancing event:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to enhance event'
        });
      }
    });

    // Summarize events with AI
    this.app.post('/api/ai/summarize-events', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { events } = req.body;
        
        if (!events || !Array.isArray(events)) {
          return res.status(400).json({
            success: false,
            error: 'Events array is required'
          });
        }

        if (!this.hfMCPService) {
          return res.status(400).json({
            success: false,
            error: 'AI service not available. Please configure HuggingFace token.'
          });
        }

        const summary = await this.hfMCPService.summarizeEvents(events);
        
        res.json({
          success: true,
          eventCount: events.length,
          summary: summary
        });
      } catch (error) {
        console.error('Error summarizing events:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to summarize events'
        });
      }
    });

    // Translate content with AI
    this.app.post('/api/ai/translate', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { text, targetLanguage } = req.body;
        
        if (!text || !targetLanguage) {
          return res.status(400).json({
            success: false,
            error: 'Text and target language are required'
          });
        }

        if (!this.hfMCPService) {
          return res.status(400).json({
            success: false,
            error: 'AI service not available. Please configure HuggingFace token.'
          });
        }

        const translatedText = await this.hfMCPService.translateEvent(text, {
          targetLanguage: targetLanguage
        });
        
        res.json({
          success: true,
          original: text,
          translated: translatedText,
          targetLanguage: targetLanguage
        });
      } catch (error) {
        console.error('Error translating text:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to translate text'
        });
      }
    });

    // Answer questions about calendar
    this.app.post('/api/ai/ask-question', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { question } = req.body;
        const userId = req.session.userId!;
        
        if (!question) {
          return res.status(400).json({
            success: false,
            error: 'Question is required'
          });
        }

        if (!this.hfMCPService) {
          return res.status(400).json({
            success: false,
            error: 'AI service not available. Please configure HuggingFace token.'
          });
        }

        // Get user's recent events for context
        const userEmail = req.session.userEmail!;
        const recentReminders = await this.database.getUserReminders(userEmail);
        
        const context = recentReminders.map(r => 
          `${r.title} on ${new Date(r.startTime).toLocaleDateString()} at ${new Date(r.startTime).toLocaleTimeString()}`
        ).join('. ');

        const answer = await this.hfMCPService.answerCalendarQuestion(question, context);
        
        res.json({
          success: true,
          question: question,
          answer: answer,
          context: `Based on ${recentReminders.length} recent events`
        });
      } catch (error) {
        console.error('Error answering question:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to answer question'
        });
      }
    });

    // Get conversation history
    this.app.get('/api/voice/history', authMiddleware, async (req: Request, res: Response) => {
      try {
        // For now, return empty history since we're using server-side processing
        const history: any[] = [];
        
        res.json({
          success: true,
          history: history.slice(-20) // Last 20 commands
        });
      } catch (error) {
        console.error('Error fetching voice history:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch voice history'
        });
      }
    });
  }

  private setupSubscriptionRoutes(authMiddleware: any) {
    // Get pricing tiers
    this.app.get('/api/subscription/pricing', (req: Request, res: Response) => {
      const tiers = this.subscriptionService.getPricingTiers();
      res.json({ success: true, tiers });
    });

    // Create checkout session
    this.app.post('/api/subscription/checkout', authMiddleware, async (req: Request, res: Response) => {
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
    this.app.get('/api/subscription/status', authMiddleware, async (req: Request, res: Response) => {
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

    // Get user subscription for pricing buttons (this endpoint checks auth and returns subscription info)
    this.app.get('/api/user/subscription', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const status = await this.subscriptionService.getUserSubscriptionStatus(userId);
        
        res.json({
          success: true,
          isAuthenticated: true,
          tier: status.tier,
          isTrialActive: status.isTrialActive,
          daysUntilTrialEnd: status.daysUntilTrialEnd
        });
      } catch (error) {
        console.error('Error fetching user subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch subscription'
        });
      }
    });

    // Cancel subscription
    this.app.post('/api/subscription/cancel', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        
        await this.subscriptionService.cancelUserSubscription(userId);
        
        res.json({
          success: true,
          message: 'Subscription cancelled successfully'
        });
      } catch (error) {
        console.error('Error cancelling subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to cancel subscription'
        });
      }
    });

    // Stripe webhook - Handle payment events
    this.app.post('/api/subscription/webhook', express.raw({ type: 'application/json' }), async (req: Request, res: Response) => {
      const sig = req.headers['stripe-signature'] as string;
      const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

      if (!webhookSecret) {
        console.error('❌ Stripe webhook secret not configured');
        return res.status(400).send('Webhook secret not configured');
      }

      let event: any;

      try {
        // Verify webhook signature
        event = require('stripe').webhooks.constructEvent(req.body, sig, webhookSecret);
        console.log('✅ Stripe webhook signature verified:', event.type);
      } catch (err: any) {
        console.error('❌ Webhook signature verification failed:', err.message);
        return res.status(400).send(`Webhook Error: ${err.message}`);
      }

      try {
        // Handle the event
        await this.subscriptionService.handleWebhook(event);
        console.log(`✅ Successfully processed webhook event: ${event.type}`);
      } catch (error) {
        console.error('❌ Error processing webhook:', error);
        return res.status(500).send('Webhook processing failed');
      }

      res.status(200).json({ received: true });
    });

    // Manual subscription sync endpoint (admin/debug)
    this.app.post('/api/subscription/sync', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        console.log(`🔄 Manual sync requested for ${userEmail}`);
        
        const synced = await this.subscriptionService.syncUserSubscriptionWithStripe(userEmail);
        
        if (synced) {
          res.json({
            success: true,
            message: 'Subscription synced successfully with Stripe'
          });
        } else {
          res.json({
            success: false,
            message: 'No active subscription found in Stripe'
          });
        }
      } catch (error) {
        console.error('Error syncing subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to sync subscription'
        });
      }
    });

    // Admin endpoint to sync all subscriptions
    this.app.post('/api/admin/sync-all-subscriptions', async (req: Request, res: Response) => {
      try {
        // Simple authentication check (you might want to add proper admin auth)
        const authHeader = req.headers.authorization;
        if (authHeader !== `Bearer ${process.env.ADMIN_SECRET_KEY}`) {
          return res.status(401).json({ error: 'Unauthorized' });
        }

        await this.subscriptionService.syncAllSubscriptionsWithStripe();
        
        res.json({
          success: true,
          message: 'All subscriptions synced with Stripe'
        });
      } catch (error) {
        console.error('Error syncing all subscriptions:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to sync all subscriptions'
        });
      }
    });

    // Downgrade subscription
    this.app.post('/api/subscription/downgrade', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { targetTier } = req.body;
        const userId = req.session.userId!;
        const userEmail = req.session.userEmail!;

        if (!targetTier || !['free', 'pro'].includes(targetTier)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid target tier. Must be "free" or "pro"'
          });
        }

        // Get current subscription status
        const currentStatus = await this.subscriptionService.getUserSubscriptionStatus(userId);
        
        // Validate downgrade path
        const validDowngrades: Record<string, string[]> = {
          'max': ['pro', 'free'],
          'pro': ['free']
        };

        if (!validDowngrades[currentStatus.tier]?.includes(targetTier)) {
          return res.status(400).json({
            success: false,
            error: `Cannot downgrade from ${currentStatus.tier} to ${targetTier}`
          });
        }

        console.log(`⬇️ Downgrade request: ${userEmail} from ${currentStatus.tier} to ${targetTier}`);

        // Perform the actual downgrade
        const result = await this.subscriptionService.downgradeUserSubscription(userId, userEmail, targetTier as 'free' | 'pro');
        
        res.json({
          success: true,
          message: result.message,
          newTier: targetTier,
          effectiveDate: result.effectiveDate
        });
      } catch (error) {
        console.error('Error downgrading subscription:', error);
        res.status(500).json({
          success: false,
          error: error instanceof Error ? error.message : 'Failed to downgrade subscription'
        });
      }
    });

    // Get billing information and invoices
    this.app.get('/api/subscription/billing', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userId = req.session.userId!;
        const userEmail = req.session.userEmail!;
        
        // Get subscription status
        const subscription = await this.subscriptionService.getUserSubscriptionStatus(userId);
        
        // Simulate billing information (in real app, fetch from Stripe)
        const nextBillingDate = new Date();
        nextBillingDate.setMonth(nextBillingDate.getMonth() + 1);
        
        const billingInfo = {
          currentPlan: subscription.tier,
          status: subscription.status,
          nextBillingDate: subscription.tier !== 'free' ? nextBillingDate.toISOString() : null,
          amount: subscription.tier === 'pro' ? 100 : subscription.tier === 'max' ? 300 : 0,
          currency: 'usd',
          paymentMethod: {
            type: 'card',
            last4: '4242', // Simulated
            brand: 'visa',
            expMonth: 12,
            expYear: 2025
          },
          invoices: [
            // Simulated invoice history
            {
              id: 'inv_001',
              date: new Date(Date.now() - 30*24*60*60*1000).toISOString(),
              amount: subscription.tier === 'pro' ? 100 : 300,
              status: 'paid',
              downloadUrl: '/api/subscription/invoice/inv_001'
            }
          ]
        };
        
        res.json({
          success: true,
          billing: billingInfo
        });
      } catch (error) {
        console.error('Error fetching billing information:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to fetch billing information'
        });
      }
    });

    // Download invoice (placeholder)
    this.app.get('/api/subscription/invoice/:invoiceId', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { invoiceId } = req.params;
        
        // In a real implementation, this would fetch the invoice from Stripe
        // and return the PDF or redirect to Stripe's hosted invoice page
        
        res.json({
          success: true,
          message: 'Invoice download feature',
          invoiceId,
          downloadUrl: `https://dashboard.stripe.com/invoices/${invoiceId}`, // Placeholder
          note: 'In production, this would provide actual invoice download'
        });
      } catch (error) {
        console.error('Error downloading invoice:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to download invoice'
        });
      }
    });

    // Update payment method (redirect to Stripe Customer Portal)
    this.app.post('/api/subscription/update-payment', authMiddleware, async (req: Request, res: Response) => {
      try {
        const userEmail = req.session.userEmail!;
        
        // In a real implementation, this would create a Stripe Customer Portal session
        // const portalSession = await stripe.billingPortal.sessions.create({
        //   customer: stripeCustomerId,
        //   return_url: `${process.env.FRONTEND_URL}/settings`,
        // });
        
        res.json({
          success: true,
          message: 'Payment method update feature',
          redirectUrl: 'https://billing.stripe.com/session/...',  // Placeholder
          note: 'In production, this would redirect to Stripe Customer Portal'
        });
      } catch (error) {
        console.error('Error updating payment method:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to update payment method'
        });
      }
    });

    // Reactivate canceled subscription
    this.app.post('/api/subscription/reactivate', authMiddleware, async (req: Request, res: Response) => {
      try {
        const { tierId } = req.body;
        const userId = req.session.userId!;
        const userEmail = req.session.userEmail!;

        if (!tierId || !['pro', 'max'].includes(tierId)) {
          return res.status(400).json({
            success: false,
            error: 'Invalid tier ID'
          });
        }

        // Check current status
        const currentStatus = await this.subscriptionService.getUserSubscriptionStatus(userId);
        
        if (currentStatus.status === 'active') {
          return res.status(400).json({
            success: false,
            error: 'Subscription is already active'
          });
        }

        // Create new checkout session for reactivation
        const checkoutUrl = await this.subscriptionService.createCheckoutSession(userId, tierId);
        
        console.log(`🔄 Reactivation checkout created for ${userEmail} - ${tierId} tier`);
        
        res.json({
          success: true,
          checkoutUrl,
          message: 'Reactivation checkout session created'
        });
      } catch (error) {
        console.error('Error reactivating subscription:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to reactivate subscription'
        });
      }
    });
  }

  private setupAdminRoutes() {
    // Admin routes can be added here if needed
    // These would require additional admin authentication middleware
    
    // Debug endpoint to clear user data (for testing data isolation)
    this.app.post('/api/debug/clear-user-data', async (req: Request, res: Response) => {
      try {
        const { userEmail, adminKey } = req.body;
        
        // Simple admin key check (in production, use proper admin auth)
        if (adminKey !== process.env.ADMIN_SECRET_KEY) {
          return res.status(401).json({ error: 'Unauthorized' });
        }
        
        if (!userEmail) {
          return res.status(400).json({ error: 'User email required' });
        }
        
        console.log(`🗑️ Clearing all data for user: ${userEmail}`);
        
        // Get user
        const user = await this.database.getUserByEmail(userEmail);
        if (!user) {
          return res.status(404).json({ error: 'User not found' });
        }
        
        // Clear user reminders from database
        await this.database.clearUserReminders(user.id);
        
        console.log(`✅ Cleared all data for user: ${userEmail}`);
        
        res.json({
          success: true,
          message: `All data cleared for user: ${userEmail}`
        });
        
      } catch (error) {
        console.error('Error clearing user data:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to clear user data'
        });
      }
    });

    // Debug endpoint to check current session user
    this.app.get('/api/debug/current-user', (req: Request, res: Response) => {
      try {
        const sessionInfo = {
          userEmail: req.session.userEmail || null,
          userId: req.session.userId || null,
          sessionId: req.sessionID,
          hasTokens: !!req.session.tokens,
          timestamp: new Date().toISOString()
        };
        
        console.log('🔍 Current session info:', sessionInfo);
        
        res.json({
          success: true,
          session: sessionInfo
        });
      } catch (error) {
        console.error('Error checking current user:', error);
        res.status(500).json({
          success: false,
          error: 'Failed to check current user'
        });
      }
    });
  }

  // Legacy auth method for compatibility
  private requireAuth(req: Request, res: Response, next: any) {
    if (!req.session.userEmail || !req.session.userId) {
      console.log('❌ App access denied - no session');
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
            const user = await this.database.getUserById(reminder.user_id);
            if (user) {
              await this.emailService.sendReminderEmail(
                user.email,
                user.name || 'User',
                reminder.title,
                reminder.description,
                reminder.startTime,
                alertMinutes
              );
              
              await this.database.markAlertSent(reminder.id, alertMinutes);
              console.log(`✅ Reminder sent: ${reminder.title} (${alertMinutes} min alert)`);
            }
          } catch (error) {
            console.error(`Error sending reminder ${reminder.id}:`, error);
          }
        }
      } catch (error) {
        console.error('Error in reminder scheduler:', error);
      }
    }, 300000); // Check every 5 minutes (reduced to prevent rate limiting)
  }

  public start() {
    this.app.listen(this.port, () => {
      console.log(`🚀 AI Reminder Agent running on port ${this.port}`);
      console.log(`📱 Visit http://localhost:${this.port} to get started`);
      console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
      
      console.log('📋 Configuration Status:');
      console.log(`   Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? '✅' : '❌'}`);
      console.log(`   OpenAI API: ${process.env.OPENAI_API_KEY ? '✅' : '❌'}`);
      console.log(`   DeepSeek API: ${process.env.DEEPSEEK_API_KEY ? '✅ (fallback)' : '❌'}`);
      console.log(`   Hugging Face API: ${process.env.HUGGING_FACE_TOKEN ? '✅ (final fallback)' : '❌'}`);
      console.log(`   Email Service: ${process.env.EMAIL_FROM ? '✅' : '❌'}`);
      console.log(`   Stripe Payments: ${process.env.STRIPE_SECRET_KEY ? '✅' : '❌'}`);
      
      if (process.env.STRIPE_PUBLISHABLE_KEY && process.env.STRIPE_SECRET_KEY) {
        console.log('💳 Stripe Configuration:');
        console.log(`   Publishable Key: ${process.env.STRIPE_PUBLISHABLE_KEY.substring(0, 20)}...`);
        console.log(`   Secret Key: sk_***`);
      }
      
      if (process.env.GOOGLE_CLIENT_ID) {
        console.log('🔍 OAuth Debug Info:');
        console.log(`   Client ID: ${process.env.GOOGLE_CLIENT_ID.substring(0, 20)}...`);
        console.log(`   Client Secret: GOCSPX-***`);
        console.log(`   Redirect URI: ${process.env.GOOGLE_REDIRECT_URI}`);
      }
    });
  }
}

// Start the application
const app = new AIReminderApp();
app.start(); 
