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
          hasTokens: !!req.session.tokens
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

    // User profile and settings routes (using enhanced auth with email verification)
    this.setupUserRoutes(authMiddleware);
    
    // Calendar and reminder routes (using enhanced auth with email verification)
    this.setupReminderRoutes(authMiddleware);
    
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
            this.oauth2Client.setCredentials(tokens);
            
            calendarResponse = await this.calendarService.createEvent({
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
