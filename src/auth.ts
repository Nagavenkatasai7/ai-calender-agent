import bcrypt from 'bcryptjs';
import speakeasy from 'speakeasy';
import qrcode from 'qrcode';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { Request, Response, NextFunction } from 'express';
import { Database, User } from './database';

export interface AuthConfig {
  jwtSecret: string;
  sessionSecret: string;
  bcryptRounds: number;
  maxLoginAttempts: number;
  lockoutTime: number; // in milliseconds
  sessionTimeout: number; // in milliseconds
  requireTwoFactor: boolean;
}

export interface LoginAttempt {
  email: string;
  attempts: number;
  lastAttempt: Date;
  lockedUntil?: Date;
}

export interface TwoFactorSecret {
  secret: string;
  qrCode: string;
  backupCodes: string[];
}

export class AuthService {
  private database: Database;
  private config: AuthConfig;
  private loginAttempts: Map<string, LoginAttempt> = new Map();
  private activeTokens: Set<string> = new Set();

  constructor(database: Database, config: AuthConfig) {
    this.database = database;
    this.config = config;
    
    // Clean up expired login attempts every hour
    setInterval(() => this.cleanupExpiredAttempts(), 60 * 60 * 1000);
  }

  // Secure password hashing
  async hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, this.config.bcryptRounds);
  }

  async verifyPassword(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  }

  // Generate secure tokens
  generateSecureToken(): string {
    return crypto.randomBytes(32).toString('hex');
  }

  generateJWT(userId: string, email: string): string {
    const payload = {
      userId,
      email,
      iat: Date.now(),
      type: 'access'
    };
    
    const token = jwt.sign(payload, this.config.jwtSecret, {
      expiresIn: '24h',
      issuer: 'ai-reminder-app',
      audience: 'ai-reminder-users'
    });
    
    this.activeTokens.add(token);
    return token;
  }

  generateRefreshToken(userId: string): string {
    const payload = {
      userId,
      iat: Date.now(),
      type: 'refresh'
    };
    
    return jwt.sign(payload, this.config.jwtSecret, {
      expiresIn: '7d',
      issuer: 'ai-reminder-app',
      audience: 'ai-reminder-users'
    });
  }

  verifyJWT(token: string): any {
    try {
      if (!this.activeTokens.has(token)) {
        throw new Error('Token has been revoked');
      }
      
      return jwt.verify(token, this.config.jwtSecret, {
        issuer: 'ai-reminder-app',
        audience: 'ai-reminder-users'
      });
    } catch (error) {
      throw new Error('Invalid token');
    }
  }

  revokeToken(token: string): void {
    this.activeTokens.delete(token);
  }

  // Rate limiting for login attempts
  async checkRateLimit(email: string): Promise<{ allowed: boolean; reason?: string; retryAfter?: number }> {
    const attempt = this.loginAttempts.get(email);
    
    if (!attempt) {
      return { allowed: true };
    }
    
    // Check if account is locked
    if (attempt.lockedUntil && new Date() < attempt.lockedUntil) {
      const retryAfter = Math.ceil((attempt.lockedUntil.getTime() - Date.now()) / 1000);
      return {
        allowed: false,
        reason: 'Account temporarily locked due to too many failed attempts',
        retryAfter
      };
    }
    
    // Reset if lockout period has passed
    if (attempt.lockedUntil && new Date() >= attempt.lockedUntil) {
      this.loginAttempts.delete(email);
      return { allowed: true };
    }
    
    // Check if too many attempts
    if (attempt.attempts >= this.config.maxLoginAttempts) {
      const lockUntil = new Date(Date.now() + this.config.lockoutTime);
      attempt.lockedUntil = lockUntil;
      
      const retryAfter = Math.ceil(this.config.lockoutTime / 1000);
      return {
        allowed: false,
        reason: 'Too many failed login attempts',
        retryAfter
      };
    }
    
    return { allowed: true };
  }

  recordFailedAttempt(email: string): void {
    const attempt = this.loginAttempts.get(email) || {
      email,
      attempts: 0,
      lastAttempt: new Date()
    };
    
    attempt.attempts++;
    attempt.lastAttempt = new Date();
    
    this.loginAttempts.set(email, attempt);
  }

  recordSuccessfulLogin(email: string): void {
    this.loginAttempts.delete(email);
  }

  private cleanupExpiredAttempts(): void {
    const now = new Date();
    const expiry = 24 * 60 * 60 * 1000; // 24 hours
    
    for (const [email, attempt] of this.loginAttempts.entries()) {
      if (now.getTime() - attempt.lastAttempt.getTime() > expiry) {
        this.loginAttempts.delete(email);
      }
    }
  }

  // Two-Factor Authentication
  async generateTwoFactorSecret(userEmail: string): Promise<TwoFactorSecret> {
    const secret = speakeasy.generateSecret({
      name: `AI Reminder (${userEmail})`,
      issuer: 'AI Reminder App',
      length: 32
    });

    const qrCode = await qrcode.toDataURL(secret.otpauth_url || '');
    
    // Generate backup codes
    const backupCodes = Array.from({ length: 8 }, () => 
      crypto.randomBytes(4).toString('hex').toUpperCase()
    );

    return {
      secret: secret.base32 || '',
      qrCode,
      backupCodes
    };
  }

  verifyTwoFactorToken(secret: string, token: string): boolean {
    return speakeasy.totp.verify({
      secret,
      encoding: 'base32',
      token,
      window: 2 // Allow 2 time steps of variance
    });
  }

  verifyBackupCode(userBackupCodes: string[], providedCode: string): { valid: boolean; remainingCodes?: string[] } {
    const codeIndex = userBackupCodes.indexOf(providedCode.toUpperCase());
    
    if (codeIndex === -1) {
      return { valid: false };
    }
    
    // Remove used backup code
    const remainingCodes = userBackupCodes.filter((_, index) => index !== codeIndex);
    
    return { valid: true, remainingCodes };
  }

  // Secure session management
  async createSecureSession(req: Request, user: User): Promise<void> {
    // Store minimal user info in session immediately
    req.session.userId = user.id;
    req.session.userEmail = user.email;
    req.session.loginTime = new Date();
    req.session.lastActivity = new Date();
    req.session.sessionId = this.generateSecureToken();
    
    // Set secure session flags
    if (req.session.cookie) {
      req.session.cookie.secure = process.env.NODE_ENV === 'production';
      req.session.cookie.httpOnly = true;
      req.session.cookie.sameSite = 'lax';
      req.session.cookie.maxAge = this.config.sessionTimeout;
    }

    // Session regeneration can cause timing issues in OAuth flow, so we skip it for now
    // TODO: Implement proper session regeneration with promise-based approach
  }

  async validateSession(req: Request): Promise<{ valid: boolean; reason?: string }> {
    if (!req.session.userId || !req.session.userEmail) {
      return { valid: false, reason: 'No session data' };
    }

    // Check session timeout
    const lastActivity = req.session.lastActivity ? new Date(req.session.lastActivity) : null;
    if (!lastActivity || Date.now() - lastActivity.getTime() > this.config.sessionTimeout) {
      return { valid: false, reason: 'Session expired' };
    }

    // Update last activity
    req.session.lastActivity = new Date();
    
    return { valid: true };
  }

  async invalidateSession(req: Request): Promise<void> {
    return new Promise((resolve) => {
      req.session.destroy((err) => {
        if (err) {
          console.error('Session destruction error:', err);
        }
        resolve();
      });
    });
  }

  // Security middleware
  createAuthMiddleware(options: { requireEmailVerification?: boolean } = {}) {
    const { requireEmailVerification = true } = options;
    
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        // Check for JWT token in Authorization header
        const authHeader = req.headers.authorization;
        let tokenValid = false;
        
        if (authHeader && authHeader.startsWith('Bearer ')) {
          const token = authHeader.substring(7);
          try {
            const payload = this.verifyJWT(token);
            req.session.userId = payload.userId;
            req.session.userEmail = payload.email;
            tokenValid = true;
          } catch (error) {
            // Token invalid, continue to session check
          }
        }
        
        // If no valid token, check session
        if (!tokenValid) {
          const sessionCheck = await this.validateSession(req);
          if (!sessionCheck.valid) {
            return res.status(401).json({
              success: false,
              error: 'Authentication required',
              reason: sessionCheck.reason
            });
          }
        }
        
        // Add user info to request
        const user = await this.database.getUserById(req.session.userId!);
        if (!user) {
          return res.status(401).json({
            success: false,
            error: 'User not found'
          });
        }
        
        // ⚠️ SECURITY: Check email verification status
        if (requireEmailVerification && !user.email_verified) {
          console.warn(`🚫 Access denied for unverified user: ${user.email}`);
          
          // Clear the session for unverified users
          await this.invalidateSession(req);
          
          return res.status(403).json({
            success: false,
            error: 'Email verification required',
            code: 'EMAIL_NOT_VERIFIED',
            message: 'Please verify your email address before accessing this feature. Check your inbox for the verification email.',
            action: 'verify_email'
          });
        }
        
        (req as any).user = user;
        next();
      } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(500).json({
          success: false,
          error: 'Authentication error'
        });
      }
    };
  }

  // Password strength validation
  validatePasswordStrength(password: string): { valid: boolean; issues: string[] } {
    const issues: string[] = [];
    
    if (password.length < 8) {
      issues.push('Password must be at least 8 characters long');
    }
    
    if (password.length > 128) {
      issues.push('Password must be less than 128 characters long');
    }
    
    if (!/[a-z]/.test(password)) {
      issues.push('Password must contain at least one lowercase letter');
    }
    
    if (!/[A-Z]/.test(password)) {
      issues.push('Password must contain at least one uppercase letter');
    }
    
    if (!/\d/.test(password)) {
      issues.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
      issues.push('Password must contain at least one special character');
    }
    
    // Check for common patterns
    const commonPatterns = [
      /123456/,
      /password/i,
      /qwerty/i,
      /admin/i,
      /letmein/i
    ];
    
    for (const pattern of commonPatterns) {
      if (pattern.test(password)) {
        issues.push('Password contains common patterns that are not secure');
        break;
      }
    }
    
    return {
      valid: issues.length === 0,
      issues
    };
  }

  // Generate password reset token
  generatePasswordResetToken(): { token: string; expires: Date } {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
    
    return { token, expires };
  }

  // Email verification token
  generateEmailVerificationToken(): { token: string; expires: Date } {
    const token = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
    
    return { token, expires };
  }

  // Security headers middleware
  createSecurityHeadersMiddleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      // Prevent clickjacking
      res.setHeader('X-Frame-Options', 'DENY');
      
      // Prevent MIME type sniffing
      res.setHeader('X-Content-Type-Options', 'nosniff');
      
      // Enable XSS protection
      res.setHeader('X-XSS-Protection', '1; mode=block');
      
      // Strict transport security (HTTPS only)
      if (process.env.NODE_ENV === 'production') {
        res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
      }
      
      // Content Security Policy
      res.setHeader('Content-Security-Policy', [
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' https://js.stripe.com https://checkout.stripe.com",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self' https://api.stripe.com",
        "frame-src https://js.stripe.com https://hooks.stripe.com https://checkout.stripe.com"
      ].join('; '));
      
      // Referrer policy
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      
      next();
    };
  }
} 