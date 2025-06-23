import 'express-session';

declare module 'express-session' {
  interface SessionData {
    userEmail?: string;
    userId?: string;
    loginTime?: Date;
    lastActivity?: Date;
    sessionId?: string;
    tokens?: {
      access_token?: string;
      refresh_token?: string;
      scope?: string;
      token_type?: string;
      expiry_date?: number;
    };
    twoFactorVerified?: boolean;
    pendingTwoFactor?: boolean;
    twoFactorUserId?: string;
  }
}

export {}; 