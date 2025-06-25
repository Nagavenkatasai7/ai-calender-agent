/// <reference types="express" />
/// <reference types="express-session" />

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

declare module 'express-serve-static-core' {
  interface Request {
    session: import('express-session').Session & import('express-session').SessionData & {
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
    };
  }
}

export {}; 