declare global {
  namespace Express {
    interface Session {
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
}

export {}; 