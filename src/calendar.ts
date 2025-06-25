import { google } from 'googleapis';
import { OAuth2Client } from 'google-auth-library';

export interface EventDetails {
  title: string;
  description?: string;
  startTime: Date;
  endTime: Date;
  timeZone?: string;
  reminders?: {
    useDefault: boolean;
    overrides?: {
      method: 'email' | 'popup';
      minutes: number;
    }[];
  };
}

export class CalendarService {
  private oauth2Client: OAuth2Client;
  private calendar: any;

  constructor() {
    this.oauth2Client = new google.auth.OAuth2(
      process.env.GOOGLE_CLIENT_ID,
      process.env.GOOGLE_CLIENT_SECRET,
      process.env.GOOGLE_REDIRECT_URI
    );
    
    // Initialize without auth - will be set in authenticate method
    this.calendar = null;
  }

  async authenticate(tokens: any) {
    this.oauth2Client.setCredentials(tokens);
    // Create calendar API instance with authenticated client
    this.calendar = google.calendar({ version: 'v3', auth: this.oauth2Client });
  }

  async createEvent(eventDetails: EventDetails, userEmail?: string) {
    try {
      // Ensure calendar API is initialized
      if (!this.calendar) {
        throw new Error('Calendar service not authenticated. Call authenticate() first.');
      }

      // If userEmail is provided, we need to authenticate with user tokens
      if (userEmail) {
        // This would require getting the user's tokens from the database
        // For now, we'll use the current oauth2Client
      }

      const event = {
        summary: eventDetails.title,
        description: eventDetails.description,
        start: {
          dateTime: eventDetails.startTime.toISOString(),
          timeZone: eventDetails.timeZone || 'America/New_York',
        },
        end: {
          dateTime: eventDetails.endTime.toISOString(),
          timeZone: eventDetails.timeZone || 'America/New_York',
        },
        reminders: eventDetails.reminders || {
          useDefault: false,
          overrides: [
            { method: 'email', minutes: 60 }, // Default 1 hour reminder
            { method: 'popup', minutes: 10 }  // Default 10 minutes popup
          ]
        }
      };

      const response = await this.calendar.events.insert({
        calendarId: 'primary',
        resource: event,
      });

      console.log('Calendar event created:', response.data.htmlLink);
      return response.data;
    } catch (error) {
      console.error('Error creating calendar event:', error);
      throw error;
    }
  }

  async getUserInfo() {
    try {
      const oauth2 = google.oauth2({ version: 'v2', auth: this.oauth2Client });
      const response = await oauth2.userinfo.get();
      return response.data;
    } catch (error) {
      console.error('Error getting user info:', error);
      throw error;
    }
  }

  getAuthUrl() {
    const scopes = [
      'https://www.googleapis.com/auth/calendar',
      'https://www.googleapis.com/auth/userinfo.email',
      'https://www.googleapis.com/auth/userinfo.profile'
    ];
    
    return this.oauth2Client.generateAuthUrl({
      access_type: 'offline',
      scope: scopes,
      prompt: 'consent' // Force consent screen to get refresh token
    });
  }

  async getTokens(code: string) {
    const { tokens } = await this.oauth2Client.getToken(code);
    return tokens;
  }

  async refreshTokens(refreshToken: string) {
    this.oauth2Client.setCredentials({ refresh_token: refreshToken });
    const { credentials } = await this.oauth2Client.refreshAccessToken();
    return credentials;
  }
} 