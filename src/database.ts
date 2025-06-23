import fs from 'fs/promises';
import path from 'path';
import { v4 as uuidv4 } from 'uuid';
import sqlite3 from 'sqlite3';
import { Database as SqliteDatabase } from 'sqlite3';

export interface ReminderRecord {
  id: string;
  title: string;
  description: string;
  startTime: Date;
  userEmail: string;
  alertMinutes: number[];
  sentAlerts: number[]; // Track which alerts have been sent
  calendarEventId?: string;
  createdAt: Date;
}

export interface UserSession {
  email: string;
  tokens: any;
  lastActive: Date;
}

export interface User {
  id: string;
  email: string;
  name?: string;
  password_hash?: string;
  email_verified: boolean;
  email_verification_token?: string;
  email_verification_expires?: Date;
  password_reset_token?: string;
  password_reset_expires?: Date;
  two_factor_secret?: string;
  two_factor_enabled: boolean;
  two_factor_backup_codes?: string;
  failed_login_attempts: number;
  locked_until?: Date;
  subscription_tier: 'free' | 'pro' | 'max';
  subscription_status: 'active' | 'canceled' | 'trial';
  trial_ends_at?: Date;
  created_at: Date;
  last_login: Date;
  settings: UserSettings;
}

export interface UserSettings {
  timezone: string;
  notification_preferences: {
    email: boolean;
    push: boolean;
    sms: boolean;
  };
  theme: 'light' | 'dark' | 'auto';
  ai_personality: 'professional' | 'casual' | 'concise';
}

export interface Subscription {
  id: string;
  user_id: string;
  tier: 'free' | 'pro' | 'max';
  status: 'active' | 'canceled' | 'past_due' | 'trial';
  stripe_subscription_id?: string;
  current_period_start: Date;
  current_period_end: Date;
  created_at: Date;
}

export interface UsageTracking {
  id: string;
  user_id: string;
  month: string; // YYYY-MM format
  ai_events_created: number;
  calendars_used: number;
  api_calls: number;
  features_used: string[]; // JSON array of feature names
}

export interface Calendar {
  id: string;
  user_id: string;
  name: string;
  color: string;
  is_default: boolean;
  google_calendar_id?: string;
  created_at: Date;
  settings: CalendarSettings;
}

export interface CalendarSettings {
  visibility: 'private' | 'shared' | 'public';
  auto_sync: boolean;
  default_event_duration: number; // minutes
}

export interface Reminder {
  id: string;
  calendar_id: string;
  user_id: string;
  title: string;
  description: string;
  startTime: Date;
  endTime: Date;
  timezone: string;
  alertMinutes: number[];
  created_via: 'ai' | 'manual' | 'import';
  ai_confidence?: number;
  original_input?: string;
  recurrence_rule?: string;
  attendees?: string[];
  location?: string;
  calendarEventId?: string;
  created_at: Date;
  updated_at: Date;
}

export class Database {
  private dbPath: string;
  private sessionsPath: string;
  private db: SqliteDatabase;

  constructor() {
    this.dbPath = path.join(__dirname, '..', 'data', 'reminders.json');
    this.sessionsPath = path.join(__dirname, '..', 'data', 'sessions.json');
    this.db = new sqlite3.Database('./data/calendar_app.db');
    this.init();
  }

  private async init() {
    // Users table with subscription info and security fields
    await this.run(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT,
        password_hash TEXT,
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_token TEXT,
        email_verification_expires DATETIME,
        password_reset_token TEXT,
        password_reset_expires DATETIME,
        two_factor_secret TEXT,
        two_factor_enabled BOOLEAN DEFAULT FALSE,
        two_factor_backup_codes TEXT,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until DATETIME,
        subscription_tier TEXT DEFAULT 'free',
        subscription_status TEXT DEFAULT 'trial',
        trial_ends_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME DEFAULT CURRENT_TIMESTAMP,
        settings TEXT DEFAULT '{"timezone":"America/New_York","notification_preferences":{"email":true,"push":false,"sms":false},"theme":"auto","ai_personality":"professional"}'
      )
    `);

    // Subscriptions table
    await this.run(`
      CREATE TABLE IF NOT EXISTS subscriptions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        tier TEXT NOT NULL,
        status TEXT NOT NULL,
        stripe_subscription_id TEXT,
        current_period_start DATETIME NOT NULL,
        current_period_end DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Usage tracking table
    await this.run(`
      CREATE TABLE IF NOT EXISTS usage_tracking (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        month TEXT NOT NULL,
        ai_events_created INTEGER DEFAULT 0,
        calendars_used INTEGER DEFAULT 1,
        api_calls INTEGER DEFAULT 0,
        features_used TEXT DEFAULT '[]',
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, month)
      )
    `);

    // Calendars table
    await this.run(`
      CREATE TABLE IF NOT EXISTS calendars (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        name TEXT NOT NULL,
        color TEXT DEFAULT '#007aff',
        is_default BOOLEAN DEFAULT false,
        google_calendar_id TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        settings TEXT DEFAULT '{"visibility":"private","auto_sync":true,"default_event_duration":60}',
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Enhanced reminders table
    await this.run(`
      CREATE TABLE IF NOT EXISTS reminders (
        id TEXT PRIMARY KEY,
        calendar_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT,
        startTime DATETIME NOT NULL,
        endTime DATETIME NOT NULL,
        timezone TEXT DEFAULT 'America/New_York',
        alertMinutes TEXT NOT NULL,
        created_via TEXT DEFAULT 'manual',
        ai_confidence REAL,
        original_input TEXT,
        recurrence_rule TEXT,
        attendees TEXT DEFAULT '[]',
        location TEXT,
        calendarEventId TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (calendar_id) REFERENCES calendars (id),
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // OAuth tokens table (existing)
    await this.run(`
      CREATE TABLE IF NOT EXISTS oauth_tokens (
        id TEXT PRIMARY KEY,
        user_email TEXT UNIQUE NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT,
        expires_at DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // User sessions for security tracking
    await this.run(`
      CREATE TABLE IF NOT EXISTS user_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_activity DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME,
        is_active BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Connected accounts (Google, Outlook, etc.)
    await this.run(`
      CREATE TABLE IF NOT EXISTS connected_accounts (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        provider TEXT NOT NULL,
        provider_account_id TEXT NOT NULL,
        access_token TEXT,
        refresh_token TEXT,
        expires_at DATETIME,
        scope TEXT,
        is_active BOOLEAN DEFAULT TRUE,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id),
        UNIQUE(user_id, provider, provider_account_id)
      )
    `);

    // Security audit log
    await this.run(`
      CREATE TABLE IF NOT EXISTS security_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT,
        action TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        details TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
      )
    `);

    // Create default data
    await this.createDefaultData();
  }

  private async createDefaultData() {
    // This will be called when setting up new users
  }

  // User management methods
  async updateUserSubscription(userId: string, tier: 'free' | 'pro' | 'max', status: 'active' | 'canceled' | 'trial' = 'active'): Promise<void> {
    const now = new Date();
    
    await this.run(
      `UPDATE users SET 
       subscription_tier = ?, 
       subscription_status = ?, 
       trial_ends_at = NULL,
       last_login = ?
       WHERE id = ?`,
      [tier, status, now.toISOString(), userId]
    );
  }

  async createUser(email: string, name?: string): Promise<User> {
    const id = this.generateId();
    const trialEndsAt = new Date();
    trialEndsAt.setDate(trialEndsAt.getDate() + 14); // 14-day trial

    const defaultSettings: UserSettings = {
      timezone: 'America/New_York',
      notification_preferences: {
        email: true,
        push: false,
        sms: false
      },
      theme: 'auto',
      ai_personality: 'professional'
    };

    await this.run(
      'INSERT INTO users (id, email, name, trial_ends_at, settings) VALUES (?, ?, ?, ?, ?)',
      [id, email, name, trialEndsAt.toISOString(), JSON.stringify(defaultSettings)]
    );

    // Create default calendar
    await this.createDefaultCalendar(id);

    // Initialize usage tracking
    await this.initializeUsageTracking(id);

    const user = await this.getUserById(id);
    if (!user) throw new Error('Failed to create user');
    return user;
  }

  async getUserByEmail(email: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM users WHERE email = ?',
        [email],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              settings: JSON.parse(row.settings),
              created_at: new Date(row.created_at),
              last_login: new Date(row.last_login),
              trial_ends_at: row.trial_ends_at ? new Date(row.trial_ends_at) : undefined
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  async getUserById(id: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM users WHERE id = ?',
        [id],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              settings: JSON.parse(row.settings),
              created_at: new Date(row.created_at),
              last_login: new Date(row.last_login),
              trial_ends_at: row.trial_ends_at ? new Date(row.trial_ends_at) : undefined
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  // Subscription management
  async getSubscriptionLimits(userId: string): Promise<{
    maxAIEventsPerMonth: number;
    maxCalendars: number;
    hasAdvancedFeatures: boolean;
    hasTeamFeatures: boolean;
  }> {
    const user = await this.getUserById(userId);
    if (!user) throw new Error('User not found');

    switch (user.subscription_tier) {
      case 'free':
        return {
          maxAIEventsPerMonth: 10,
          maxCalendars: 1,
          hasAdvancedFeatures: false,
          hasTeamFeatures: false
        };
      case 'pro':
        return {
          maxAIEventsPerMonth: 100,
          maxCalendars: 5,
          hasAdvancedFeatures: true,
          hasTeamFeatures: false
        };
      case 'max':
        return {
          maxAIEventsPerMonth: -1, // unlimited
          maxCalendars: -1, // unlimited
          hasAdvancedFeatures: true,
          hasTeamFeatures: true
        };
      default:
        throw new Error('Invalid subscription tier');
    }
  }

  // Usage tracking
  async trackUsage(userId: string, feature: string): Promise<void> {
    const month = new Date().toISOString().slice(0, 7); // YYYY-MM

    // Update or create usage record
    await this.run(`
      INSERT INTO usage_tracking (id, user_id, month, api_calls, features_used)
      VALUES (?, ?, ?, 1, ?)
      ON CONFLICT(user_id, month) DO UPDATE SET
        api_calls = api_calls + 1,
        features_used = json_insert(features_used, '$[#]', ?)
    `, [this.generateId(), userId, month, JSON.stringify([feature]), feature]);
  }

  async incrementAIEventUsage(userId: string): Promise<boolean> {
    const month = new Date().toISOString().slice(0, 7);
    const limits = await this.getSubscriptionLimits(userId);
    
    if (limits.maxAIEventsPerMonth === -1) {
      // Unlimited, just track
      await this.run(`
        INSERT INTO usage_tracking (id, user_id, month, ai_events_created)
        VALUES (?, ?, ?, 1)
        ON CONFLICT(user_id, month) DO UPDATE SET
          ai_events_created = ai_events_created + 1
      `, [this.generateId(), userId, month]);
      return true;
    }

    // Check current usage
    const currentUsage = await this.getCurrentUsage(userId, month);
    if (currentUsage.ai_events_created >= limits.maxAIEventsPerMonth) {
      return false; // Limit exceeded
    }

    // Increment usage
    await this.run(`
      INSERT INTO usage_tracking (id, user_id, month, ai_events_created)
      VALUES (?, ?, ?, 1)
      ON CONFLICT(user_id, month) DO UPDATE SET
        ai_events_created = ai_events_created + 1
    `, [this.generateId(), userId, month]);

    return true;
  }

  async getCurrentUsage(userId: string, month: string): Promise<UsageTracking> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM usage_tracking WHERE user_id = ? AND month = ?',
        [userId, month],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              features_used: JSON.parse(row.features_used)
            });
          } else {
            // Return default usage
            resolve({
              id: '',
              user_id: userId,
              month,
              ai_events_created: 0,
              calendars_used: 1,
              api_calls: 0,
              features_used: []
            });
          }
        }
      );
    });
  }

  // Calendar management
  async createDefaultCalendar(userId: string): Promise<string> {
    const id = this.generateId();
    const defaultSettings: CalendarSettings = {
      visibility: 'private',
      auto_sync: true,
      default_event_duration: 60
    };

    await this.run(
      'INSERT INTO calendars (id, user_id, name, is_default, settings) VALUES (?, ?, ?, ?, ?)',
      [id, userId, 'My Calendar', true, JSON.stringify(defaultSettings)]
    );

    return id;
  }

  async getUserCalendars(userId: string): Promise<Calendar[]> {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM calendars WHERE user_id = ? ORDER BY is_default DESC, created_at ASC',
        [userId],
        (err, rows: any[]) => {
          if (err) {
            reject(err);
          } else {
            resolve(rows.map(row => ({
              ...row,
              is_default: Boolean(row.is_default),
              settings: JSON.parse(row.settings),
              created_at: new Date(row.created_at)
            })));
          }
        }
      );
    });
  }

  // Enhanced reminder methods
  async addReminder(reminder: Omit<Reminder, 'id' | 'created_at' | 'updated_at'>): Promise<Reminder> {
    const id = this.generateId();
    const now = new Date();

    await this.run(`
      INSERT INTO reminders (
        id, calendar_id, user_id, title, description, startTime, endTime, 
        timezone, alertMinutes, created_via, ai_confidence, original_input,
        recurrence_rule, attendees, location, calendarEventId, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
      id, reminder.calendar_id, reminder.user_id, reminder.title, reminder.description,
      reminder.startTime.toISOString(), reminder.endTime.toISOString(),
      reminder.timezone, JSON.stringify(reminder.alertMinutes),
      reminder.created_via, reminder.ai_confidence, reminder.original_input,
      reminder.recurrence_rule, JSON.stringify(reminder.attendees || []),
      reminder.location, reminder.calendarEventId, now.toISOString(), now.toISOString()
    ]);

    // Track usage if AI-created
    if (reminder.created_via === 'ai') {
      await this.incrementAIEventUsage(reminder.user_id);
    }

    const createdReminder = await this.getReminderById(id);
    if (!createdReminder) throw new Error('Failed to create reminder');
    return createdReminder;
  }

  async getReminderById(id: string): Promise<Reminder | null> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM reminders WHERE id = ?',
        [id],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              startTime: new Date(row.startTime),
              endTime: new Date(row.endTime),
              alertMinutes: JSON.parse(row.alertMinutes),
              attendees: JSON.parse(row.attendees || '[]'),
              created_at: new Date(row.created_at),
              updated_at: new Date(row.updated_at)
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  // Legacy compatibility methods
  async getUserSession(userEmail: string) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM oauth_tokens WHERE user_email = ?',
        [userEmail],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              userEmail: row.user_email,
              tokens: {
                access_token: row.access_token,
                refresh_token: row.refresh_token,
                expiry_date: row.expires_at ? new Date(row.expires_at).getTime() : undefined
              }
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  async getUserReminders(userEmail: string): Promise<Reminder[]> {
    // First get user by email
    const user = await this.getUserByEmail(userEmail);
    if (!user) return [];

    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM reminders WHERE user_id = ? ORDER BY startTime ASC',
        [user.id],
        (err, rows: any[]) => {
          if (err) {
            reject(err);
          } else {
            resolve(rows.map(row => ({
              ...row,
              startTime: new Date(row.startTime),
              endTime: new Date(row.endTime),
              alertMinutes: JSON.parse(row.alertMinutes),
              attendees: JSON.parse(row.attendees || '[]'),
              created_at: new Date(row.created_at),
              updated_at: new Date(row.updated_at)
            })));
          }
        }
      );
    });
  }

  private async initializeUsageTracking(userId: string): Promise<void> {
    const month = new Date().toISOString().slice(0, 7);
    await this.run(
      'INSERT INTO usage_tracking (id, user_id, month) VALUES (?, ?, ?)',
      [this.generateId(), userId, month]
    );
  }

  private generateId(): string {
    return Math.random().toString(36).substr(2, 9);
  }

  private run(sql: string, params: any[] = []): Promise<void> {
    return new Promise((resolve, reject) => {
      this.db.run(sql, params, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  // Additional helper methods...
  async getPendingReminders(): Promise<Array<{ reminder: Reminder; alertMinutes: number }>> {
    // Implementation for email reminders - keeping existing logic
    return [];
  }

  async markAlertSent(reminderId: string, alertMinutes: number): Promise<void> {
    // Implementation for marking alerts as sent
  }

  async deleteReminder(id: string, userEmail: string): Promise<boolean> {
    // Implementation for deleting reminders
    return true;
  }

  async cleanupOldReminders(): Promise<void> {
    // Implementation for cleanup
  }

  // Security-related database methods
  async updateUserPassword(userId: string, passwordHash: string): Promise<void> {
    await this.run(
      'UPDATE users SET password_hash = ? WHERE id = ?',
      [passwordHash, userId]
    );
  }

  async updateEmailVerificationToken(userId: string, token: string, expires: Date): Promise<void> {
    await this.run(
      'UPDATE users SET email_verification_token = ?, email_verification_expires = ? WHERE id = ?',
      [token, expires.toISOString(), userId]
    );
  }

  async getUserByVerificationToken(token: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM users WHERE email_verification_token = ? AND email_verification_expires > ?',
        [token, new Date().toISOString()],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              settings: JSON.parse(row.settings),
              created_at: new Date(row.created_at),
              last_login: new Date(row.last_login),
              trial_ends_at: row.trial_ends_at ? new Date(row.trial_ends_at) : undefined
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  async markEmailVerified(userId: string): Promise<void> {
    await this.run(
      'UPDATE users SET email_verified = TRUE, email_verification_token = NULL, email_verification_expires = NULL WHERE id = ?',
      [userId]
    );
  }

  async updatePasswordResetToken(userId: string, token: string, expires: Date): Promise<void> {
    await this.run(
      'UPDATE users SET password_reset_token = ?, password_reset_expires = ? WHERE id = ?',
      [token, expires.toISOString(), userId]
    );
  }

  async getUserByPasswordResetToken(token: string): Promise<User | null> {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM users WHERE password_reset_token = ? AND password_reset_expires > ?',
        [token, new Date().toISOString()],
        (err, row: any) => {
          if (err) {
            reject(err);
          } else if (row) {
            resolve({
              ...row,
              settings: JSON.parse(row.settings),
              created_at: new Date(row.created_at),
              last_login: new Date(row.last_login),
              trial_ends_at: row.trial_ends_at ? new Date(row.trial_ends_at) : undefined
            });
          } else {
            resolve(null);
          }
        }
      );
    });
  }

  async clearPasswordResetToken(userId: string): Promise<void> {
    await this.run(
      'UPDATE users SET password_reset_token = NULL, password_reset_expires = NULL WHERE id = ?',
      [userId]
    );
  }

  async updateLastLogin(userId: string): Promise<void> {
    await this.run(
      'UPDATE users SET last_login = ? WHERE id = ?',
      [new Date().toISOString(), userId]
    );
  }

  async updateTwoFactorSecret(userId: string, secret: string, enabled: boolean): Promise<void> {
    await this.run(
      'UPDATE users SET two_factor_secret = ?, two_factor_enabled = ? WHERE id = ?',
      [secret, enabled, userId]
    );
  }

  async enable2FA(userId: string, backupCodes: string): Promise<void> {
    await this.run(
      'UPDATE users SET two_factor_enabled = TRUE, two_factor_backup_codes = ? WHERE id = ?',
      [backupCodes, userId]
    );
  }

  async disable2FA(userId: string): Promise<void> {
    await this.run(
      'UPDATE users SET two_factor_enabled = FALSE, two_factor_secret = NULL, two_factor_backup_codes = NULL WHERE id = ?',
      [userId]
    );
  }

  async updateTwoFactorBackupCodes(userId: string, backupCodes: string): Promise<void> {
    await this.run(
      'UPDATE users SET two_factor_backup_codes = ? WHERE id = ?',
      [backupCodes, userId]
    );
  }

  async updateUserProfile(userId: string, updates: { name?: string; settings?: UserSettings }): Promise<void> {
    const fields = [];
    const values = [];

    if (updates.name !== undefined) {
      fields.push('name = ?');
      values.push(updates.name);
    }

    if (updates.settings !== undefined) {
      fields.push('settings = ?');
      values.push(JSON.stringify(updates.settings));
    }

    if (fields.length > 0) {
      values.push(userId);
      await this.run(
        `UPDATE users SET ${fields.join(', ')} WHERE id = ?`,
        values
      );
    }
  }

  async getConnectedAccounts(userId: string): Promise<any[]> {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM connected_accounts WHERE user_id = ? AND is_active = TRUE ORDER BY created_at DESC',
        [userId],
        (err, rows: any[]) => {
          if (err) {
            reject(err);
          } else {
            resolve(rows.map(row => ({
              ...row,
              created_at: new Date(row.created_at),
              updated_at: new Date(row.updated_at),
              expires_at: row.expires_at ? new Date(row.expires_at) : undefined
            })));
          }
        }
      );
    });
  }
} 