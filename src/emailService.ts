import nodemailer from 'nodemailer';

export interface ReminderEmail {
  to: string;
  eventDetails: {
    title: string;
    description: string;
    startTime: Date;
  };
  minutesBefore: number;
}

export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor() {
    this.transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS, // Use app password for Gmail
      },
    });

    // Log email configuration status
    if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
      console.error('⚠️  Email service not configured. Please set EMAIL_USER and EMAIL_PASS in your .env file.');
      console.error('📧 For Gmail, you need:');
      console.error('   1. Enable 2-factor authentication on your Google account');
      console.error('   2. Generate an App Password at: https://myaccount.google.com/apppasswords');
      console.error('   3. Use that App Password (not your regular password) as EMAIL_PASS');
    }
  }

  async sendReminder(reminderEmail: ReminderEmail) {
    const { to, eventDetails, minutesBefore } = reminderEmail;
    
    const timeText = this.getTimeText(minutesBefore);
    const eventTime = eventDetails.startTime.toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short'
    });

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: to,
      subject: `⏰ Reminder: ${eventDetails.title} ${timeText}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
          <div style="background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #4285f4; margin: 0; font-size: 28px;">🔔 Event Reminder</h1>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
              <h2 style="color: #333; margin: 0 0 15px 0; font-size: 24px;">${eventDetails.title}</h2>
              <p style="color: #666; font-size: 16px; margin: 0 0 10px 0;"><strong>📅 When:</strong> ${eventTime}</p>
              <p style="color: #666; font-size: 16px; margin: 0;"><strong>📝 Details:</strong> ${eventDetails.description}</p>
            </div>
            
            <div style="background-color: #e8f0fe; padding: 15px; border-radius: 8px; border-left: 4px solid #4285f4;">
              <p style="margin: 0; color: #1a73e8; font-weight: bold; font-size: 16px;">
                ⏰ This event is starting ${timeText}!
              </p>
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
              <p style="color: #888; font-size: 14px; margin: 0;">
                This reminder was sent by your AI Reminder Agent
              </p>
            </div>
          </div>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Reminder email sent successfully to ${to} for event: ${eventDetails.title}`);
      return true;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }

  async testConnection(): Promise<boolean> {
    try {
      await this.transporter.verify();
      console.log('Email service connection verified');
      return true;
    } catch (error) {
      console.error('Email service connection failed:', error);
      return false;
    }
  }

  async sendVerificationEmail(email: string, name: string, token: string): Promise<void> {
    const verificationUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/api/auth/verify-email/${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: '✅ Verify Your AI Reminder Account',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
          <div style="background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #4285f4; margin: 0; font-size: 28px;">🤖 Welcome to AI Reminder</h1>
            </div>
            
            <div style="margin-bottom: 30px;">
              <h2 style="color: #333; margin: 0 0 15px 0;">Hi ${name}!</h2>
              <p style="color: #666; font-size: 16px; line-height: 1.6;">
                Thank you for signing up for AI Reminder! To complete your account setup and start using our intelligent calendar assistant, please verify your email address.
              </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${verificationUrl}" style="background-color: #4285f4; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: bold; display: inline-block;">
                Verify Email Address
              </a>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p style="color: #666; font-size: 14px; margin: 0; text-align: center;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <span style="word-break: break-all; color: #4285f4;">${verificationUrl}</span>
              </p>
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
              <p style="color: #888; font-size: 12px; margin: 0;">
                This verification link expires in 24 hours. If you didn't create an account, you can safely ignore this email.
              </p>
            </div>
          </div>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Verification email sent to ${email}`);
    } catch (error) {
      console.error('Error sending verification email:', error);
      throw error;
    }
  }

  async sendPasswordResetEmail(email: string, name: string, token: string): Promise<void> {
    const resetUrl = `${process.env.BASE_URL || 'http://localhost:3000'}/reset-password?token=${token}`;
    
    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: '🔒 Reset Your AI Reminder Password',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
          <div style="background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #dc3545; margin: 0; font-size: 28px;">🔒 Password Reset</h1>
            </div>
            
            <div style="margin-bottom: 30px;">
              <h2 style="color: #333; margin: 0 0 15px 0;">Hi ${name}!</h2>
              <p style="color: #666; font-size: 16px; line-height: 1.6;">
                We received a request to reset your password for your AI Reminder account. If you didn't make this request, you can safely ignore this email.
              </p>
            </div>
            
            <div style="text-align: center; margin: 30px 0;">
              <a href="${resetUrl}" style="background-color: #dc3545; color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-size: 16px; font-weight: bold; display: inline-block;">
                Reset Password
              </a>
            </div>
            
            <div style="background-color: #fff3cd; padding: 20px; border-radius: 8px; border-left: 4px solid #ffc107; margin: 20px 0;">
              <p style="color: #856404; font-size: 14px; margin: 0;">
                <strong>Security Note:</strong> This reset link expires in 1 hour for your security. If you didn't request this reset, please secure your account immediately.
              </p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
              <p style="color: #666; font-size: 14px; margin: 0; text-align: center;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <span style="word-break: break-all; color: #dc3545;">${resetUrl}</span>
              </p>
            </div>
          </div>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Password reset email sent to ${email}`);
    } catch (error) {
      console.error('Error sending password reset email:', error);
      throw error;
    }
  }

  async sendReminderEmail(email: string, name: string, title: string, description: string, startTime: Date, minutesBefore: number): Promise<void> {
    const timeText = this.getTimeText(minutesBefore);
    const eventTime = startTime.toLocaleString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: 'numeric',
      minute: '2-digit',
      timeZoneName: 'short'
    });

    const mailOptions = {
      from: process.env.EMAIL_FROM || process.env.EMAIL_USER,
      to: email,
      subject: `⏰ Reminder: ${title} ${timeText}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; background-color: #f9f9f9;">
          <div style="background-color: #fff; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
            <div style="text-align: center; margin-bottom: 30px;">
              <h1 style="color: #4285f4; margin: 0; font-size: 28px;">🔔 Event Reminder</h1>
            </div>
            
            <div style="margin-bottom: 20px;">
              <h2 style="color: #333; margin: 0 0 10px 0;">Hi ${name}!</h2>
              <p style="color: #666; font-size: 16px;">This is a friendly reminder about your upcoming event.</p>
            </div>
            
            <div style="background-color: #f8f9fa; padding: 20px; border-radius: 8px; margin-bottom: 20px;">
              <h2 style="color: #333; margin: 0 0 15px 0; font-size: 24px;">${title}</h2>
              <p style="color: #666; font-size: 16px; margin: 0 0 10px 0;"><strong>📅 When:</strong> ${eventTime}</p>
              <p style="color: #666; font-size: 16px; margin: 0;"><strong>📝 Details:</strong> ${description}</p>
            </div>
            
            <div style="background-color: #e8f0fe; padding: 15px; border-radius: 8px; border-left: 4px solid #4285f4;">
              <p style="margin: 0; color: #1a73e8; font-weight: bold; font-size: 16px;">
                ⏰ This event is starting ${timeText}!
              </p>
            </div>
            
            <div style="margin-top: 30px; text-align: center;">
              <p style="color: #888; font-size: 14px; margin: 0;">
                This reminder was sent by your AI Reminder Agent
              </p>
            </div>
          </div>
        </div>
      `,
    };

    try {
      await this.transporter.sendMail(mailOptions);
      console.log(`Reminder email sent to ${email} for event: ${title}`);
    } catch (error) {
      console.error('Error sending reminder email:', error);
      throw error;
    }
  }

  private getTimeText(minutesBefore: number): string {
    if (minutesBefore < 60) {
      return `in ${minutesBefore} minute${minutesBefore !== 1 ? 's' : ''}`;
    } else if (minutesBefore === 60) {
      return 'in 1 hour';
    } else if (minutesBefore < 1440) {
      const hours = Math.floor(minutesBefore / 60);
      const remainingMinutes = minutesBefore % 60;
      if (remainingMinutes === 0) {
        return `in ${hours} hour${hours !== 1 ? 's' : ''}`;
      } else {
        return `in ${hours} hour${hours !== 1 ? 's' : ''} and ${remainingMinutes} minute${remainingMinutes !== 1 ? 's' : ''}`;
      }
    } else {
      const days = Math.floor(minutesBefore / 1440);
      return `in ${days} day${days !== 1 ? 's' : ''}`;
    }
  }
} 