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