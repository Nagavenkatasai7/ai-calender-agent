import Stripe from 'stripe';
import { Database, User } from './database';

export interface PricingTier {
  id: 'free' | 'pro' | 'max';
  name: string;
  price: number; // in cents
  description: string;
  features: string[];
  limits: {
    maxAIEventsPerMonth: number;
    maxCalendars: number;
    hasAdvancedFeatures: boolean;
    hasTeamFeatures: boolean;
  };
}

export class SubscriptionService {
  private stripe: Stripe;
  private database: Database;

  // Pricing configuration
  private readonly PRICING_TIERS: PricingTier[] = [
    {
      id: 'free',
      name: 'Free Tier',
      price: 0,
      description: 'Perfect for personal use',
      features: [
        'Up to 10 AI events per month',
        'Basic calendar view (month/week)',
        'Email reminders',
        'Manual event creation',
        'Single calendar',
        'Basic export (.ics)'
      ],
      limits: {
        maxAIEventsPerMonth: 10,
        maxCalendars: 1,
        hasAdvancedFeatures: false,
        hasTeamFeatures: false
      }
    },
    {
      id: 'pro',
      name: 'Pro Tier',
      price: 100, // $1.00
      description: 'Enhanced productivity features',
      features: [
        'Up to 100 AI events per month',
        'Advanced natural language processing',
        'Up to 5 calendars',
        'Smart scheduling suggestions',
        'SMS & push notifications',
        'Recurring events',
        'Calendar sharing',
        'Google Calendar & Outlook sync',
        'Priority email support'
      ],
      limits: {
        maxAIEventsPerMonth: 100,
        maxCalendars: 5,
        hasAdvancedFeatures: true,
        hasTeamFeatures: false
      }
    },
    {
      id: 'max',
      name: 'Max Tier',
      price: 300, // $3.00
      description: 'Unlimited power for teams',
      features: [
        'Unlimited AI events',
        'Advanced AI with context understanding',
        'Unlimited calendars',
        'Team calendar management',
        'Meeting room booking',
        'Slack, Teams, Zoom integration',
        'CRM integration',
        'Analytics & productivity insights',
        'Phone & chat support',
        'Custom AI training'
      ],
      limits: {
        maxAIEventsPerMonth: -1, // unlimited
        maxCalendars: -1, // unlimited
        hasAdvancedFeatures: true,
        hasTeamFeatures: true
      }
    }
  ];

  constructor(database: Database) {
    this.database = database;
    // Initialize Stripe with the secret key (the publishable key goes in the frontend)
    this.stripe = new Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_...', {
      apiVersion: '2025-05-28.basil'
    });
  }

  getPricingTiers(): PricingTier[] {
    return this.PRICING_TIERS;
  }

  getTierById(tierId: string): PricingTier | null {
    return this.PRICING_TIERS.find(tier => tier.id === tierId) || null;
  }

  async createCheckoutSession(userId: string, tierId: 'pro' | 'max'): Promise<string> {
    const tier = this.getTierById(tierId);
    if (!tier || tier.id === 'free') {
      throw new Error('Invalid tier for checkout');
    }

    const user = await this.database.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    try {
      const session = await this.stripe.checkout.sessions.create({
        payment_method_types: ['card'],
        customer_email: user.email,
        line_items: [
          {
            price_data: {
              currency: 'usd',
              product_data: {
                name: `AI Calendar ${tier.name}`,
                description: tier.description,
              },
              unit_amount: tier.price,
              recurring: {
                interval: 'month',
              },
            },
            quantity: 1,
          },
        ],
        mode: 'subscription',
        success_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/app?payment=success&plan=${tierId}`,
        cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/pricing?payment=cancel`,
        metadata: {
          userId: userId,
          tier: tierId,
        },
      });

      return session.url || '';
    } catch (error) {
      console.error('Error creating checkout session:', error);
      throw new Error('Failed to create checkout session');
    }
  }

  async handleWebhook(event: Stripe.Event): Promise<void> {
    switch (event.type) {
      case 'checkout.session.completed':
        await this.handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
        break;
      case 'invoice.payment_succeeded':
        await this.handlePaymentSucceeded(event.data.object as Stripe.Invoice);
        break;
      case 'customer.subscription.deleted':
        await this.handleSubscriptionCanceled(event.data.object as Stripe.Subscription);
        break;
      default:
        console.log(`Unhandled event type: ${event.type}`);
    }
  }

  private async handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
    const userId = session.metadata?.userId;
    const tier = session.metadata?.tier;

    if (!userId || !tier) {
      console.error('Missing metadata in checkout session');
      return;
    }

    // Update user subscription
    await this.updateUserSubscription(userId, tier as 'pro' | 'max', session.subscription as string);
  }

  private async handlePaymentSucceeded(invoice: Stripe.Invoice): Promise<void> {
    // Handle recurring payment success
    console.log('Payment succeeded for invoice:', invoice.id);
  }

  private async handleSubscriptionCanceled(subscription: Stripe.Subscription): Promise<void> {
    // Find user by subscription ID and downgrade to free
    const userId = subscription.metadata?.userId;
    if (userId) {
      await this.updateUserSubscription(userId, 'free');
    }
  }

  private async updateUserSubscription(userId: string, tier: 'free' | 'pro' | 'max', stripeSubscriptionId?: string): Promise<void> {
    console.log(`Updating user ${userId} to ${tier} tier`);
    
    try {
      await this.database.updateUserSubscription(userId, tier, 'active');
      console.log(`✅ User ${userId} successfully upgraded to ${tier} tier`);
    } catch (error) {
      console.error(`❌ Failed to update user subscription:`, error);
      throw error;
    }
  }

  async upgradeUserSubscription(userId: string, tier: 'pro' | 'max'): Promise<void> {
    await this.updateUserSubscription(userId, tier);
  }

  async getUserSubscriptionStatus(userId: string): Promise<{
    tier: 'free' | 'pro' | 'max';
    status: 'active' | 'trial' | 'canceled';
    currentUsage: {
      ai_events_created: number;
      calendars_used: number;
    };
    limits: PricingTier['limits'];
    daysUntilTrialEnd?: number;
    isTrialActive: boolean;
  }> {
    const user = await this.database.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const tier = this.getTierById(user.subscription_tier);
    if (!tier) {
      throw new Error('Invalid subscription tier');
    }

    // Get current month usage
    const currentMonth = new Date().toISOString().slice(0, 7);
    const usage = await this.database.getCurrentUsage(userId, currentMonth);

    let daysUntilTrialEnd: number | undefined;
    if (user.subscription_status === 'trial' && user.trial_ends_at) {
      const now = new Date();
      const trialEnd = new Date(user.trial_ends_at);
      daysUntilTrialEnd = Math.ceil((trialEnd.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
    }

    const isTrialActive = user.subscription_status === 'trial' && 
      !!user.trial_ends_at && new Date() < new Date(user.trial_ends_at);

    return {
      tier: user.subscription_tier,
      status: user.subscription_status,
      currentUsage: {
        ai_events_created: usage.ai_events_created,
        calendars_used: usage.calendars_used,
      },
      limits: tier.limits,
      daysUntilTrialEnd,
      isTrialActive: isTrialActive,
    };
  }

  async canUserCreateAIEvent(userId: string): Promise<{ allowed: boolean; reason?: string }> {
    const user = await this.database.getUserById(userId);
    if (!user) {
      return { allowed: false, reason: 'User not found' };
    }

    // Check if trial has expired
    if (user.subscription_status === 'trial' && user.trial_ends_at) {
      const now = new Date();
      const trialEnd = new Date(user.trial_ends_at);
      if (now > trialEnd) {
        return { allowed: false, reason: 'Trial period has ended. Please upgrade to continue using AI features.' };
      }
    }

    // Check subscription status
    if (user.subscription_status === 'canceled') {
      return { allowed: false, reason: 'Subscription canceled. Please renew to continue using AI features.' };
    }

    // Check usage limits
    const currentMonth = new Date().toISOString().slice(0, 7);
    const usage = await this.database.getCurrentUsage(userId, currentMonth);
    const limits = await this.database.getSubscriptionLimits(userId);

    if (limits.maxAIEventsPerMonth !== -1 && usage.ai_events_created >= limits.maxAIEventsPerMonth) {
      const tier = this.getTierById(user.subscription_tier);
      const nextTier = user.subscription_tier === 'free' ? 'pro' : 'max';
      return { 
        allowed: false, 
        reason: `You've reached your monthly limit of ${limits.maxAIEventsPerMonth} AI events. Upgrade to ${nextTier} tier for more.` 
      };
    }

    return { allowed: true };
  }

  async createUsageDashboard(userId: string): Promise<{
    currentTier: PricingTier;
    usage: {
      ai_events_created: number;
      calendars_used: number;
      percentage_used: number;
    };
    suggestions: string[];
    upgradeOptions: PricingTier[];
  }> {
    const user = await this.database.getUserById(userId);
    if (!user) {
      throw new Error('User not found');
    }

    const currentTier = this.getTierById(user.subscription_tier);
    if (!currentTier) {
      throw new Error('Invalid subscription tier');
    }

    const currentMonth = new Date().toISOString().slice(0, 7);
    const usage = await this.database.getCurrentUsage(userId, currentMonth);

    // Calculate usage percentage
    let percentage_used = 0;
    if (currentTier.limits.maxAIEventsPerMonth > 0) {
      percentage_used = (usage.ai_events_created / currentTier.limits.maxAIEventsPerMonth) * 100;
    }

    // Generate suggestions
    const suggestions: string[] = [];
    if (percentage_used > 80) {
      suggestions.push('You\'re using most of your AI events. Consider upgrading for unlimited access.');
    }
    if (usage.calendars_used >= currentTier.limits.maxCalendars) {
      suggestions.push('You\'ve reached your calendar limit. Upgrade to create more calendars.');
    }

    // Get upgrade options
    const upgradeOptions = this.PRICING_TIERS.filter(tier => 
      tier.id !== user.subscription_tier && tier.price > currentTier.price
    );

    return {
      currentTier,
      usage: {
        ai_events_created: usage.ai_events_created,
        calendars_used: usage.calendars_used,
        percentage_used: Math.round(percentage_used),
      },
      suggestions,
      upgradeOptions,
    };
  }
} 