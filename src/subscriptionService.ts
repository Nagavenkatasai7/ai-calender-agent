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
        'Up to 1,000 AI events per month',
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
        maxAIEventsPerMonth: 1000,
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
    console.log(`🔗 Processing Stripe webhook: ${event.type} - ${event.id}`);
    
    switch (event.type) {
      case 'checkout.session.completed':
        await this.handleCheckoutCompleted(event.data.object as Stripe.Checkout.Session);
        break;
      case 'invoice.payment_succeeded':
        await this.handlePaymentSucceeded(event.data.object as Stripe.Invoice);
        break;
      case 'customer.subscription.created':
        await this.handleSubscriptionCreated(event.data.object as Stripe.Subscription);
        break;
      case 'customer.subscription.updated':
        await this.handleSubscriptionUpdated(event.data.object as Stripe.Subscription);
        break;
      case 'customer.subscription.deleted':
        await this.handleSubscriptionCanceled(event.data.object as Stripe.Subscription);
        break;
      case 'invoice.payment_failed':
        await this.handlePaymentFailed(event.data.object as Stripe.Invoice);
        break;
      default:
        console.log(`ℹ️ Unhandled event type: ${event.type}`);
    }
  }

  private async handleCheckoutCompleted(session: Stripe.Checkout.Session): Promise<void> {
    console.log('🎉 Processing checkout completion:', session.id);
    
    const userId = session.metadata?.userId;
    const tier = session.metadata?.tier;

    if (!userId || !tier) {
      console.error('❌ Missing metadata in checkout session:', { 
        sessionId: session.id, 
        hasUserId: !!userId, 
        hasTier: !!tier,
        metadata: session.metadata 
      });
      return;
    }

    if (!['pro', 'max'].includes(tier)) {
      console.error('❌ Invalid tier in checkout session:', tier);
      return;
    }

    console.log(`💰 Payment successful! Processing upgrade for user ${userId} to ${tier} tier`);

    try {
      // Update user subscription
      await this.updateUserSubscription(userId, tier as 'pro' | 'max', session.subscription as string);
      console.log(`🎯 User ${userId} successfully upgraded to ${tier} - payment completed!`);
    } catch (error) {
      console.error('❌ Failed to process checkout completion:', error);
      throw error;
    }
  }

  private async handleSubscriptionCreated(subscription: Stripe.Subscription): Promise<void> {
    console.log(`🆕 NEW SUBSCRIPTION CREATED: ${subscription.id} - status: ${subscription.status}`);
    
    try {
      const customer = await this.stripe.customers.retrieve(subscription.customer as string);
      if (customer && !customer.deleted && customer.email) {
        console.log(`🔄 Auto-syncing new subscription for ${customer.email}...`);
        await this.syncUserSubscriptionWithStripe(customer.email);
        console.log(`✅ New subscription synced for ${customer.email}`);
      }
    } catch (error) {
      console.error('❌ Error handling subscription creation:', error);
    }
  }

  private async handleSubscriptionUpdated(subscription: Stripe.Subscription): Promise<void> {
    console.log(`🔄 SUBSCRIPTION UPDATED: ${subscription.id} - status: ${subscription.status}`);
    
    try {
      const customer = await this.stripe.customers.retrieve(subscription.customer as string);
      if (customer && !customer.deleted && customer.email) {
        console.log(`🔄 Auto-syncing updated subscription for ${customer.email}...`);
        
        if (['active', 'trialing', 'past_due'].includes(subscription.status)) {
          // Subscription is active/valid - sync to get the highest tier
          await this.syncUserSubscriptionWithStripe(customer.email);
          console.log(`✅ Subscription update synced for ${customer.email}`);
        } else if (['canceled', 'unpaid', 'incomplete_expired'].includes(subscription.status)) {
          // Subscription is no longer valid - check if user has other active subscriptions
          console.log(`⚠️ Subscription ${subscription.id} is ${subscription.status} - checking other subscriptions...`);
          const syncResult = await this.syncUserSubscriptionWithStripe(customer.email);
          
          if (!syncResult) {
            // No other active subscriptions found, downgrade to free
            const user = await this.database.getUserByEmail(customer.email);
            if (user) {
              await this.updateUserSubscription(user.id, 'free');
              console.log(`⬇️ Downgraded ${customer.email} to free - no active subscriptions`);
            }
          }
        }
      }
    } catch (error) {
      console.error('❌ Error handling subscription update:', error);
    }
  }

  private async handleSubscriptionCanceled(subscription: Stripe.Subscription): Promise<void> {
    console.log(`🚫 SUBSCRIPTION CANCELED: ${subscription.id}`);
    
    try {
      const customer = await this.stripe.customers.retrieve(subscription.customer as string);
      if (customer && !customer.deleted && customer.email) {
        console.log(`🔄 Checking remaining subscriptions for ${customer.email}...`);
        
        // Check if user has other active subscriptions
        const syncResult = await this.syncUserSubscriptionWithStripe(customer.email);
        
        if (!syncResult) {
          // No other active subscriptions found, downgrade to free
          const user = await this.database.getUserByEmail(customer.email);
          if (user) {
            await this.updateUserSubscription(user.id, 'free');
            console.log(`⬇️ Downgraded ${customer.email} to free - subscription canceled`);
          }
        }
      }
    } catch (error) {
      console.error('❌ Error handling subscription cancellation:', error);
    }
  }

  private async handlePaymentSucceeded(invoice: Stripe.Invoice): Promise<void> {
    console.log(`💳 PAYMENT SUCCEEDED: ${invoice.id} - amount: $${(invoice.amount_paid / 100).toFixed(2)}`);
    
    try {
      if (invoice.customer_email) {
        console.log(`✅ Payment successful for ${invoice.customer_email}`);
        
        // Sync to ensure user has access to their paid features
        await this.syncUserSubscriptionWithStripe(invoice.customer_email);
        console.log(`🎯 Payment confirmed and access granted for ${invoice.customer_email}`);
      }
    } catch (error) {
      console.error('❌ Error handling payment success:', error);
    }
  }

  private async handlePaymentFailed(invoice: Stripe.Invoice): Promise<void> {
    console.log(`💸 PAYMENT FAILED: ${invoice.id} - amount: $${(invoice.amount_due / 100).toFixed(2)}`);
    
    try {
      if (invoice.customer_email) {
        console.log(`⚠️ Payment failure for ${invoice.customer_email}`);
        
        // Check current subscription status after payment failure
        await this.syncUserSubscriptionWithStripe(invoice.customer_email);
        
        // Note: Stripe will handle retries and eventual cancellation
        // We just log the failure and sync current status
        console.log(`📋 Subscription status updated after payment failure for ${invoice.customer_email}`);
      }
    } catch (error) {
      console.error('❌ Error handling payment failure:', error);
    }
  }

  private async updateUserSubscription(userId: string, tier: 'free' | 'pro' | 'max', stripeSubscriptionId?: string): Promise<void> {
    console.log(`🔄 Updating user ${userId} to ${tier} tier`);
    
    try {
      // Get user info for logging
      const user = await this.database.getUserById(userId);
      if (!user) {
        throw new Error(`User ${userId} not found`);
      }

      const oldTier = user.subscription_tier;
      await this.database.updateUserSubscription(userId, tier, 'active');
      
      console.log(`✅ SUBSCRIPTION UPDATED: User ${user.email} upgraded from ${oldTier} to ${tier} tier`);
      console.log(`💳 Payment processed successfully - user now has access to ${tier} features`);
      
      // Log the specific features they now have access to
      const tierInfo = this.getTierById(tier);
      if (tierInfo) {
        console.log(`🎯 User ${user.email} now has access to:`);
        tierInfo.features.forEach(feature => {
          console.log(`   • ${feature}`);
        });
      }
    } catch (error) {
      console.error(`❌ Failed to update user subscription for ${userId}:`, error);
      throw error;
    }
  }

  async upgradeUserSubscription(userId: string, tier: 'pro' | 'max'): Promise<void> {
    await this.updateUserSubscription(userId, tier);
  }

  async cancelUserSubscription(userId: string): Promise<void> {
    await this.updateUserSubscription(userId, 'free', undefined);
  }

  async downgradeUserSubscription(userId: string, userEmail: string, targetTier: 'free' | 'pro'): Promise<{
    message: string;
    effectiveDate: string;
  }> {
    try {
      // Get current user data
      const user = await this.database.getUserById(userId);
      if (!user) {
        throw new Error('User not found');
      }

      const currentTier = user.subscription_tier;
      
      // Find the user's Stripe customer and subscription
      const customers = await this.stripe.customers.list({
        email: userEmail,
        limit: 1
      });

      if (customers.data.length === 0) {
        // No Stripe customer, just update locally
        await this.updateUserSubscription(userId, targetTier);
        return {
          message: `Successfully downgraded to ${targetTier} tier`,
          effectiveDate: 'immediate'
        };
      }

      const customer = customers.data[0];
      
      // Get active subscriptions
      const subscriptions = await this.stripe.subscriptions.list({
        customer: customer.id,
        status: 'active',
        limit: 10
      });

      const ourSubscriptions = subscriptions.data.filter(sub => {
        return sub.items.data.some(item => {
          const priceAmount = item.price.unit_amount || 0;
          return priceAmount >= 100 && priceAmount <= 300; // Our products: $1-$3
        });
      });

      if (targetTier === 'free') {
        // Cancel all active subscriptions for free tier
        for (const subscription of ourSubscriptions) {
          try {
            console.log(`🚫 Canceling subscription ${subscription.id} for downgrade to free`);
            await this.stripe.subscriptions.cancel(subscription.id);
          } catch (error) {
            console.error(`⚠️ Failed to cancel subscription ${subscription.id}:`, error);
          }
        }
        
        // Update database immediately
        await this.updateUserSubscription(userId, 'free');
        
        return {
          message: 'Successfully downgraded to free tier',
          effectiveDate: 'immediate'
        };
      } else if (targetTier === 'pro' && currentTier === 'max') {
        // Downgrade from max to pro
        const maxSubscriptions = ourSubscriptions.filter(sub => {
          return sub.items.data.some(item => (item.price.unit_amount || 0) >= 300);
        });

        if (maxSubscriptions.length > 0) {
          // Cancel max tier subscriptions
          for (const maxSub of maxSubscriptions) {
            try {
              console.log(`🚫 Canceling max subscription ${maxSub.id} for downgrade to pro`);
              await this.stripe.subscriptions.cancel(maxSub.id);
            } catch (error) {
              console.error(`⚠️ Failed to cancel max subscription:`, error);
            }
          }

          // Create new pro subscription
          const proPrice = process.env.STRIPE_PRO_PRICE_ID;
          if (proPrice) {
            try {
              console.log(`✨ Creating new pro subscription for ${userEmail}`);
              const newSubscription = await this.stripe.subscriptions.create({
                customer: customer.id,
                items: [{ price: proPrice }],
                metadata: {
                  userId: userId,
                  tier: 'pro',
                  downgraded_from: 'max'
                }
              });
              
              await this.updateUserSubscription(userId, 'pro', newSubscription.id);
              
              return {
                message: 'Successfully downgraded to pro tier',
                effectiveDate: 'immediate'
              };
            } catch (error) {
              console.error('⚠️ Failed to create pro subscription, updating locally:', error);
              await this.updateUserSubscription(userId, 'pro');
              return {
                message: 'Downgraded to pro tier (billing will be updated)',
                effectiveDate: 'immediate'
              };
            }
          }
        }
        
        // Fallback: just update locally
        await this.updateUserSubscription(userId, 'pro');
        return {
          message: 'Downgraded to pro tier',
          effectiveDate: 'immediate'
        };
      }

      throw new Error(`Invalid downgrade path: ${currentTier} to ${targetTier}`);
    } catch (error) {
      console.error(`❌ Error during downgrade:`, error);
      throw error;
    }
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

  async canUserCreateAIEvent(userId: string): Promise<{ 
    allowed: boolean; 
    reason?: string; 
    needsUpgrade?: boolean;
    currentTier?: string;
    recommendedTier?: string;
    upgradeMessage?: string;
  }> {
    const user = await this.database.getUserById(userId);
    if (!user) {
      return { allowed: false, reason: 'User not found' };
    }

    // Check if trial has expired
    if (user.subscription_status === 'trial' && user.trial_ends_at) {
      const now = new Date();
      const trialEnd = new Date(user.trial_ends_at);
      if (now > trialEnd) {
        return { 
          allowed: false, 
          reason: 'Trial period has ended. Please upgrade to continue using AI features.',
          needsUpgrade: true,
          currentTier: user.subscription_tier,
          recommendedTier: 'pro',
          upgradeMessage: 'Upgrade to Pro for 1,000 AI events per month at just $1/month!'
        };
      }
    }

    // Check subscription status
    if (user.subscription_status === 'canceled') {
      return { 
        allowed: false, 
        reason: 'Subscription canceled. Please renew to continue using AI features.',
        needsUpgrade: true,
        currentTier: user.subscription_tier,
        recommendedTier: user.subscription_tier === 'free' ? 'pro' : user.subscription_tier
      };
    }

    // Check usage limits
    const currentMonth = new Date().toISOString().slice(0, 7);
    const usage = await this.database.getCurrentUsage(userId, currentMonth);
    const limits = await this.database.getSubscriptionLimits(userId);

    if (limits.maxAIEventsPerMonth !== -1 && usage.ai_events_created >= limits.maxAIEventsPerMonth) {
      const currentTier = this.getTierById(user.subscription_tier);
      const nextTier = user.subscription_tier === 'free' ? 'pro' : 'max';
      const nextTierInfo = this.getTierById(nextTier);
      
      let upgradeMessage = '';
      if (nextTier === 'pro') {
        upgradeMessage = 'Upgrade to Pro for 1,000 AI events per month at just $1/month!';
      } else if (nextTier === 'max') {
        upgradeMessage = 'Upgrade to Max for unlimited AI events at just $3/month!';
      }

      return { 
        allowed: false, 
        reason: `You've reached your monthly limit of ${limits.maxAIEventsPerMonth.toLocaleString()} AI events. Upgrade to ${nextTier} tier for ${nextTierInfo?.limits.maxAIEventsPerMonth === -1 ? 'unlimited' : nextTierInfo?.limits.maxAIEventsPerMonth.toLocaleString()} events.`,
        needsUpgrade: true,
        currentTier: user.subscription_tier,
        recommendedTier: nextTier,
        upgradeMessage
      };
    }

    return { allowed: true };
  }

  // Check if user can access advanced natural language processing
  async canUseAdvancedNLP(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'Advanced natural language processing is only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can create multiple calendars
  async canCreateCalendar(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean; currentCount?: number; maxAllowed?: number }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    const currentCalendars = await this.database.getUserCalendarCount(userId);

    if (currentCalendars >= limits.maxCalendars) {
      return {
        allowed: false,
        reason: `You can only have ${limits.maxCalendars} calendar${limits.maxCalendars > 1 ? 's' : ''} on your current plan.`,
        needsUpgrade: limits.maxCalendars < 5,
        currentCount: currentCalendars,
        maxAllowed: limits.maxCalendars
      };
    }

    return { allowed: true, currentCount: currentCalendars, maxAllowed: limits.maxCalendars };
  }

  // Check if user can use smart scheduling
  async canUseSmartScheduling(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'Smart scheduling suggestions are only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can use SMS & push notifications
  async canUseSMSNotifications(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'SMS & push notifications are only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can create recurring events
  async canCreateRecurringEvents(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'Recurring events are only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can share calendars
  async canShareCalendars(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'Calendar sharing is only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can sync with external calendars
  async canSyncExternalCalendars(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasAdvancedFeatures) {
      return {
        allowed: false,
        reason: 'Google Calendar & Outlook sync is only available for Pro and Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Check if user can access team features
  async canUseTeamFeatures(userId: string): Promise<{ allowed: boolean; reason?: string; needsUpgrade?: boolean }> {
    const user = await this.database.getUserById(userId);
    if (!user) return { allowed: false, reason: 'User not found' };

    const limits = await this.database.getSubscriptionLimits(userId);
    if (!limits.hasTeamFeatures) {
      return {
        allowed: false,
        reason: 'Team collaboration features are only available for Max subscribers.',
        needsUpgrade: true
      };
    }

    return { allowed: true };
  }

  // Get user's feature summary
  async getUserFeatureSummary(userId: string) {
    const user = await this.database.getUserById(userId);
    if (!user) return null;

    const limits = await this.database.getSubscriptionLimits(userId);
    const currentMonth = new Date().toISOString().slice(0, 7);
    const usage = await this.database.getCurrentUsage(userId, currentMonth);
    const calendarCount = await this.database.getUserCalendarCount(userId);

    return {
      subscription: {
        tier: user.subscription_tier,
        status: user.subscription_status,
        trialEndsAt: user.trial_ends_at
      },
      limits,
      usage: {
        aiEventsCreated: usage.ai_events_created,
        calendarsCreated: calendarCount
      },
      features: {
        advancedNLP: limits.hasAdvancedFeatures,
        smartScheduling: limits.hasAdvancedFeatures,
        smsNotifications: limits.hasAdvancedFeatures,
        recurringEvents: limits.hasAdvancedFeatures,
        calendarSharing: limits.hasAdvancedFeatures,
        externalSync: limits.hasAdvancedFeatures,
        teamFeatures: limits.hasTeamFeatures
      }
    };
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

  // ENHANCED: Direct Stripe subscription sync with highest tier selection
  async syncUserSubscriptionWithStripe(userEmail: string): Promise<boolean> {
    console.log(`🔄 Syncing subscription for ${userEmail} with Stripe...`);
    
    try {
      // Find customer in Stripe by email
      const customers = await this.stripe.customers.list({
        email: userEmail,
        limit: 1
      });

      if (customers.data.length === 0) {
        console.log(`⚠️ No Stripe customer found for ${userEmail} - keeping current status`);
        return false;
      }

      const customer = customers.data[0];
      console.log(`👤 Found Stripe customer: ${customer.id} for ${userEmail}`);

      // Get ALL subscriptions for this customer (active, trialing, past_due)
      const subscriptions = await this.stripe.subscriptions.list({
        customer: customer.id,
        status: 'all',
        limit: 20
      });

      console.log(`📋 Found ${subscriptions.data.length} total subscriptions for ${userEmail}`);

      // Filter to only active/valid subscriptions from our product
      const ourSubscriptions = subscriptions.data.filter(sub => {
        // Only consider active, trialing, or past_due subscriptions
        if (!['active', 'trialing', 'past_due'].includes(sub.status)) {
          return false;
        }
        
        // Check if this is one of our product subscriptions by price
        return sub.items.data.some(item => {
          const priceAmount = item.price.unit_amount || 0;
          // Our pricing: $1.00 (100 cents) for Pro, $3.00 (300 cents) for Max
          return priceAmount >= 100 && priceAmount <= 300;
        });
      });

      console.log(`✅ Found ${ourSubscriptions.length} valid subscriptions from our products`);

      if (ourSubscriptions.length === 0) {
        console.log(`⚠️ No active subscriptions found for ${userEmail} in Stripe`);
        
        // Check if user should be downgraded to free
        const user = await this.database.getUserByEmail(userEmail);
        if (user && user.subscription_tier !== 'free') {
          console.log(`⬇️ Downgrading ${userEmail} to free tier - no active Stripe subscription`);
          await this.updateUserSubscription(user.id, 'free');
        }
        return false;
      }

      // Find the HIGHEST TIER subscription (highest price = best tier)
      let highestTierSubscription = ourSubscriptions[0];
      let highestPrice = 0;
      let highestTier: 'pro' | 'max' = 'pro';

      for (const sub of ourSubscriptions) {
        const priceAmount = sub.items.data[0]?.price.unit_amount || 0;
        
        if (priceAmount > highestPrice) {
          highestPrice = priceAmount;
          highestTierSubscription = sub;
          
          // Determine tier based on price
          if (priceAmount >= 300) { // $3.00 or more = max
            highestTier = 'max';
          } else if (priceAmount >= 100) { // $1.00 = pro
            highestTier = 'pro';
          }
        }
      }

      console.log(`🎯 HIGHEST TIER SUBSCRIPTION SELECTED:`);
      console.log(`   Subscription ID: ${highestTierSubscription.id}`);
      console.log(`   Price: $${(highestPrice / 100).toFixed(2)}/month`);
      console.log(`   Tier: ${highestTier.toUpperCase()}`);
      console.log(`   Status: ${highestTierSubscription.status}`);

      // Cancel any lower-tier subscriptions to avoid double billing
      for (const sub of ourSubscriptions) {
        if (sub.id !== highestTierSubscription.id && sub.status === 'active') {
          try {
            console.log(`🚫 Canceling lower-tier subscription: ${sub.id}`);
            await this.stripe.subscriptions.cancel(sub.id);
          } catch (error) {
            console.error(`⚠️ Failed to cancel subscription ${sub.id}:`, error);
          }
        }
      }

      // Update user subscription in database
      const user = await this.database.getUserByEmail(userEmail);
      if (user) {
        const oldTier = user.subscription_tier;
        await this.updateUserSubscription(user.id, highestTier, highestTierSubscription.id);
        
        if (oldTier !== highestTier) {
          console.log(`🚀 UPGRADED: ${userEmail} from ${oldTier} to ${highestTier} tier!`);
        } else {
          console.log(`✅ Confirmed: ${userEmail} maintains ${highestTier} tier`);
        }
        return true;
      } else {
        console.error(`❌ User ${userEmail} not found in database`);
        return false;
      }
    } catch (error) {
      console.error(`❌ Error syncing subscription for ${userEmail}:`, error);
      return false;
    }
  }

  // Manual subscription sync for all users
  async syncAllSubscriptionsWithStripe(): Promise<void> {
    console.log('🔄 Starting manual sync of all subscriptions with Stripe...');
    
    try {
      // Get all customers from Stripe with active subscriptions
      const subscriptions = await this.stripe.subscriptions.list({
        status: 'active',
        limit: 100
      });

      console.log(`📊 Found ${subscriptions.data.length} active subscriptions in Stripe`);

      for (const subscription of subscriptions.data) {
        try {
          const customer = await this.stripe.customers.retrieve(subscription.customer as string);
          
          if (customer && !customer.deleted && customer.email) {
            console.log(`🔄 Syncing ${customer.email}...`);
            await this.syncUserSubscriptionWithStripe(customer.email);
          }
        } catch (error) {
          console.error(`❌ Error syncing subscription ${subscription.id}:`, error);
        }
      }

      console.log('✅ Manual sync completed!');
    } catch (error) {
      console.error('❌ Error during manual sync:', error);
    }
  }
} 