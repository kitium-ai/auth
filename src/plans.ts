/**
 * Default billing plans
 */

export const DEFAULT_PLANS = [
  {
    id: 'free',
    name: 'Free',
    description: 'Perfect for getting started',
    price: 0,
    features: ['Up to 100 users', 'Basic support', '2FA support'],
  },
  {
    id: 'pro',
    name: 'Pro',
    description: 'For growing teams',
    price: 2999,
    features: ['Up to 1000 users', 'Priority support', 'Advanced RBAC', 'SSO support'],
  },
  {
    id: 'enterprise',
    name: 'Enterprise',
    description: 'For large organizations',
    price: 9999,
    features: ['Unlimited users', '24/7 support', 'Custom integrations', 'On-premise option'],
  },
];
