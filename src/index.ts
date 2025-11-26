// Kitium Auth - Complete authentication solution with lazy loading and plugin system

// Core authentication engine (always loaded)
export { AuthCore } from './core';

// Configuration system (always loaded)
export {
  defineConfig,
  createProvider,
  createOAuthProvider,
  createEmailProvider,
  createStorageConfig,
  createBillingConfig,
  createApiKeyConfig,
  createSessionConfig,
  createOrganizationConfig,
  createEventConfig,
  validateConfig,
  getEnvVar,
  getEnvVarAsNumber,
  getEnvVarAsBoolean,
} from './config';

// Types (always loaded)
export type {
  // Core types
  Scope,
  Principal,
  IssueApiKeyInput,
  IssueApiKeyResult,
  VerifyApiKeyResult,
  Session,
  Entitlement,
  Plan,
  Organization,
  AuthEvent,
  RateLimit,

  // Configuration types
  AuthConfig,
  AuthProvider,
  StorageConfig,
  BillingConfig,
  BillingProduct,
  ApiKeyConfig,
  SessionConfig,
  OrganizationConfig,
  EventConfig,

  // Adapter interfaces
  StorageAdapter,
  BillingAdapter,
  CacheAdapter,

  // Database record types
  ApiKeyRecord,
  SessionRecord,
  OrganizationRecord,

  // Billing types
  Customer,
  CustomerData,
  Subscription,
  SubscriptionData,
  WebhookEvent,

  // OAuth types
  OAuthCallbackResult,
  OAuthProfile,
  OAuthTokenResponse,

  // User types
  User,
  UserRecord,
  OAuthLink,
  CreateUserInput,
  UpdateUserInput,
} from './types';

// Plugin system (always loaded)
export { KitiumPluginManager } from './plugins/manager';
export type { Plugin, PluginManager, PluginContext } from './plugins/types';

// Lazy loading system (always loaded)
export { lazyLoader, lazy, lazyImport, loadIfAvailable } from './lazy';

// Utility functions (always loaded)
export { generateApiKey, hashApiKey, verifyApiKey } from './utils';
export {
  hashPassword,
  verifyPassword,
  validatePasswordStrength,
  generatePasswordResetToken,
  validateEmail,
  normalizeEmail,
} from './password';
export type { PasswordHashOptions, PasswordValidationRules } from './password';

// OAuth utilities (always loaded)
export { OAuthManager, PKCEGenerator } from './oauth';
export type {
  OAuthState,
  OAuthAuthorizationRequest,
  OAuthTokenResponse as OAuthTokenResponseType,
} from './oauth';

// Pre-configured OAuth providers (always loaded)
export {
  createOAuthProviderFromPreset,
  getAvailableOAuthProviders,
  hasOAuthProviderPreset,
  GOOGLE_PROVIDER,
  GITHUB_PROVIDER,
  MICROSOFT_PROVIDER,
  FACEBOOK_PROVIDER,
  APPLE_PROVIDER,
  TWITTER_PROVIDER,
  DISCORD_PROVIDER,
  LINKEDIN_PROVIDER,
  OAUTH_PROVIDER_PRESETS,
} from './providers/oauth-presets';
export type { OAuthProviderPreset } from './providers/oauth-presets';

// Error handling (always loaded)
// Re-exports from @kitiumai/error with auth-specific wrappers
export {
  AuthError,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  ConflictError,
  RateLimitError,
  OAuthError,
  ProviderNotFoundError,
  TokenError,
  SessionError,
  ApiKeyError,
  DatabaseError,
  ConfigurationError,
  IntegrationError,
  InternalError,
  isAuthError,
  toAuthError,
  getStatusCode,
  formatErrorResponse,
} from './errors';

// Also export KitiumError utilities for direct use
export {
  KitiumError,
  toKitiumError,
  problemDetailsFrom,
  logError,
  enrichError,
  getErrorFingerprint,
  getErrorMetrics,
} from '@kitiumai/error';

// Error middleware (lazy loaded)
export const getErrorHandler = (): Promise<
  typeof import('./frameworks/error-handler').errorHandler
> => import('./frameworks/error-handler').then((m) => m.errorHandler);
export const getAsyncHandler = (): Promise<
  typeof import('./frameworks/error-handler').asyncHandler
> => import('./frameworks/error-handler').then((m) => m.asyncHandler);
export const getErrorMiddleware = (): Promise<
  typeof import('./frameworks/error-handler').setupErrorHandling
> => import('./frameworks/error-handler').then((m) => m.setupErrorHandling);

// Rate limiting (lazy loaded)
export const getRateLimiter = (): Promise<{
  // eslint-disable-next-line @typescript-eslint/naming-convention
  RateLimiter: typeof import('./frameworks/rate-limiter').RateLimiter;
  generateRateLimitKey: typeof import('./frameworks/rate-limiter').generateRateLimitKey;
  generateRateLimitHeaders: typeof import('./frameworks/rate-limiter').generateRateLimitHeaders;
}> =>
  import('./frameworks/rate-limiter').then((m) => ({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    RateLimiter: m.RateLimiter,
    generateRateLimitKey: m.generateRateLimitKey,
    generateRateLimitHeaders: m.generateRateLimitHeaders,
  }));
export const getRateLimitMiddleware = (): Promise<{
  createRateLimitMiddleware: typeof import('./frameworks/rate-limit-middleware').createRateLimitMiddleware;
  createPublicRateLimitMiddleware: typeof import('./frameworks/rate-limit-middleware').createPublicRateLimitMiddleware;
  createPerPrincipalRateLimitMiddleware: typeof import('./frameworks/rate-limit-middleware').createPerPrincipalRateLimitMiddleware;
  createEndpointRateLimitMiddleware: typeof import('./frameworks/rate-limit-middleware').createEndpointRateLimitMiddleware;
}> =>
  import('./frameworks/rate-limit-middleware').then((m) => ({
    createRateLimitMiddleware: m.createRateLimitMiddleware,
    createPublicRateLimitMiddleware: m.createPublicRateLimitMiddleware,
    createPerPrincipalRateLimitMiddleware: m.createPerPrincipalRateLimitMiddleware,
    createEndpointRateLimitMiddleware: m.createEndpointRateLimitMiddleware,
  }));

// Email authentication (lazy loaded)
export const getEmailAuthService = (): Promise<typeof import('./email/service').EmailAuthService> =>
  import('./email/service').then((m) => m.EmailAuthService);
export const getEmailRoutes = (): Promise<typeof import('./email/routes').createEmailRoutes> =>
  import('./email/routes').then((m) => m.createEmailRoutes);
export const getEmailVerificationManager = (): Promise<{
  // eslint-disable-next-line @typescript-eslint/naming-convention
  EmailVerificationManager: typeof import('./email/verification').EmailVerificationManager;
  generateVerificationLink: typeof import('./email/verification').generateVerificationLink;
  generateResetLink: typeof import('./email/verification').generateResetLink;
  generateLoginLink: typeof import('./email/verification').generateLoginLink;
}> =>
  import('./email/verification').then((m) => ({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    EmailVerificationManager: m.EmailVerificationManager,
    generateVerificationLink: m.generateVerificationLink,
    generateResetLink: m.generateResetLink,
    generateLoginLink: m.generateLoginLink,
  }));
export const getEmailProviders = (): Promise<{
  createEmailProvider: typeof import('./email/providers').createEmailProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  SMTPEmailProvider: typeof import('./email/providers').SMTPEmailProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  SendGridEmailProvider: typeof import('./email/providers').SendGridEmailProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  MailgunEmailProvider: typeof import('./email/providers').MailgunEmailProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  ResendEmailProvider: typeof import('./email/providers').ResendEmailProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  MockEmailProvider: typeof import('./email/providers').MockEmailProvider;
}> =>
  import('./email/providers').then((m) => ({
    createEmailProvider: m.createEmailProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    SMTPEmailProvider: m.SMTPEmailProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    SendGridEmailProvider: m.SendGridEmailProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    MailgunEmailProvider: m.MailgunEmailProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ResendEmailProvider: m.ResendEmailProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    MockEmailProvider: m.MockEmailProvider,
  }));
export const getEmailTemplates = (): Promise<{
  createPasswordResetTemplate: typeof import('./email/templates').createPasswordResetTemplate;
  createEmailVerificationTemplate: typeof import('./email/templates').createEmailVerificationTemplate;
  createVerificationCodeTemplate: typeof import('./email/templates').createVerificationCodeTemplate;
  createLoginLinkTemplate: typeof import('./email/templates').createLoginLinkTemplate;
  createWelcomeTemplate: typeof import('./email/templates').createWelcomeTemplate;
}> =>
  import('./email/templates').then((m) => ({
    createPasswordResetTemplate: m.createPasswordResetTemplate,
    createEmailVerificationTemplate: m.createEmailVerificationTemplate,
    createVerificationCodeTemplate: m.createVerificationCodeTemplate,
    createLoginLinkTemplate: m.createLoginLinkTemplate,
    createWelcomeTemplate: m.createWelcomeTemplate,
  }));

// Two-Factor Authentication (lazy loaded)
export const getTwoFactorAuthService = (): Promise<
  typeof import('./twofa/service').TwoFactorAuthService
> => import('./twofa/service').then((m) => m.TwoFactorAuthService);
export const getSMSProviders = (): Promise<{
  // eslint-disable-next-line @typescript-eslint/naming-convention
  ConsoleSMSProvider: typeof import('./twofa/sms-provider').ConsoleSMSProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  TwilioSMSProvider: typeof import('./twofa/sms-provider').TwilioSMSProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  AWSSNSSMSProvider: typeof import('./twofa/sms-provider').AWSSNSSMSProvider;
  // eslint-disable-next-line @typescript-eslint/naming-convention
  CustomSMSProvider: typeof import('./twofa/sms-provider').CustomSMSProvider;
}> =>
  import('./twofa/sms-provider').then((m) => ({
    // eslint-disable-next-line @typescript-eslint/naming-convention
    ConsoleSMSProvider: m.ConsoleSMSProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    TwilioSMSProvider: m.TwilioSMSProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    AWSSNSSMSProvider: m.AWSSNSSMSProvider,
    // eslint-disable-next-line @typescript-eslint/naming-convention
    CustomSMSProvider: m.CustomSMSProvider,
  }));

// WebAuthn/FIDO2 (lazy loaded)
export const getWebAuthnService = (): Promise<
  typeof import('./webauthn/service').WebAuthnService
> => import('./webauthn/service').then((m) => m.WebAuthnService);
// WebAuthn types (always loaded)
export type {
  WebAuthnDevice,
  WebAuthnConfig,
  WebAuthnRegistrationOptions,
  WebAuthnAuthenticationOptions,
  WebAuthnCredentialCreation,
  WebAuthnCredentialAssertion,
} from './webauthn/types';

// Hooks/Events System (always loaded)
export { createHookManager, HookManagerImpl } from './hooks/manager';
export type {
  HookManager,
  HookEventType,
  HookContext,
  HookHandler,
  HookRegistration,
  UserHookData,
  SessionHookData,
  ApiKeyHookData,
  OrganizationHookData,
  AuthHookData,
} from './hooks/types';

// Security Features (lazy loaded)
export const getAnomalyDetectionService = (): Promise<
  typeof import('./security/anomaly-detection').AnomalyDetectionService
> => import('./security/anomaly-detection').then((m) => m.AnomalyDetectionService);
export const getConditionalAccessService = (): Promise<
  typeof import('./security/conditional-access').ConditionalAccessService
> => import('./security/conditional-access').then((m) => m.ConditionalAccessService);
export const getDeviceManagementService = (): Promise<
  typeof import('./security/device-management').DeviceManagementService
> => import('./security/device-management').then((m) => m.DeviceManagementService);
// Security types (always loaded)
export type {
  AnomalyDetectionConfig,
  RiskScore,
  RiskFactors,
  AuthAttempt,
} from './security/anomaly-detection';
export type {
  ConditionalAccessPolicy,
  ConditionalAccessPolicyType,
  LocationPolicy,
  DevicePolicy,
  TimePolicy,
  IpRangePolicy,
  MfaRequiredPolicy,
  RiskLevelPolicy,
  PolicyEvaluationContext,
  PolicyEvaluationResult,
} from './security/conditional-access';
export type {
  Device,
  DeviceType,
  DeviceTrustLevel,
  DeviceRegistrationRequest,
} from './security/device-management';

// Governance types (always loaded)
export type {
  AccessReview,
  AccessReviewCampaign,
  AccessReviewStatus,
  AccessReviewType,
} from './governance/access-reviews';

// Governance Features (lazy loaded)
export const getAccessReviewService = (): Promise<
  typeof import('./governance/access-reviews').AccessReviewService
> => import('./governance/access-reviews').then((m) => m.AccessReviewService);

// SAML authentication (lazy loaded)
export const getSAMLAuthService = (): Promise<typeof import('./saml/service').SAMLAuthService> =>
  import('./saml/service').then((m) => m.SAMLAuthService);
export const getSAMLRoutes = (): Promise<{
  createSAMLRoutes: typeof import('./saml/routes').createSAMLRoutes;
  extractTenantIdMiddleware: typeof import('./saml/routes').extractTenantIdMiddleware;
}> =>
  import('./saml/routes').then((m) => ({
    createSAMLRoutes: m.createSAMLRoutes,
    extractTenantIdMiddleware: m.extractTenantIdMiddleware,
  }));
export const getSAMLUtils = (): Promise<{
  generateSAMLAuthRequest: typeof import('./saml/utils').generateSAMLAuthRequest;
  parseSAMLResponse: typeof import('./saml/utils').parseSAMLResponse;
  extractUserProfile: typeof import('./saml/utils').extractUserProfile;
  generateSPMetadata: typeof import('./saml/utils').generateSPMetadata;
  validateSignature: typeof import('./saml/utils').validateSignature;
}> =>
  import('./saml/utils').then((m) => ({
    generateSAMLAuthRequest: m.generateSAMLAuthRequest,
    parseSAMLResponse: m.parseSAMLResponse,
    extractUserProfile: m.extractUserProfile,
    generateSPMetadata: m.generateSPMetadata,
    validateSignature: m.validateSignature,
  }));

// HTTP Service (lazy loaded)
export const getHttpService = (): Promise<
  typeof import('./service/http-service').HttpAuthService
> => import('./service/http-service').then((m) => m.HttpAuthService);
export const getStartAuthService = (): Promise<
  typeof import('./service/http-service').startAuthService
> => import('./service/http-service').then((m) => m.startAuthService);
export const getApiRoutes = (): Promise<typeof import('./service/api-routes').createApiRoutes> =>
  import('./service/api-routes').then((m) => m.createApiRoutes);

// Default plans (always loaded)
export { DEFAULT_PLANS } from './plans';

// Lazy-loaded exports (loaded on demand)
// Note: Adapter packages (@kitium/auth-postgres, @kitium/auth-stripe, @kitium/auth-redis)
// should be used directly for production adapters
export const getMemoryAdapter = (): Promise<
  typeof import('./adapters/memory').MemoryStorageAdapter
> => import('./adapters/memory').then((m) => m.MemoryStorageAdapter);

// Framework integrations (lazy loaded)
export const getNextAuth = (): Promise<typeof import('./frameworks/next').withAuth> =>
  import('./frameworks/next').then((m) => m.withAuth);
export const getExpressAuth = (): Promise<typeof import('./frameworks/express').authMiddleware> =>
  import('./frameworks/express').then((m) => m.authMiddleware);
export const getReactAuth = (): Promise<typeof import('./frameworks/react').useAuth> =>
  import('./frameworks/react').then((m) => m.useAuth);
export const getOAuthRoutes = (): Promise<
  typeof import('./frameworks/oauth-routes').createOAuthRoutes
> => import('./frameworks/oauth-routes').then((m) => m.createOAuthRoutes);
export const getEmailAuthRoutes = (): Promise<{
  createRegisterRoute: typeof import('./frameworks/nextjs-email-routes').createRegisterRoute;
  createLoginRoute: typeof import('./frameworks/nextjs-email-routes').createLoginRoute;
  createForgotPasswordRoute: typeof import('./frameworks/nextjs-email-routes').createForgotPasswordRoute;
  createResetPasswordRoute: typeof import('./frameworks/nextjs-email-routes').createResetPasswordRoute;
  createEmailAuthRoutes: typeof import('./frameworks/nextjs-email-routes').createEmailAuthRoutes;
}> =>
  import('./frameworks/nextjs-email-routes').then((m) => ({
    createRegisterRoute: m.createRegisterRoute,
    createLoginRoute: m.createLoginRoute,
    createForgotPasswordRoute: m.createForgotPasswordRoute,
    createResetPasswordRoute: m.createResetPasswordRoute,
    createEmailAuthRoutes: m.createEmailAuthRoutes,
  }));
export type { EmailAuthRoutesConfig } from './frameworks/nextjs-email-routes';

// React components (lazy loaded)
export const getSignIn = (): Promise<typeof import('./components/SignIn').signIn> =>
  import('./components/SignIn').then((m) => m.signIn);
export const getUserMenu = (): Promise<typeof import('./components/UserMenu').userMenu> =>
  import('./components/UserMenu').then((m) => m.userMenu);
export const getBillingPortal = (): Promise<
  typeof import('./components/BillingPortal').billingPortal
> => import('./components/BillingPortal').then((m) => m.billingPortal);

// CLI is an executable; not exposed via library API

// Convenience functions for common use cases
export async function createAuth(
  config: import('./config').AuthConfig
): Promise<import('./core').AuthCore> {
  // eslint-disable-next-line @typescript-eslint/naming-convention
  const { AuthCore } = await import('./core');
  return new AuthCore(config);
}

export async function withAuth(options?: Record<string, unknown>): Promise<unknown> {
  const { withAuth: nextAuth } = await import('./frameworks/next');
  return nextAuth(options);
}

export async function authMiddleware(options?: Record<string, unknown>): Promise<unknown> {
  const { authMiddleware: expressAuth } = await import('./frameworks/express');
  return expressAuth(options);
}

// eslint-disable-next-line @typescript-eslint/naming-convention
export async function SignIn(props: unknown): Promise<null> {
  const { signIn: signInComponent } = await import('./components/SignIn');
  return signInComponent(props);
}

// eslint-disable-next-line @typescript-eslint/naming-convention
export async function UserMenu(props: unknown): Promise<null> {
  const { userMenu: userMenuComponent } = await import('./components/UserMenu');
  return userMenuComponent(props);
}

// Plugin registration helpers
export async function registerStoragePlugin(
  plugin: import('./plugins/types').Plugin
): Promise<void> {
  const { lazyLoader } = await import('./lazy');
  const manager = (await lazyLoader.load(
    'plugin-manager'
  )) as import('./plugins/manager').KitiumPluginManager;
  return manager.register(plugin);
}

export async function registerBillingPlugin(
  plugin: import('./plugins/types').Plugin
): Promise<void> {
  const { lazyLoader } = await import('./lazy');
  const manager = (await lazyLoader.load(
    'plugin-manager'
  )) as import('./plugins/manager').KitiumPluginManager;
  return manager.register(plugin);
}

export async function registerFrameworkPlugin(
  plugin: import('./plugins/types').Plugin
): Promise<void> {
  const { lazyLoader } = await import('./lazy');
  const manager = (await lazyLoader.load(
    'plugin-manager'
  )) as import('./plugins/manager').KitiumPluginManager;
  return manager.register(plugin);
}

// Environment detection
export const isBrowser =
  typeof globalThis !== 'undefined' &&
  typeof (globalThis as { window?: unknown }).window !== 'undefined';
export const isNode = !isBrowser;
export const isReact = (): boolean => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return typeof require !== 'undefined' && require('react');
  } catch {
    return false;
  }
};
export const isNext = (): boolean => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return typeof require !== 'undefined' && require('next');
  } catch {
    return false;
  }
};
export const isExpress = (): boolean => {
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return typeof require !== 'undefined' && require('express');
  } catch {
    return false;
  }
};

// Auto-detection and setup
export async function autoSetup(): Promise<void> {
  const { lazyLoader } = await import('./lazy');

  // Auto-detect environment and preload appropriate modules
  if (isBrowser) {
    await lazyLoader.preload('react');
    await lazyLoader.preload('signin');
    await lazyLoader.preload('usermenu');
  }

  if (isNode) {
    await lazyLoader.preload('express');
    await lazyLoader.preload('postgres');
  }

  if (isNext()) {
    await lazyLoader.preload('next');
    await lazyLoader.preload('next-auth');
  }

  if (isExpress()) {
    await lazyLoader.preload('express-auth');
  }
}

// Default export for convenience
// Note: no default export to avoid pulling all modules eagerly
