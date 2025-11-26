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
export const getErrorHandler = () =>
  import('./frameworks/error-handler').then((m) => m.errorHandler);
export const getAsyncHandler = () =>
  import('./frameworks/error-handler').then((m) => m.asyncHandler);
export const getErrorMiddleware = () =>
  import('./frameworks/error-handler').then((m) => m.setupErrorHandling);

// Rate limiting (lazy loaded)
export const getRateLimiter = () =>
  import('./frameworks/rate-limiter').then((m) => ({
    RateLimiter: m.RateLimiter,
    generateRateLimitKey: m.generateRateLimitKey,
    generateRateLimitHeaders: m.generateRateLimitHeaders,
  }));
export const getRateLimitMiddleware = () =>
  import('./frameworks/rate-limit-middleware').then((m) => ({
    createRateLimitMiddleware: m.createRateLimitMiddleware,
    createPublicRateLimitMiddleware: m.createPublicRateLimitMiddleware,
    createPerPrincipalRateLimitMiddleware: m.createPerPrincipalRateLimitMiddleware,
    createEndpointRateLimitMiddleware: m.createEndpointRateLimitMiddleware,
  }));

// Email authentication (lazy loaded)
export const getEmailAuthService = () => import('./email/service').then((m) => m.EmailAuthService);
export const getEmailRoutes = () => import('./email/routes').then((m) => m.createEmailRoutes);
export const getEmailVerificationManager = () =>
  import('./email/verification').then((m) => ({
    EmailVerificationManager: m.EmailVerificationManager,
    generateVerificationLink: m.generateVerificationLink,
    generateResetLink: m.generateResetLink,
    generateLoginLink: m.generateLoginLink,
  }));
export const getEmailProviders = () =>
  import('./email/providers').then((m) => ({
    createEmailProvider: m.createEmailProvider,
    SMTPEmailProvider: m.SMTPEmailProvider,
    SendGridEmailProvider: m.SendGridEmailProvider,
    MailgunEmailProvider: m.MailgunEmailProvider,
    ResendEmailProvider: m.ResendEmailProvider,
    MockEmailProvider: m.MockEmailProvider,
  }));
export const getEmailTemplates = () =>
  import('./email/templates').then((m) => ({
    createPasswordResetTemplate: m.createPasswordResetTemplate,
    createEmailVerificationTemplate: m.createEmailVerificationTemplate,
    createVerificationCodeTemplate: m.createVerificationCodeTemplate,
    createLoginLinkTemplate: m.createLoginLinkTemplate,
    createWelcomeTemplate: m.createWelcomeTemplate,
  }));

// Two-Factor Authentication (lazy loaded)
export const getTwoFactorAuthService = () =>
  import('./twofa/service').then((m) => m.TwoFactorAuthService);
export const getSMSProviders = () =>
  import('./twofa/sms-provider').then((m) => ({
    ConsoleSMSProvider: m.ConsoleSMSProvider,
    TwilioSMSProvider: m.TwilioSMSProvider,
    AWSSNSSMSProvider: m.AWSSNSSMSProvider,
    CustomSMSProvider: m.CustomSMSProvider,
  }));

// WebAuthn/FIDO2 (lazy loaded)
export const getWebAuthnService = () => import('./webauthn/service').then((m) => m.WebAuthnService);
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
export const getAnomalyDetectionService = () =>
  import('./security/anomaly-detection').then((m) => m.AnomalyDetectionService);
export const getConditionalAccessService = () =>
  import('./security/conditional-access').then((m) => m.ConditionalAccessService);
export const getDeviceManagementService = () =>
  import('./security/device-management').then((m) => m.DeviceManagementService);
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
export const getAccessReviewService = () =>
  import('./governance/access-reviews').then((m) => m.AccessReviewService);

// SAML authentication (lazy loaded)
export const getSAMLAuthService = () => import('./saml/service').then((m) => m.SAMLAuthService);
export const getSAMLRoutes = () =>
  import('./saml/routes').then((m) => ({
    createSAMLRoutes: m.createSAMLRoutes,
    extractTenantIdMiddleware: m.extractTenantIdMiddleware,
  }));
export const getSAMLUtils = () =>
  import('./saml/utils').then((m) => ({
    generateSAMLAuthRequest: m.generateSAMLAuthRequest,
    parseSAMLResponse: m.parseSAMLResponse,
    extractUserProfile: m.extractUserProfile,
    generateSPMetadata: m.generateSPMetadata,
    validateSignature: m.validateSignature,
  }));

// HTTP Service (lazy loaded)
export const getHttpService = () => import('./service/http-service').then((m) => m.HttpAuthService);
export const getStartAuthService = () =>
  import('./service/http-service').then((m) => m.startAuthService);
export const getApiRoutes = () => import('./service/api-routes').then((m) => m.createApiRoutes);

// Default plans (always loaded)
export { DEFAULT_PLANS } from './plans';

// Lazy-loaded exports (loaded on demand)
// Note: Adapter packages (@kitium/auth-postgres, @kitium/auth-stripe, @kitium/auth-redis)
// should be used directly for production adapters
export const getMemoryAdapter = () =>
  import('./adapters/memory').then((m) => m.MemoryStorageAdapter);

// Framework integrations (lazy loaded)
export const getNextAuth = () => import('./frameworks/next').then((m) => m.withAuth);
export const getExpressAuth = () => import('./frameworks/express').then((m) => m.authMiddleware);
export const getReactAuth = () => import('./frameworks/react').then((m) => m.useAuth);
export const getOAuthRoutes = () =>
  import('./frameworks/oauth-routes').then((m) => m.createOAuthRoutes);
export const getEmailAuthRoutes = () =>
  import('./frameworks/nextjs-email-routes').then((m) => ({
    createRegisterRoute: m.createRegisterRoute,
    createLoginRoute: m.createLoginRoute,
    createForgotPasswordRoute: m.createForgotPasswordRoute,
    createResetPasswordRoute: m.createResetPasswordRoute,
    createEmailAuthRoutes: m.createEmailAuthRoutes,
  }));
export type { EmailAuthRoutesConfig } from './frameworks/nextjs-email-routes';

// React components (lazy loaded)
export const getSignIn = () => import('./components/SignIn').then((m) => m.SignIn);
export const getUserMenu = () => import('./components/UserMenu').then((m) => m.UserMenu);
export const getBillingPortal = () =>
  import('./components/BillingPortal').then((m) => m.BillingPortal);

// CLI is an executable; not exposed via library API

// Convenience functions for common use cases
export async function createAuth(storage: any, options: any) {
  const { AuthCore } = await import('./core');
  return new AuthCore(storage, options);
}

export async function withAuth(options?: any): Promise<any> {
  const { withAuth: nextAuth } = await import('./frameworks/next');
  return nextAuth(options);
}

export async function authMiddleware(options?: any): Promise<any> {
  const { authMiddleware: expressAuth } = await import('./frameworks/express');
  return expressAuth(options);
}

export async function SignIn(props: any) {
  const { SignIn: SignInComponent } = await import('./components/SignIn');
  return SignInComponent(props);
}

export async function UserMenu(props: any) {
  const { UserMenu: UserMenuComponent } = await import('./components/UserMenu');
  return UserMenuComponent(props);
}

// Plugin registration helpers
export async function registerStoragePlugin(plugin: any) {
  const { lazyLoader } = await import('./lazy');
  return lazyLoader.load('plugin-manager').then((manager: any) => manager.register(plugin));
}

export async function registerBillingPlugin(plugin: any) {
  const { lazyLoader } = await import('./lazy');
  return lazyLoader.load('plugin-manager').then((manager: any) => manager.register(plugin));
}

export async function registerFrameworkPlugin(plugin: any) {
  const { lazyLoader } = await import('./lazy');
  return lazyLoader.load('plugin-manager').then((manager: any) => manager.register(plugin));
}

// Environment detection
export const isBrowser =
  typeof globalThis !== 'undefined' && typeof (globalThis as any).window !== 'undefined';
export const isNode = !isBrowser;
export const isReact = () => {
  try {
    return typeof require !== 'undefined' && require('react');
  } catch {
    return false;
  }
};
export const isNext = () => {
  try {
    return typeof require !== 'undefined' && require('next');
  } catch {
    return false;
  }
};
export const isExpress = () => {
  try {
    return typeof require !== 'undefined' && require('express');
  } catch {
    return false;
  }
};

// Auto-detection and setup
export async function autoSetup() {
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
