// Kitium Auth - Complete authentication solution with lazy loading and plugin system

// Core authentication engine (always loaded)
export { AuthCore } from './core';

// Configuration system (always loaded)
export {
  createApiKeyConfig,
  createBillingConfig,
  createEmailProvider,
  createEventConfig,
  createOAuthProvider,
  createOrganizationConfig,
  createProvider,
  createSessionConfig,
  createStorageConfig,
  defineConfig,
  getEnvVar,
  getEnvVarAsBoolean,
  getEnvVarAsNumber,
  validateConfig,
} from './config';

// Types (always loaded)
export type {
  ApiKeyConfig,
  // Database record types
  ApiKeyRecord,
  // Configuration types
  AuthConfig,
  AuthEvent,
  AuthProvider,
  BillingAdapter,
  BillingConfig,
  BillingProduct,
  CacheAdapter,
  CreateUserInput,
  // Billing types
  Customer,
  CustomerData,
  // Verification types
  EmailVerificationToken,
  Entitlement,
  EventConfig,
  IssueApiKeyInput,
  IssueApiKeyResult,
  // OAuth types
  OAuthCallbackResult,
  OAuthLink,
  OAuthProfile,
  OAuthTokenResponse,
  Organization,
  OrganizationConfig,
  OrganizationMember,
  OrganizationRecord,
  Plan,
  Principal,
  RateLimit,
  // Core types
  Scope,
  Session,
  SessionConfig,
  SessionRecord,
  // Adapter interfaces
  StorageAdapter,
  StorageConfig,
  Subscription,
  SubscriptionData,
  UpdateUserInput,
  // User types
  User,
  UserRecord,
  VerifyApiKeyResult,
  WebhookEvent,
} from './types';

// RBAC types
export type { RoleRecord } from './types/rbac';

// Two-factor auth types
export type { BackupCode, TwoFactorDevice, TwoFactorSession } from './types/2fa';

// SSO types
export type { SSOLink, SSOSession } from './types/sso';

// Observability and governance
export type {
  CertificationAlignment,
  ComplianceProfile,
  DataRetentionPolicy,
  PasswordPolicy,
} from './compliance/policies';
export { defaultComplianceProfile, validatePasswordAgainstPolicy } from './compliance/policies';
export type {
  JitProfile,
  JitResult,
  ScimProvisioningResult,
  ScimUser,
} from './lifecycle/provisioning';
export { ProvisioningService } from './lifecycle/provisioning';
export type { Tenant, TenantRegionPolicy } from './multitenancy/tenant-registry';
export { TenantRegistry } from './multitenancy/tenant-registry';
export type {
  AuditCategory,
  AuditEvent,
  AuditExporter,
  AuditOptions,
  AuditSeverity,
  MetricsSink,
} from './observability/audit';
export {
  AuditService,
  ConsoleAuditExporter,
  createDefaultAuditService,
  InMemoryAuditExporter,
} from './observability/audit';
export type { Runbook, RunbookStep } from './operational/runbooks';
export { defaultRunbooks } from './operational/runbooks';
export type {
  JwksKey,
  KeyRotationPolicy,
  TokenFormat,
  TokenGovernanceConfig,
  TokenIssueResult,
} from './security/token-governance';
export { createTokenGovernance, TokenGovernance } from './security/token-governance';

// Plugin system (always loaded)
export { KitiumPluginManager } from './plugins/manager';
export type { Plugin, PluginContext, PluginManager } from './plugins/types';

// Lazy loading system (always loaded)
export { lazy, lazyImport, lazyLoader, loadIfAvailable } from './lazy';

// Utility functions (always loaded)
export type { PasswordHashOptions, PasswordValidationRules } from './password';
export {
  generatePasswordResetToken,
  hashPassword,
  normalizeEmail,
  validateEmail,
  validatePasswordStrength,
  verifyPassword,
} from './password';
export { generateApiKey, hashApiKey, verifyApiKey } from './utils';

// OAuth utilities (always loaded)
export type {
  OAuthAuthorizationRequest,
  OAuthState,
  OAuthTokenResponse as OAuthTokenResponseType,
} from './oauth';
export { OAuthManager, PKCEGenerator } from './oauth';

// Pre-configured OAuth providers (always loaded)
export type { OAuthProviderPreset } from './providers/oauth-presets';
export {
  APPLE_PROVIDER,
  createOAuthProviderFromPreset,
  DISCORD_PROVIDER,
  FACEBOOK_PROVIDER,
  getAvailableOAuthProviders,
  GITHUB_PROVIDER,
  GOOGLE_PROVIDER,
  hasOAuthProviderPreset,
  LINKEDIN_PROVIDER,
  MICROSOFT_PROVIDER,
  OAUTH_PROVIDER_PRESETS,
  TWITTER_PROVIDER,
} from './providers/oauth-presets';

// Error handling (always loaded)
// Re-exports from @kitiumai/error with auth-specific wrappers and ErrorRegistry
export {
  AUTH_ERRORS, // Centralized error definitions
  AuthenticationError,
  AuthorizationError,
  ConflictError,
  createError,
  formatErrorResponse,
  getStatusCode,
  InternalError,
  isAuthError,
  NotFoundError,
  problemDetailsFrom,
  RateLimitError,
  toAuthError,
  ValidationError,
} from './errors';

// Also export KitiumError utilities for direct use
export type { ErrorRegistry } from '@kitiumai/error';
export { KitiumError, toKitiumError } from '@kitiumai/error';

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
  RateLimiter: typeof import('./frameworks/rate-limiter').RateLimiter;
  generateRateLimitKey: typeof import('./frameworks/rate-limiter').generateRateLimitKey;
  generateRateLimitHeaders: typeof import('./frameworks/rate-limiter').generateRateLimitHeaders;
}> =>
  import('./frameworks/rate-limiter').then((m) => ({
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
  EmailVerificationManager: typeof import('./email/verification').EmailVerificationManager;
  generateVerificationLink: typeof import('./email/verification').generateVerificationLink;
  generateResetLink: typeof import('./email/verification').generateResetLink;
  generateLoginLink: typeof import('./email/verification').generateLoginLink;
}> =>
  import('./email/verification').then((m) => ({
    EmailVerificationManager: m.EmailVerificationManager,
    generateVerificationLink: m.generateVerificationLink,
    generateResetLink: m.generateResetLink,
    generateLoginLink: m.generateLoginLink,
  }));
export const getEmailProviders = (): Promise<{
  createEmailProvider: typeof import('./email/providers').createEmailProvider;

  SMTPEmailProvider: typeof import('./email/providers').SMTPEmailProvider;

  SendGridEmailProvider: typeof import('./email/providers').SendGridEmailProvider;

  MailgunEmailProvider: typeof import('./email/providers').MailgunEmailProvider;

  ResendEmailProvider: typeof import('./email/providers').ResendEmailProvider;

  MockEmailProvider: typeof import('./email/providers').MockEmailProvider;
}> =>
  import('./email/providers').then((m) => ({
    createEmailProvider: m.createEmailProvider,

    SMTPEmailProvider: m.SMTPEmailProvider,

    SendGridEmailProvider: m.SendGridEmailProvider,

    MailgunEmailProvider: m.MailgunEmailProvider,

    ResendEmailProvider: m.ResendEmailProvider,

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
  ConsoleSMSProvider: typeof import('./twofa/sms-provider').ConsoleSMSProvider;

  TwilioSMSProvider: typeof import('./twofa/sms-provider').TwilioSMSProvider;

  AWSSNSSMSProvider: typeof import('./twofa/sms-provider').AWSSNSSMSProvider;

  CustomSMSProvider: typeof import('./twofa/sms-provider').CustomSMSProvider;
}> =>
  import('./twofa/sms-provider').then((m) => ({
    ConsoleSMSProvider: m.ConsoleSMSProvider,

    TwilioSMSProvider: m.TwilioSMSProvider,

    AWSSNSSMSProvider: m.AWSSNSSMSProvider,

    CustomSMSProvider: m.CustomSMSProvider,
  }));

// WebAuthn/FIDO2 (lazy loaded)
export const getWebAuthnService = (): Promise<
  typeof import('./webauthn/service').WebAuthnService
> => import('./webauthn/service').then((m) => m.WebAuthnService);
// WebAuthn types (always loaded)
export type {
  WebAuthnAuthenticationOptions,
  WebAuthnConfig,
  WebAuthnCredentialAssertion,
  WebAuthnCredentialCreation,
  WebAuthnDevice,
  WebAuthnRegistrationOptions,
} from './webauthn/types';

// Hooks/Events System (always loaded)
export { createHookManager, HookManagerImpl } from './hooks/manager';
export type {
  ApiKeyHookData,
  AuthHookData,
  HookContext,
  HookEventType,
  HookHandler,
  HookManager,
  HookRegistration,
  OrganizationHookData,
  SessionHookData,
  UserHookData,
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
  AuthAttempt,
  RiskFactors,
  RiskScore,
} from './security/anomaly-detection';
export type {
  ConditionalAccessPolicy,
  ConditionalAccessPolicyType,
  DevicePolicy,
  IpRangePolicy,
  LocationPolicy,
  MfaRequiredPolicy,
  PolicyEvaluationContext,
  PolicyEvaluationResult,
  RiskLevelPolicy,
  TimePolicy,
} from './security/conditional-access';
export type {
  Device,
  DeviceRegistrationRequest,
  DeviceTrustLevel,
  DeviceType,
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
export const getReactUtils = (): Promise<typeof import('./frameworks/react')> =>
  import('./frameworks/react');
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

export async function SignIn(props: unknown): Promise<null> {
  const { signIn: signInComponent } = await import('./components/SignIn');
  return signInComponent(props);
}

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

// Type exports
export * from './types';

// Default export for convenience
// Note: no default export to avoid pulling all modules eagerly
