# @kitiumai/auth

Complete authentication solution with OAuth, API keys, email, SAML, 2FA, WebAuthn, RBAC, and subscription management.

## Features

- 🔐 **Multiple Authentication Methods**: Email/password, OAuth, API keys, SAML, WebAuthn
- 🔒 **Two-Factor Authentication**: TOTP and SMS support with backup codes
- 🎫 **WebAuthn/FIDO2**: Passwordless authentication with security keys
- 👥 **Single Sign-On**: OIDC and SAML 2.0 support
- 🛡️ **Role-Based Access Control**: Complete RBAC with permissions
- 🔍 **Security Features**: Anomaly detection, conditional access, device management
- 📊 **Access Reviews**: Governance and certification workflows
- 🎣 **Hooks System**: Event-driven extensibility
- ⚡ **Lazy Loading**: Performance-optimized on-demand loading
- 🔌 **Plugin System**: Extensible plugin architecture
- 🚦 **Rate Limiting**: Configurable rate limiting per user/IP/endpoint
- 🎨 **Framework Integrations**: Express.js, Next.js, React
- 📦 **Pre-configured OAuth Providers**: Google, GitHub, Microsoft, Facebook, Apple, Twitter, Discord, LinkedIn
- 🛠️ **TypeScript**: Full TypeScript support with comprehensive types
- 📋 **RFC 7807**: Problem Details for HTTP APIs error format
- 🧭 **Enterprise Readiness**: JWKS-backed token governance, SIEM-ready audit events, SCIM/JIT provisioning, tenant isolation, and compliance presets

## Installation

```bash
npm install @kitiumai/auth
# or
pnpm add @kitiumai/auth
# or
yarn add @kitiumai/auth
```

## Quick Start

### Basic Setup

```typescript
import { AuthCore, defineConfig, MemoryStorageAdapter } from '@kitiumai/auth';

// Create configuration
const config = defineConfig({
  appName: 'My App',
  appUrl: 'https://myapp.com',
  providers: [
    {
      id: 'email',
      name: 'Email',
      type: 'email',
      enabled: true,
    },
  ],
  storage: {
    type: 'memory',
  },
});

// Initialize storage adapter
const storage = new MemoryStorageAdapter();

// Create AuthCore instance
const auth = new AuthCore(config, storage);

// Register a user
const user = await auth.registerUser({
  email: 'user@example.com',
  password: 'securePassword123!',
});

// Authenticate
const session = await auth.authenticate('user@example.com', 'securePassword123!');
```

### Express.js Integration

```typescript
import express from 'express';
import { getExpressAuth, getOAuthRoutes } from '@kitiumai/auth';

const app = express();

// Get Express auth middleware (lazy loaded)
const authMiddleware = await getExpressAuth();
app.use('/api', authMiddleware(auth));

// Get OAuth routes (lazy loaded)
const createOAuthRoutes = await getOAuthRoutes();
app.use('/auth/oauth', createOAuthRoutes(auth));
```

### OAuth with Pre-configured Providers

```typescript
import {
  AuthCore,
  defineConfig,
  createOAuthProviderFromPreset,
  GOOGLE_PROVIDER,
} from '@kitiumai/auth';

const config = defineConfig({
  appName: 'My App',
  appUrl: 'https://myapp.com',
  providers: [
    createOAuthProviderFromPreset(GOOGLE_PROVIDER, {
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      redirectUri: 'https://myapp.com/auth/oauth/google/callback',
    }),
  ],
  storage: {
    type: 'memory',
  },
});

const auth = new AuthCore(config, storage);

// Initiate OAuth flow
const authUrl = await auth.getOAuthAuthorizationUrl('google', {
  redirectUri: 'https://myapp.com/auth/oauth/google/callback',
  state: 'random-state-string',
});

// Handle OAuth callback
const result = await auth.handleOAuthCallback('google', {
  code: 'authorization-code',
  state: 'random-state-string',
});
```

### Enterprise controls

**Signed tokens with JWKS rotation**

```typescript
import { createTokenGovernance } from '@kitiumai/auth';

const tokenGovernance = createTokenGovernance({
  format: {
    audience: 'my-app',
    issuer: 'https://auth.my-app.com',
    expirationSeconds: 3600,
    cookieFlags: { httpOnly: true, sameSite: 'lax', secure: true },
  },
  rotation: { rotationDays: 30, overlapSeconds: 60, enforceKid: true },
});

const { token, kid } = tokenGovernance.issueToken('user-123', { roles: ['admin'] });
tokenGovernance.verifyToken(token);
```

**Audit pipeline with SIEM export and metrics hooks**

```typescript
import { AuditService, ConsoleAuditExporter } from '@kitiumai/auth';

const audit = new AuditService([new ConsoleAuditExporter()], { redactionFields: ['password'] }, {
  record: async (metric, value, tags) => console.log(metric, value, tags),
});

await audit.record({
  id: 'evt-1',
  category: 'auth',
  actor: 'user-123',
  action: 'login',
  severity: 'info',
  timestamp: new Date(),
  metadata: { ip: '192.168.1.1' },
});
```

**SCIM and JIT provisioning**

```typescript
import { ProvisioningService } from '@kitiumai/auth';

const provisioning = new ProvisioningService();
await provisioning.upsertScimUser({
  userName: 'jane.doe',
  active: true,
  emails: [{ value: 'jane@example.com', primary: true }],
});

await provisioning.jitProvision({ email: 'saml-user@example.com', provider: 'saml' });
```

**Tenant isolation and residency**

```typescript
import { TenantRegistry } from '@kitiumai/auth';

const tenants = new TenantRegistry();
const tenant = tenants.createTenant('Acme', { region: 'eu-west-1', residencyRequired: true, encryptionKeyId: 'kms-eu' });
tenants.setFeatureFlag(tenant.id, 'adaptive-mfa', true);
```

**Compliance and credential policy enforcement**

```typescript
import { defaultComplianceProfile, validatePasswordAgainstPolicy } from '@kitiumai/auth';

const compliance = defaultComplianceProfile();
const violations = validatePasswordAgainstPolicy('weak', compliance.password);
if (violations.length) {
  throw new Error(`Password rejected: ${violations.join(', ')}`);
}
```

### Two-Factor Authentication

```typescript
import { getTwoFactorAuthService } from '@kitiumai/auth';

const twoFAService = await getTwoFactorAuthService();
await twoFAService.initialize(storage, { enabled: true });

// Enroll TOTP device
const device = await twoFAService.enrollTOTPDevice(userId, 'My Phone');
// device.secret contains the TOTP secret
// Generate QR code using device.secret

// Verify TOTP enrollment
const backupCodes = await twoFAService.verifyTOTPEnrollment(
  userId,
  device.id,
  '123456' // TOTP code
);

// Verify 2FA during login
const isValid = await twoFAService.verifyTwoFactor(userId, device.id, '123456');
```

### WebAuthn (Passwordless)

```typescript
import { getWebAuthnService } from '@kitiumai/auth';

const webauthnService = await getWebAuthnService();
await webauthnService.initialize(storage, {
  enabled: true,
  rpId: 'myapp.com',
  rpName: 'My App',
});

// Register credential
const registrationOptions = await webauthnService.getRegistrationOptions(userId);
// Send to client for credential creation

// Authenticate with credential
const authOptions = await webauthnService.getAuthenticationOptions(userId);
// Send to client for credential assertion
```

### RBAC (Role-Based Access Control)

```typescript
import { getRBACService } from '@kitiumai/auth';

const rbacService = await getRBACService();
await rbacService.initialize(storage, { enabled: true });

// Create role
const role = await rbacService.createRole(orgId, 'Admin', [
  { id: 'perm_1', name: 'Full Access', resource: '*', action: '*' },
]);

// Assign role to user
await rbacService.assignRoleToUser(userId, role.id, orgId);

// Check permission
const hasPermission = await rbacService.hasPermission(userId, {
  resource: 'users',
  action: 'delete',
  orgId,
});
```

### Express.js RBAC Middleware

```typescript
import { getRBACMiddleware } from '@kitiumai/auth';
import express from 'express';

const app = express();
const { requireRole, requirePermission } = await getRBACMiddleware();

// Require specific role
app.get('/admin', requireRole(['admin'], { rbacService }), (req, res) => {
  res.json({ message: 'Admin access granted' });
});

// Require specific permission
app.delete('/users/:id', requirePermission('users', 'delete', { rbacService }), (req, res) => {
  res.json({ message: 'User deleted' });
});
```

### Rate Limiting

```typescript
import { getRateLimitMiddleware } from '@kitiumai/auth';
import express from 'express';

const app = express();
const { createRateLimitMiddleware } = await getRateLimitMiddleware();

// Apply rate limiting
app.use(
  createRateLimitMiddleware({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // 100 requests per window
  })
);
```

### Error Handling

```typescript
import { getErrorHandler, setupErrorHandling } from '@kitiumai/auth';
import express from 'express';

const app = express();

// Setup error handling (includes 404 handler)
setupErrorHandling(app);

// Or use error handler directly
const errorHandler = await getErrorHandler();
app.use(errorHandler);
```

### Hooks/Events

```typescript
import { createHookManager } from '@kitiumai/auth';

const hookManager = createHookManager();

// Register hook
hookManager.on('user.created', async (data) => {
  console.log('User created:', data.user.email);
  // Send welcome email, create default resources, etc.
});

// Trigger hook
await hookManager.trigger('user.created', {
  user: { id: 'user_1', email: 'user@example.com' },
});
```

### Anomaly Detection

```typescript
import { getAnomalyDetectionService } from '@kitiumai/auth';

const anomalyService = await getAnomalyDetectionService();
await anomalyService.initialize(storage, {
  enabled: true,
  bruteForceThreshold: 5,
  bruteForceWindow: 300, // 5 minutes
});

// Record authentication attempt
await anomalyService.recordAttempt({
  email: 'user@example.com',
  ipAddress: '192.168.1.1',
  success: false,
});

// Check for brute force
const isBruteForce = await anomalyService.isBruteForceAttempt('user@example.com');

// Get risk score
const riskScore = await anomalyService.calculateRiskScore({
  email: 'user@example.com',
  ipAddress: '192.168.1.1',
  newDevice: true,
  newLocation: true,
});
```

### Conditional Access

```typescript
import { getConditionalAccessService } from '@kitiumai/auth';

const conditionalAccess = await getConditionalAccessService();
await conditionalAccess.initialize(storage, { enabled: true });

// Create location policy
const policy = await conditionalAccess.createPolicy({
  name: 'Block High-Risk Countries',
  type: 'location',
  blockedCountries: ['XX', 'YY'],
});

// Evaluate policy
const result = await conditionalAccess.evaluatePolicy(policy.id, {
  userId: 'user_1',
  ipAddress: '192.168.1.1',
  country: 'US',
  deviceId: 'device_1',
});
```

## API Reference

### Core Classes

#### `AuthCore`

Main authentication engine.

```typescript
class AuthCore {
  constructor(config: AuthConfig, storage: StorageAdapter);

  // User management
  registerUser(input: CreateUserInput): Promise<User>;
  updateUser(userId: string, input: UpdateUserInput): Promise<User>;
  deleteUser(userId: string): Promise<void>;
  getUser(userId: string): Promise<User | null>;

  // Authentication
  authenticate(email: string, password: string): Promise<Session>;
  verifySession(sessionId: string): Promise<Session>;
  revokeSession(sessionId: string): Promise<void>;

  // API Keys
  issueApiKey(userId: string, input: IssueApiKeyInput): Promise<IssueApiKeyResult>;
  verifyApiKey(apiKey: string): Promise<VerifyApiKeyResult>;
  revokeApiKey(keyId: string): Promise<void>;

  // OAuth
  getOAuthAuthorizationUrl(providerId: string, options: OAuthOptions): Promise<string>;
  handleOAuthCallback(
    providerId: string,
    params: OAuthCallbackParams
  ): Promise<OAuthCallbackResult>;
}
```

#### `TwoFactorAuthService`

Two-factor authentication service.

```typescript
class TwoFactorAuthService {
  // TOTP
  enrollTOTPDevice(userId: string, name?: string): Promise<TwoFactorDevice>;
  verifyTOTPEnrollment(userId: string, deviceId: string, code: string): Promise<BackupCode[]>;

  // SMS
  enrollSMSDevice(userId: string, phoneNumber: string, name?: string): Promise<TwoFactorDevice>;
  sendSMSCode(deviceId: string): Promise<void>;
  verifySMSCode(userId: string, deviceId: string, code: string): Promise<void>;

  // Verification
  verifyTwoFactor(userId: string, deviceId: string, code: string): Promise<boolean>;

  // Management
  listDevices(userId: string): Promise<TwoFactorDevice[]>;
  deleteDevice(deviceId: string): Promise<void>;
  getTwoFactorStatus(userId: string): Promise<TwoFactorStatus>;
}
```

#### `WebAuthnService`

WebAuthn/FIDO2 passwordless authentication.

```typescript
class WebAuthnService {
  getRegistrationOptions(userId: string): Promise<WebAuthnRegistrationOptions>;
  registerCredential(
    userId: string,
    credential: WebAuthnCredentialCreation
  ): Promise<WebAuthnDevice>;

  getAuthenticationOptions(userId: string): Promise<WebAuthnAuthenticationOptions>;
  authenticateCredential(userId: string, assertion: WebAuthnCredentialAssertion): Promise<boolean>;

  listDevices(userId: string): Promise<WebAuthnDevice[]>;
  deleteDevice(deviceId: string): Promise<void>;
}
```

#### `RBACService`

Role-based access control service.

```typescript
class RBACService {
  // Roles
  createRole(orgId: string, name: string, permissions: Permission[]): Promise<Role>;
  updateRole(roleId: string, updates: Partial<Role>): Promise<Role>;
  deleteRole(roleId: string): Promise<void>;
  getRole(roleId: string): Promise<Role | null>;
  listRoles(orgId: string): Promise<Role[]>;

  // Assignments
  assignRoleToUser(userId: string, roleId: string, orgId: string): Promise<void>;
  revokeRoleFromUser(userId: string, roleId: string, orgId: string): Promise<void>;
  getUserRoles(userId: string, orgId: string): Promise<Role[]>;

  // Permissions
  hasPermission(userId: string, check: PermissionCheck): Promise<boolean>;
  hasAnyPermission(userId: string, checks: PermissionCheck[]): Promise<boolean>;
  hasAllPermissions(userId: string, checks: PermissionCheck[]): Promise<boolean>;
  getUserPermissions(userId: string, orgId: string): Promise<Permission[]>;
}
```

#### `SSOService`

Single sign-on service.

```typescript
class SSOService {
  // OIDC
  registerOIDCProvider(config: OIDCProviderConfig): Promise<OIDCProvider>;
  getOIDCAuthorizationUrl(providerId: string, options: OIDCOptions): Promise<string>;
  handleOIDCCallback(providerId: string, params: OIDCCallbackParams): Promise<OIDCCallbackResult>;

  // SAML
  registerSAMLProvider(config: SAMLProviderConfig): Promise<SAMLProvider>;
  getSAMLAuthRequest(providerId: string, options: SAMLOptions): Promise<string>;
  handleSAMLResponse(providerId: string, samlResponse: string): Promise<SAMLCallbackResult>;

  // Links
  linkSSOProvider(userId: string, providerId: string, subject: string): Promise<SSOLink>;
  getUserSSOLinks(userId: string): Promise<SSOLink[]>;
  deleteSSOLink(linkId: string): Promise<void>;
}
```

### Configuration

#### `defineConfig`

Create authentication configuration.

```typescript
function defineConfig(config: AuthConfig): AuthConfig;

interface AuthConfig {
  appName: string;
  appUrl: string;
  providers: AuthProvider[];
  storage: StorageConfig;
  billing?: BillingConfig;
  apiKeys?: ApiKeyConfig;
  sessions?: SessionConfig;
  organizations?: OrganizationConfig;
  events?: EventConfig;
}
```

#### Pre-configured OAuth Providers

```typescript
import {
  GOOGLE_PROVIDER,
  GITHUB_PROVIDER,
  MICROSOFT_PROVIDER,
  FACEBOOK_PROVIDER,
  APPLE_PROVIDER,
  TWITTER_PROVIDER,
  DISCORD_PROVIDER,
  LINKEDIN_PROVIDER,
  createOAuthProviderFromPreset,
} from '@kitiumai/auth';

const provider = createOAuthProviderFromPreset(GOOGLE_PROVIDER, {
  clientId: 'your-client-id',
  clientSecret: 'your-client-secret',
  redirectUri: 'https://yourapp.com/callback',
});
```

### Error Handling

All errors use the `@kitiumai/error` API with RFC 7807 Problem Details format.

```typescript
import {
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError,
} from '@kitiumai/auth';

// Error format
throw new ValidationError({
  code: 'auth/invalid_email',
  message: 'Invalid email address',
  severity: 'error',
  retryable: false,
  context: { email: 'invalid-email' },
});
```

### Framework Integrations

#### Express.js

```typescript
import { getExpressAuth, getRBACMiddleware, getErrorHandler } from '@kitiumai/auth';

// Authentication middleware
const authMiddleware = await getExpressAuth();
app.use('/api', authMiddleware(auth));

// RBAC middleware
const { requireRole, requirePermission } = await getRBACMiddleware();
app.get('/admin', requireRole(['admin'], { rbacService }), handler);

// Error handling
const errorHandler = await getErrorHandler();
app.use(errorHandler);
```

#### Next.js

```typescript
import { getNextAuth } from '@kitiumai/auth';

// Server-side auth helper
const withAuth = await getNextAuth();
export default withAuth(async (req, res) => {
  // req.user is available
  res.json({ user: req.user });
});
```

#### React

```typescript
import { getReactAuth } from '@kitiumai/auth';

function MyComponent() {
  const { user, isLoading, signOut } = await getReactAuth();

  if (isLoading) return <div>Loading...</div>;
  if (!user) return <div>Not authenticated</div>;

  return (
    <div>
      <p>Welcome, {user.email}</p>
      <button onClick={signOut}>Sign Out</button>
    </div>
  );
}
```

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```typescript
import type {
  User,
  Session,
  AuthConfig,
  AuthProvider,
  StorageAdapter,
  TwoFactorDevice,
  WebAuthnDevice,
  Role,
  Permission,
  SSOProvider,
} from '@kitiumai/auth';
```

## Security Best Practices

1. **Use Strong Passwords**: Enable password strength validation
2. **Enable 2FA**: Require 2FA for sensitive operations
3. **Use HTTPS**: Always use HTTPS in production
4. **Rate Limiting**: Enable rate limiting to prevent brute force attacks
5. **Anomaly Detection**: Monitor and detect suspicious activity
6. **Conditional Access**: Implement location and device-based policies
7. **Regular Access Reviews**: Review and certify user access regularly
8. **Secure API Keys**: Rotate API keys regularly
9. **Session Management**: Use secure, httpOnly cookies for sessions
10. **Error Handling**: Don't expose sensitive information in error messages

## Contributing

Contributions are welcome! Please read our contributing guidelines first.

## License

MIT

## Support

- [Documentation](https://github.com/kitium-ai/auth)
- [Issues](https://github.com/kitium-ai/auth/issues)
- [Discussions](https://github.com/kitium-ai/auth/discussions)
