# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v4.0.1] - 2025-12-02

### Added

bumped patch version for kitiumai packages

## [v4.0.0] - 2025-11-30

### Added
- Token governance utilities with JWKS rotation, strict cookie guidance, and verification helpers for enterprise session hardening.
- Audit pipeline building blocks that support SIEM export, metrics hooks, and redaction defaults.
- SCIM/JIT provisioning, tenant registry with residency flags, compliance profiles, and operational runbooks to align with enterprise readiness recommendations.

## [3.0.0] - 2025-11-26

### Added

#### Core Authentication Features

- **AuthCore**: Main authentication engine orchestrating all auth operations
  - Email/password authentication with secure password hashing (argon2)
  - API key authentication with secure key generation and verification
  - Session management with configurable expiration
  - User management (create, update, delete users)
  - Multi-tenant organization support
  - Subscription and billing integration hooks

#### OAuth Authentication

- **OAuth Manager**: Complete OAuth 2.0 implementation
  - Authorization code flow with PKCE support
  - Token management and refresh
  - State management for security
  - Pre-configured providers: Google, GitHub, Microsoft, Facebook, Apple, Twitter, Discord, LinkedIn
  - Custom OAuth provider support
  - OAuth profile mapping and user linking

#### Email Authentication

- **Email Auth Service**: Email-based authentication
  - User registration with email verification
  - Password reset flow
  - Magic link authentication
  - Email verification management
  - Multiple email provider support (SMTP, SendGrid, Mailgun, Resend)
  - Customizable email templates

#### Two-Factor Authentication (2FA)

- **TwoFactorAuthService**: Comprehensive 2FA implementation
  - TOTP (Time-based One-Time Password) support
  - SMS-based 2FA with multiple providers (Twilio, AWS SNS, Console)
  - Backup codes generation and management
  - Device management for 2FA
  - Session-based 2FA verification
  - Express.js middleware for 2FA enforcement

#### WebAuthn/FIDO2

- **WebAuthnService**: Passwordless authentication
  - FIDO2/WebAuthn credential registration
  - Passwordless authentication flow
  - Device credential management
  - Challenge-based security
  - Cross-platform support (desktop, mobile, security keys)

#### Single Sign-On (SSO)

- **SSOService**: Enterprise SSO support
  - OIDC (OpenID Connect) provider management
  - SAML 2.0 provider support
  - SSO link management (multiple providers per user)
  - SSO session management
  - Auto-provisioning and user data sync
  - Metadata URL support for OIDC discovery

#### Role-Based Access Control (RBAC)

- **RBACService**: Complete RBAC implementation
  - Role creation and management
  - Permission-based access control
  - Role assignment to users
  - Organization-scoped roles
  - System roles protection
  - Permission checking (single, any, all)
  - Express.js middleware for RBAC enforcement

#### Security Features

- **AnomalyDetectionService**: Security monitoring
  - Brute force detection
  - Risk scoring based on multiple factors
  - Suspicious IP detection
  - Bot detection capabilities
  - Authentication attempt tracking
  - Configurable thresholds and time windows

- **ConditionalAccessService**: Policy-based access control
  - Location-based policies (country/region blocking)
  - Device-based policies (trusted devices, device registration)
  - Time-based policies (business hours, day restrictions)
  - IP range policies (allow/block IP ranges)
  - MFA requirement policies
  - Risk-level based policies
  - Policy evaluation and enforcement

- **DeviceManagementService**: Device trust management
  - Device registration and fingerprinting
  - Device trust levels (trusted, untrusted, unknown)
  - Device verification workflows
  - Device deletion and management
  - Device metadata tracking

#### Governance

- **AccessReviewService**: Access certification workflows
  - Access review campaign creation
  - Review assignment and tracking
  - Review status management (pending, approved, rejected, expired)
  - Campaign lifecycle management
  - Review expiration handling

#### Hooks/Events System

- **HookManager**: Event-driven extensibility
  - User lifecycle hooks (created, updated, deleted)
  - Session hooks (created, expired, revoked)
  - API key hooks (created, revoked)
  - Organization hooks (created, updated, deleted)
  - Authentication hooks (login, logout, failed)
  - Custom hook registration
  - Async hook execution

#### Error Handling

- **Integrated @kitiumai/error**: Enterprise-grade error handling
  - RFC 7807 Problem Details support
  - Structured error codes with `auth/` prefix
  - Error context and metadata
  - Error metrics and fingerprinting
  - Retry strategy metadata
  - Comprehensive error types (ValidationError, AuthenticationError, AuthorizationError, etc.)
  - Express.js error handler middleware

#### Rate Limiting

- **RateLimiter**: Configurable rate limiting
  - Per-user rate limiting
  - Per-IP rate limiting
  - Per-endpoint rate limiting
  - Public rate limiting
  - Configurable windows and limits
  - Rate limit headers (X-RateLimit-\*)
  - Express.js middleware integration

#### Framework Integrations

- **Express.js**: Complete Express integration
  - Authentication middleware
  - RBAC middleware
  - 2FA middleware
  - Rate limiting middleware
  - Error handling middleware
  - OAuth routes
  - Email auth routes

- **Next.js**: Next.js integration
  - Server-side authentication helpers
  - API route protection
  - Email authentication routes
  - OAuth callback handling

- **React**: React hooks and components
  - `useAuth` hook
  - SignIn component
  - UserMenu component
  - BillingPortal component

#### Configuration System

- **Flexible Configuration**: Environment-aware configuration
  - Provider configuration (OAuth, email, SAML)
  - Storage adapter configuration
  - Billing configuration
  - API key configuration
  - Session configuration
  - Organization configuration
  - Event configuration
  - Environment variable helpers
  - Configuration validation

#### Plugin System

- **KitiumPluginManager**: Extensible plugin architecture
  - Plugin registration and lifecycle
  - Plugin context and dependencies
  - Plugin hooks integration
  - Lazy plugin loading

#### Lazy Loading

- **Lazy Loading System**: Performance optimization
  - On-demand module loading
  - Code splitting support
  - Conditional loading
  - Lazy import utilities

#### Utilities

- **Password Utilities**: Secure password handling
  - Argon2 password hashing
  - Password strength validation
  - Password reset token generation
  - Email validation and normalization

- **API Key Utilities**: Secure API key management
  - Cryptographically secure key generation
  - Key hashing and verification
  - Key format validation

#### Storage Adapters

- **Memory Adapter**: In-memory storage for development/testing
  - Full CRUD operations
  - Transaction support
  - Query capabilities

#### TypeScript Support

- **Full TypeScript Coverage**: Complete type definitions
  - All APIs fully typed
  - Type-safe configuration
  - Type-safe error handling
  - Comprehensive type exports

### Changed

#### Error Handling Migration

- Migrated from custom error classes to `@kitiumai/error` API
- All error instantiations now use object-based format with error codes
- Added `severity` and `retryable` fields to all errors
- Enhanced error context with correlation IDs and metadata
- RFC 7807 Problem Details format support

### Security

- **Password Security**: Argon2 hashing with configurable parameters
- **API Key Security**: Cryptographically secure key generation and hashing
- **Session Security**: Secure session management with expiration
- **OAuth Security**: PKCE support, state validation, secure token handling
- **2FA Security**: TOTP with secure secret generation, SMS with rate limiting
- **WebAuthn Security**: Challenge-based authentication, credential verification
- **Rate Limiting**: Protection against brute force and abuse
- **Anomaly Detection**: Proactive threat detection and risk scoring

### Documentation

- Comprehensive API documentation
- Usage examples for all features
- Framework integration guides
- Security best practices
- Configuration reference
- Error code reference
