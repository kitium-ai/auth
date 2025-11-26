/**
 * WebAuthn/FIDO2 Types
 * Passwordless authentication using WebAuthn API
 */

/**
 * Authenticator transport types
 */
export type AuthenticatorTransport = 'usb' | 'nfc' | 'ble' | 'internal';

/**
 * WebAuthn device/credential
 */
export interface WebAuthnDevice {
  id: string;
  userId: string;
  name: string;
  credentialId: string;
  publicKey: string;
  counter: number;
  transports?: AuthenticatorTransport[];
  createdAt: Date;
  lastUsedAt?: Date;
  verified: boolean;
}

/**
 * WebAuthn registration options
 */
export interface WebAuthnRegistrationOptions {
  challenge: string;
  rp: {
    name: string;
    id?: string;
  };
  user: {
    id: string;
    name: string;
    displayName: string;
  };
  pubKeyCredParams: Array<{
    type: 'public-key';
    alg: number;
  }>;
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct';
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    userVerification?: 'required' | 'preferred' | 'discouraged';
    requireResidentKey?: boolean;
  };
}

/**
 * WebAuthn authentication options
 */
export interface WebAuthnAuthenticationOptions {
  challenge: string;
  timeout?: number;
  rpId?: string;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  userVerification?: 'required' | 'preferred' | 'discouraged';
}

/**
 * WebAuthn credential creation result
 */
export interface WebAuthnCredentialCreation {
  credentialId: string;
  publicKey: string;
  attestationObject: string;
  clientDataJSON: string;
  transports?: AuthenticatorTransport[];
}

/**
 * WebAuthn credential assertion result
 */
export interface WebAuthnCredentialAssertion {
  credentialId: string;
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle?: string;
}

/**
 * WebAuthn configuration
 */
export interface WebAuthnConfig {
  enabled: boolean;
  rpName: string;
  rpId?: string;
  origin: string;
  timeout?: number;
  attestation?: 'none' | 'indirect' | 'direct';
  authenticatorSelection?: {
    authenticatorAttachment?: 'platform' | 'cross-platform';
    userVerification?: 'required' | 'preferred' | 'discouraged';
    requireResidentKey?: boolean;
  };
}
