export interface PasswordPolicy {
  minLength: number;
  requireNumbers?: boolean;
  requireSymbols?: boolean;
  deniedPasswords?: string[];
  breachCheckEnabled?: boolean;
}

export interface DataRetentionPolicy {
  eventRetentionDays: number;
  piiRedactionEnabled?: boolean;
  anonymizeAfterDays?: number;
}

export interface CertificationAlignment {
  soc2?: boolean;
  iso27001?: boolean;
  gdpr?: boolean;
}

export interface ComplianceProfile {
  password: PasswordPolicy;
  retention: DataRetentionPolicy;
  certifications?: CertificationAlignment;
}

export function validatePasswordAgainstPolicy(password: string, policy: PasswordPolicy): string[] {
  const errors: string[] = [];
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters`);
  }
  if (policy.requireNumbers && !/[0-9]/.test(password)) {
    errors.push('Password must include at least one number');
  }
  if (policy.requireSymbols && !/[^A-Za-z0-9]/.test(password)) {
    errors.push('Password must include at least one symbol');
  }
  if (policy.deniedPasswords?.includes(password)) {
    errors.push('Password is on the deny list');
  }
  return errors;
}

export function defaultComplianceProfile(): ComplianceProfile {
  return {
    password: {
      minLength: 12,
      requireNumbers: true,
      requireSymbols: true,
      breachCheckEnabled: true,
    },
    retention: {
      eventRetentionDays: 365,
      piiRedactionEnabled: true,
      anonymizeAfterDays: 730,
    },
    certifications: {
      soc2: true,
      iso27001: true,
      gdpr: true,
    },
  };
}
