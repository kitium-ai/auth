/**
 * Conditional Access Policies
 * Location, device, time-based access control
 */

import { getLogger } from '@kitiumai/logger';
import { ValidationError, AuthorizationError } from '../errors';

const logger = getLogger();

/**
 * Conditional access policy type
 */
export type ConditionalAccessPolicyType =
  | 'location'
  | 'device'
  | 'time'
  | 'ip_range'
  | 'mfa_required'
  | 'risk_level';

/**
 * Location-based policy
 */
export interface LocationPolicy {
  type: 'location';
  allowedCountries?: string[]; // ISO 3166-1 alpha-2 codes
  blockedCountries?: string[];
  allowedRegions?: string[];
  blockedRegions?: string[];
}

/**
 * Device-based policy
 */
export interface DevicePolicy {
  type: 'device';
  requireDeviceTrust?: boolean;
  allowedDeviceIds?: string[];
  blockedDeviceIds?: string[];
  requireDeviceRegistration?: boolean;
}

/**
 * Time-based policy
 */
export interface TimePolicy {
  type: 'time';
  allowedDays?: number[]; // 0 = Sunday, 6 = Saturday
  allowedHours?: { start: number; end: number }[]; // 0-23
  timezone?: string;
}

/**
 * IP range policy
 */
export interface IpRangePolicy {
  type: 'ip_range';
  allowedIpRanges?: string[]; // CIDR notation
  blockedIpRanges?: string[];
}

/**
 * MFA requirement policy
 */
export interface MfaRequiredPolicy {
  type: 'mfa_required';
  requireMfa: boolean;
  mfaMethods?: ('totp' | 'sms' | 'webauthn')[];
}

/**
 * Risk level policy
 */
export interface RiskLevelPolicy {
  type: 'risk_level';
  maxRiskLevel: 'low' | 'medium' | 'high' | 'critical';
  requireMfaForHighRisk?: boolean;
  blockCriticalRisk?: boolean;
}

/**
 * Conditional access policy
 */
export type ConditionalAccessPolicy =
  | LocationPolicy
  | DevicePolicy
  | TimePolicy
  | IpRangePolicy
  | MfaRequiredPolicy
  | RiskLevelPolicy;

/**
 * Policy evaluation context
 */
export interface PolicyEvaluationContext {
  userId: string;
  orgId?: string;
  ipAddress?: string;
  country?: string;
  region?: string;
  deviceId?: string;
  deviceTrusted?: boolean;
  deviceRegistered?: boolean;
  timestamp?: Date;
  riskLevel?: 'low' | 'medium' | 'high' | 'critical';
  mfaMethods?: string[];
}

/**
 * Policy evaluation result
 */
export interface PolicyEvaluationResult {
  allowed: boolean;
  reason?: string;
  requiredActions?: string[];
  policies: Array<{
    policy: ConditionalAccessPolicy;
    allowed: boolean;
    reason?: string;
  }>;
}

/**
 * Conditional Access Service
 */
export class ConditionalAccessService {
  private policies: Map<string, ConditionalAccessPolicy[]> = new Map();

  /**
   * Add a policy for an organization or user
   */
  addPolicy(orgIdOrUserId: string, policy: ConditionalAccessPolicy, priority?: number): void {
    if (!this.policies.has(orgIdOrUserId)) {
      this.policies.set(orgIdOrUserId, []);
    }
    this.policies.get(orgIdOrUserId)!.push(policy);
    logger.debug('Conditional access policy added', { orgIdOrUserId, type: policy.type });
  }

  /**
   * Remove a policy
   */
  removePolicy(orgIdOrUserId: string, policyType: ConditionalAccessPolicyType): void {
    const policies = this.policies.get(orgIdOrUserId);
    if (policies) {
      const filtered = policies.filter((p) => p.type !== policyType);
      this.policies.set(orgIdOrUserId, filtered);
      logger.debug('Conditional access policy removed', { orgIdOrUserId, policyType });
    }
  }

  /**
   * Get policies for an organization or user
   */
  getPolicies(orgIdOrUserId: string): ConditionalAccessPolicy[] {
    return this.policies.get(orgIdOrUserId) || [];
  }

  /**
   * Evaluate policies for a context
   */
  async evaluatePolicies(context: PolicyEvaluationContext): Promise<PolicyEvaluationResult> {
    const orgId = context.orgId || 'default';
    const userId = context.userId;
    const policies = [...this.getPolicies(orgId), ...this.getPolicies(userId)];

    if (policies.length === 0) {
      return {
        allowed: true,
        policies: [],
      };
    }

    const results: PolicyEvaluationResult['policies'] = [];
    let allowed = true;
    const requiredActions: string[] = [];

    for (const policy of policies) {
      const result = this.evaluatePolicy(policy, context);
      results.push({
        policy,
        allowed: result.allowed,
        reason: result.reason,
      });

      if (!result.allowed) {
        allowed = false;
      }

      if (result.requiredActions) {
        requiredActions.push(...result.requiredActions);
      }
    }

    return {
      allowed,
      reason: allowed ? undefined : 'One or more policies blocked access',
      requiredActions: requiredActions.length > 0 ? requiredActions : undefined,
      policies: results,
    };
  }

  /**
   * Evaluate a single policy
   */
  private evaluatePolicy(
    policy: ConditionalAccessPolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string; requiredActions?: string[] } {
    switch (policy.type) {
      case 'location':
        return this.evaluateLocationPolicy(policy, context);
      case 'device':
        return this.evaluateDevicePolicy(policy, context);
      case 'time':
        return this.evaluateTimePolicy(policy, context);
      case 'ip_range':
        return this.evaluateIpRangePolicy(policy, context);
      case 'mfa_required':
        return this.evaluateMfaRequiredPolicy(policy, context);
      case 'risk_level':
        return this.evaluateRiskLevelPolicy(policy, context);
      default:
        return { allowed: true };
    }
  }

  /**
   * Evaluate location policy
   */
  private evaluateLocationPolicy(
    policy: LocationPolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string } {
    if (!context.country) {
      return { allowed: true }; // No location data, allow
    }

    if (policy.blockedCountries?.includes(context.country)) {
      return {
        allowed: false,
        reason: `Country ${context.country} is blocked`,
      };
    }

    if (policy.allowedCountries && !policy.allowedCountries.includes(context.country)) {
      return {
        allowed: false,
        reason: `Country ${context.country} is not in allowed list`,
      };
    }

    return { allowed: true };
  }

  /**
   * Evaluate device policy
   */
  private evaluateDevicePolicy(
    policy: DevicePolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string; requiredActions?: string[] } {
    if (policy.requireDeviceTrust && !context.deviceTrusted) {
      return {
        allowed: false,
        reason: 'Device trust required',
        requiredActions: ['register_device'],
      };
    }

    if (policy.requireDeviceRegistration && !context.deviceRegistered) {
      return {
        allowed: false,
        reason: 'Device registration required',
        requiredActions: ['register_device'],
      };
    }

    if (policy.blockedDeviceIds?.includes(context.deviceId || '')) {
      return {
        allowed: false,
        reason: 'Device is blocked',
      };
    }

    if (
      policy.allowedDeviceIds &&
      context.deviceId &&
      !policy.allowedDeviceIds.includes(context.deviceId)
    ) {
      return {
        allowed: false,
        reason: 'Device is not in allowed list',
      };
    }

    return { allowed: true };
  }

  /**
   * Evaluate time policy
   */
  private evaluateTimePolicy(
    policy: TimePolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string } {
    const timestamp = context.timestamp || new Date();
    const day = timestamp.getDay();
    const hour = timestamp.getHours();

    if (policy.allowedDays && !policy.allowedDays.includes(day)) {
      return {
        allowed: false,
        reason: `Day ${day} is not in allowed days`,
      };
    }

    if (policy.allowedHours) {
      const isAllowed = policy.allowedHours.some(
        (range) => hour >= range.start && hour <= range.end
      );
      if (!isAllowed) {
        return {
          allowed: false,
          reason: `Hour ${hour} is not in allowed hours`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Evaluate IP range policy
   */
  private evaluateIpRangePolicy(
    policy: IpRangePolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string } {
    if (!context.ipAddress) {
      return { allowed: true };
    }

    // Simple CIDR check (simplified - would need proper CIDR library in production)
    if (policy.blockedIpRanges) {
      for (const range of policy.blockedIpRanges) {
        if (this.isIpInRange(context.ipAddress, range)) {
          return {
            allowed: false,
            reason: `IP ${context.ipAddress} is in blocked range ${range}`,
          };
        }
      }
    }

    if (policy.allowedIpRanges && policy.allowedIpRanges.length > 0) {
      const isAllowed = policy.allowedIpRanges.some((range) =>
        this.isIpInRange(context.ipAddress!, range)
      );
      if (!isAllowed) {
        return {
          allowed: false,
          reason: `IP ${context.ipAddress} is not in allowed ranges`,
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Evaluate MFA required policy
   */
  private evaluateMfaRequiredPolicy(
    policy: MfaRequiredPolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string; requiredActions?: string[] } {
    if (!policy.requireMfa) {
      return { allowed: true };
    }

    if (!context.mfaMethods || context.mfaMethods.length === 0) {
      return {
        allowed: false,
        reason: 'MFA is required but not configured',
        requiredActions: ['enable_mfa'],
      };
    }

    if (policy.mfaMethods) {
      const hasRequiredMethod = policy.mfaMethods.some((method) =>
        context.mfaMethods?.includes(method)
      );
      if (!hasRequiredMethod) {
        return {
          allowed: false,
          reason: 'Required MFA method not configured',
          requiredActions: ['enable_mfa'],
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Evaluate risk level policy
   */
  private evaluateRiskLevelPolicy(
    policy: RiskLevelPolicy,
    context: PolicyEvaluationContext
  ): { allowed: boolean; reason?: string; requiredActions?: string[] } {
    if (!context.riskLevel) {
      return { allowed: true };
    }

    const riskLevels = ['low', 'medium', 'high', 'critical'];
    const currentRiskIndex = riskLevels.indexOf(context.riskLevel);
    const maxRiskIndex = riskLevels.indexOf(policy.maxRiskLevel);

    if (currentRiskIndex > maxRiskIndex) {
      if (policy.blockCriticalRisk && context.riskLevel === 'critical') {
        return {
          allowed: false,
          reason: 'Critical risk level - access blocked',
        };
      }

      if (policy.requireMfaForHighRisk) {
        return {
          allowed: false,
          reason: 'High risk level - MFA required',
          requiredActions: ['verify_mfa'],
        };
      }
    }

    return { allowed: true };
  }

  /**
   * Check if IP is in CIDR range (simplified)
   */
  private isIpInRange(ip: string, cidr: string): boolean {
    // Simplified implementation - would need proper CIDR library
    if (cidr.includes('/')) {
      const [rangeIp, prefix] = cidr.split('/');
      return ip.startsWith(
        rangeIp
          .split('.')
          .slice(0, parseInt(prefix) / 8)
          .join('.')
      );
    }
    return ip === cidr;
  }
}
