/**
 * Anomaly Detection Service
 * Detects suspicious authentication patterns and potential attacks
 */

import { getLogger } from '@kitiumai/logger';
import { StorageAdapter } from '../types';

const logger = getLogger();

/**
 * Anomaly detection configuration
 */
export interface AnomalyDetectionConfig {
  enabled: boolean;
  bruteForceThreshold?: number; // Failed attempts before blocking
  bruteForceWindow?: number; // Time window in seconds
  suspiciousIpThreshold?: number; // Requests from same IP
  suspiciousIpWindow?: number; // Time window in seconds
  botDetectionEnabled?: boolean;
  riskScoringEnabled?: boolean;
}

/**
 * Risk score factors
 */
export interface RiskFactors {
  failedAttempts: number;
  suspiciousIp: boolean;
  newDevice: boolean;
  newLocation: boolean;
  unusualTime: boolean;
  velocityCheck: boolean;
}

/**
 * Risk score result
 */
export interface RiskScore {
  score: number; // 0-100
  level: 'low' | 'medium' | 'high' | 'critical';
  factors: RiskFactors;
  recommendations: string[];
}

/**
 * Authentication attempt record
 */
export interface AuthAttempt {
  id: string;
  userId?: string;
  email?: string;
  ipAddress: string;
  userAgent?: string;
  success: boolean;
  timestamp: Date;
  provider?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Anomaly Detection Service
 */
export class AnomalyDetectionService {
  private storage: StorageAdapter;
  private config: AnomalyDetectionConfig;
  private attempts: Map<string, AuthAttempt[]> = new Map();

  constructor(storage: StorageAdapter, config: AnomalyDetectionConfig) {
    this.storage = storage;
    this.config = {
      enabled: config.enabled,
      bruteForceThreshold: config.bruteForceThreshold || 5,
      bruteForceWindow: config.bruteForceWindow || 300, // 5 minutes
      suspiciousIpThreshold: config.suspiciousIpThreshold || 10,
      suspiciousIpWindow: config.suspiciousIpWindow || 60, // 1 minute
      botDetectionEnabled: config.botDetectionEnabled ?? true,
      riskScoringEnabled: config.riskScoringEnabled ?? true,
    };
    logger.debug('AnomalyDetectionService initialized', { enabled: this.config.enabled });
  }

  /**
   * Record an authentication attempt
   */
  async recordAttempt(attempt: Omit<AuthAttempt, 'id' | 'timestamp'>): Promise<void> {
    if (!this.config.enabled) {
      return;
    }

    const authAttempt: AuthAttempt = {
      ...attempt,
      id: `attempt_${Date.now()}_${Math.random()}`,
      timestamp: new Date(),
    };

    const key = attempt.email || attempt.userId || attempt.ipAddress;
    if (!this.attempts.has(key)) {
      this.attempts.set(key, []);
    }
    this.attempts.get(key)!.push(authAttempt);

    // Clean up old attempts
    this.cleanupOldAttempts(key);

    logger.debug('Auth attempt recorded', {
      key,
      success: attempt.success,
      ipAddress: attempt.ipAddress,
    });
  }

  /**
   * Check for brute force attacks
   */
  async checkBruteForce(email?: string, userId?: string, ipAddress?: string): Promise<boolean> {
    if (!this.config.enabled) {
      return false;
    }

    const key = email || userId || ipAddress;
    if (!key) {
      return false;
    }

    const attempts = this.attempts.get(key) || [];
    const windowStart = new Date(Date.now() - this.config.bruteForceWindow! * 1000);

    const recentFailedAttempts = attempts.filter((a) => !a.success && a.timestamp > windowStart);

    const isBruteForce = recentFailedAttempts.length >= this.config.bruteForceThreshold!;

    if (isBruteForce) {
      logger.warn('Brute force attack detected', {
        key,
        failedAttempts: recentFailedAttempts.length,
        threshold: this.config.bruteForceThreshold,
      });
    }

    return isBruteForce;
  }

  /**
   * Check for suspicious IP activity
   */
  async checkSuspiciousIp(ipAddress: string): Promise<boolean> {
    if (!this.config.enabled) {
      return false;
    }

    const attempts = this.attempts.get(ipAddress) || [];
    const windowStart = new Date(Date.now() - this.config.suspiciousIpWindow! * 1000);

    const recentAttempts = attempts.filter((a) => a.timestamp > windowStart);

    const isSuspicious = recentAttempts.length >= this.config.suspiciousIpThreshold!;

    if (isSuspicious) {
      logger.warn('Suspicious IP activity detected', {
        ipAddress,
        attempts: recentAttempts.length,
        threshold: this.config.suspiciousIpThreshold,
      });
    }

    return isSuspicious;
  }

  /**
   * Calculate risk score for an authentication attempt
   */
  async calculateRiskScore(
    email?: string,
    userId?: string,
    ipAddress?: string,
    userAgent?: string,
    metadata?: Record<string, unknown>
  ): Promise<RiskScore> {
    if (!this.config.enabled || !this.config.riskScoringEnabled) {
      return {
        score: 0,
        level: 'low',
        factors: {
          failedAttempts: 0,
          suspiciousIp: false,
          newDevice: false,
          newLocation: false,
          unusualTime: false,
          velocityCheck: false,
        },
        recommendations: [],
      };
    }

    const key = email || userId || ipAddress;
    const attempts = key ? this.attempts.get(key) || [] : [];
    const windowStart = new Date(Date.now() - 3600000); // 1 hour
    const recentAttempts = attempts.filter((a) => a.timestamp > windowStart);

    const failedAttempts = recentAttempts.filter((a) => !a.success).length;
    const suspiciousIp = ipAddress ? await this.checkSuspiciousIp(ipAddress) : false;
    const newDevice = metadata?.newDevice === true;
    const newLocation = metadata?.newLocation === true;
    const unusualTime = this.checkUnusualTime();
    const velocityCheck = recentAttempts.length > 20; // Too many requests

    const factors: RiskFactors = {
      failedAttempts,
      suspiciousIp,
      newDevice,
      newLocation,
      unusualTime,
      velocityCheck,
    };

    let score = 0;
    const recommendations: string[] = [];

    if (failedAttempts > 3) {
      score += 20;
      recommendations.push('Multiple failed login attempts detected');
    }
    if (suspiciousIp) {
      score += 30;
      recommendations.push('Suspicious IP address activity');
    }
    if (newDevice) {
      score += 15;
      recommendations.push('New device detected');
    }
    if (newLocation) {
      score += 15;
      recommendations.push('New location detected');
    }
    if (unusualTime) {
      score += 10;
      recommendations.push('Unusual login time');
    }
    if (velocityCheck) {
      score += 20;
      recommendations.push('High request velocity detected');
    }

    let level: 'low' | 'medium' | 'high' | 'critical';
    if (score >= 70) {
      level = 'critical';
    } else if (score >= 50) {
      level = 'high';
    } else if (score >= 30) {
      level = 'medium';
    } else {
      level = 'low';
    }

    return {
      score,
      level,
      factors,
      recommendations,
    };
  }

  /**
   * Check if login time is unusual
   */
  private checkUnusualTime(): boolean {
    const hour = new Date().getHours();
    // Consider 2 AM - 5 AM as unusual
    return hour >= 2 && hour <= 5;
  }

  /**
   * Clean up old attempts
   */
  private cleanupOldAttempts(key: string): void {
    const attempts = this.attempts.get(key);
    if (!attempts) {
      return;
    }

    const cutoff = new Date(Date.now() - 3600000); // 1 hour
    const filtered = attempts.filter((a) => a.timestamp > cutoff);

    if (filtered.length === 0) {
      this.attempts.delete(key);
    } else {
      this.attempts.set(key, filtered);
    }
  }

  /**
   * Get authentication attempt history
   */
  async getAttemptHistory(
    email?: string,
    userId?: string,
    ipAddress?: string,
    limit: number = 100
  ): Promise<AuthAttempt[]> {
    const key = email || userId || ipAddress;
    if (!key) {
      return [];
    }

    const attempts = this.attempts.get(key) || [];
    return attempts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime()).slice(0, limit);
  }
}
