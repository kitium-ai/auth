/**
 * Access Reviews and Certification
 * Periodic access certification and review workflows
 */

import { nanoid } from 'nanoid';
import { getLogger } from '@kitiumai/logger';
import { StorageAdapter } from '../types';
import { ValidationError, AuthorizationError } from '../errors';

const logger = getLogger();

/**
 * Access review status
 */
export type AccessReviewStatus = 'pending' | 'approved' | 'rejected' | 'expired';

/**
 * Access review type
 */
export type AccessReviewType = 'user' | 'role' | 'api_key' | 'organization_member';

/**
 * Access review
 */
export interface AccessReview {
  id: string;
  orgId: string;
  type: AccessReviewType;
  resourceId: string; // userId, roleId, apiKeyId, etc.
  reviewerId: string;
  status: AccessReviewStatus;
  comments?: string;
  createdAt: Date;
  expiresAt: Date;
  reviewedAt?: Date;
  metadata?: Record<string, unknown>;
}

/**
 * Access review campaign
 */
export interface AccessReviewCampaign {
  id: string;
  orgId: string;
  name: string;
  description?: string;
  type: AccessReviewType;
  schedule?: {
    frequency: 'monthly' | 'quarterly' | 'yearly';
    dayOfMonth?: number;
  };
  autoApprove?: boolean;
  autoApproveAfterDays?: number;
  reviewers: string[]; // User IDs who can review
  status: 'draft' | 'active' | 'completed' | 'cancelled';
  createdAt: Date;
  startedAt?: Date;
  completedAt?: Date;
  metadata?: Record<string, unknown>;
}

/**
 * Access Review Service
 */
export class AccessReviewService {
  private storage: StorageAdapter;
  private reviews: Map<string, AccessReview> = new Map();
  private campaigns: Map<string, AccessReviewCampaign> = new Map();

  constructor(storage: StorageAdapter) {
    this.storage = storage;
    logger.debug('AccessReviewService initialized');
  }

  /**
   * Create an access review campaign
   */
  async createCampaign(
    orgId: string,
    name: string,
    type: AccessReviewType,
    reviewers: string[],
    options?: {
      description?: string;
      schedule?: AccessReviewCampaign['schedule'];
      autoApprove?: boolean;
      autoApproveAfterDays?: number;
    }
  ): Promise<AccessReviewCampaign> {
    const campaignId = `campaign_${nanoid()}`;
    const now = new Date();

    const campaign: AccessReviewCampaign = {
      id: campaignId,
      orgId,
      name,
      description: options?.description,
      type,
      schedule: options?.schedule,
      autoApprove: options?.autoApprove || false,
      autoApproveAfterDays: options?.autoApproveAfterDays,
      reviewers,
      status: 'draft',
      createdAt: now,
      metadata: {},
    };

    this.campaigns.set(campaignId, campaign);
    logger.info('Access review campaign created', { campaignId, orgId, type });

    return campaign;
  }

  /**
   * Start an access review campaign
   */
  async startCampaign(campaignId: string): Promise<AccessReview[]> {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) {
      throw new ValidationError({
        code: 'auth/campaign_not_found',
        message: `Campaign not found: ${campaignId}`,
        context: { campaignId },
      });
    }

    if (campaign.status !== 'draft') {
      throw new ValidationError({
        code: 'auth/campaign_not_draft',
        message: 'Campaign is not in draft status',
      });
    }

    campaign.status = 'active';
    campaign.startedAt = new Date();

    // Generate reviews based on campaign type
    const reviews = await this.generateReviewsForCampaign(campaign);

    logger.info('Access review campaign started', {
      campaignId,
      reviewCount: reviews.length,
    });

    return reviews;
  }

  /**
   * Generate reviews for a campaign
   */
  private async generateReviewsForCampaign(
    campaign: AccessReviewCampaign
  ): Promise<AccessReview[]> {
    const reviews: AccessReview[] = [];
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 30); // 30 days to review

    // In production, fetch resources based on campaign type
    // For now, return empty array
    const resourceIds: string[] = [];

    for (const resourceId of resourceIds) {
      for (const reviewerId of campaign.reviewers) {
        const review: AccessReview = {
          id: `review_${nanoid()}`,
          orgId: campaign.orgId,
          type: campaign.type,
          resourceId,
          reviewerId,
          status: 'pending',
          createdAt: new Date(),
          expiresAt,
        };

        this.reviews.set(review.id, review);
        reviews.push(review);
      }
    }

    return reviews;
  }

  /**
   * Review an access review
   */
  async reviewAccess(
    reviewId: string,
    reviewerId: string,
    status: 'approved' | 'rejected',
    comments?: string
  ): Promise<AccessReview> {
    const review = this.reviews.get(reviewId);
    if (!review) {
      throw new ValidationError(`Review not found: ${reviewId}`);
    }

    if (review.reviewerId !== reviewerId) {
      throw new AuthorizationError({
        code: 'auth/review_unauthorized',
        message: 'Not authorized to review this access',
      });
    }

    if (review.status !== 'pending') {
      throw new ValidationError({
        code: 'auth/review_not_pending',
        message: 'Review is not pending',
      });
    }

    if (new Date() > review.expiresAt) {
      review.status = 'expired';
      throw new ValidationError({
        code: 'auth/review_expired',
        message: 'Review has expired',
      });
    }

    review.status = status;
    review.comments = comments;
    review.reviewedAt = new Date();

    logger.info('Access review completed', { reviewId, status, reviewerId });

    return review;
  }

  /**
   * Get pending reviews for a reviewer
   */
  async getPendingReviews(reviewerId: string, orgId?: string): Promise<AccessReview[]> {
    const reviews = Array.from(this.reviews.values()).filter(
      (r) =>
        r.reviewerId === reviewerId &&
        r.status === 'pending' &&
        (!orgId || r.orgId === orgId) &&
        new Date() <= r.expiresAt
    );

    return reviews.sort((a, b) => a.expiresAt.getTime() - b.expiresAt.getTime());
  }

  /**
   * Get reviews for a resource
   */
  async getReviewsForResource(
    resourceId: string,
    type: AccessReviewType,
    orgId?: string
  ): Promise<AccessReview[]> {
    return Array.from(this.reviews.values()).filter(
      (r) => r.resourceId === resourceId && r.type === type && (!orgId || r.orgId === orgId)
    );
  }

  /**
   * Auto-approve expired reviews
   */
  async autoApproveExpiredReviews(campaignId: string): Promise<number> {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign || !campaign.autoApprove) {
      return 0;
    }

    const reviews = Array.from(this.reviews.values()).filter(
      (r) =>
        r.orgId === campaign.orgId &&
        r.type === campaign.type &&
        r.status === 'pending' &&
        new Date() > r.expiresAt
    );

    let count = 0;
    for (const review of reviews) {
      review.status = 'approved';
      review.reviewedAt = new Date();
      review.comments = 'Auto-approved after expiration';
      count++;
    }

    logger.info('Auto-approved expired reviews', { campaignId, count });
    return count;
  }

  /**
   * Complete a campaign
   */
  async completeCampaign(campaignId: string): Promise<void> {
    const campaign = this.campaigns.get(campaignId);
    if (!campaign) {
      throw new ValidationError({
        code: 'auth/campaign_not_found',
        message: `Campaign not found: ${campaignId}`,
        context: { campaignId },
      });
    }

    const pendingReviews = Array.from(this.reviews.values()).filter(
      (r) => r.orgId === campaign.orgId && r.status === 'pending'
    );

    if (pendingReviews.length > 0) {
      throw new ValidationError({
        code: 'auth/campaign_has_pending_reviews',
        message: 'Campaign has pending reviews',
      });
    }

    campaign.status = 'completed';
    campaign.completedAt = new Date();

    logger.info('Access review campaign completed', { campaignId });
  }

  /**
   * Get campaign
   */
  async getCampaign(campaignId: string): Promise<AccessReviewCampaign | null> {
    return this.campaigns.get(campaignId) || null;
  }

  /**
   * List campaigns
   */
  async listCampaigns(orgId?: string): Promise<AccessReviewCampaign[]> {
    return Array.from(this.campaigns.values()).filter((c) => !orgId || c.orgId === orgId);
  }
}
