import { getLogger, getMetricsRegistry } from '@kitiumai/logger';
import { err, ok } from '@kitiumai/utils-ts/runtime/result';

import { createError } from '../errors';
import type { Result } from '@kitiumai/utils-ts/types/result';

export type AuditSeverity = 'info' | 'warning' | 'critical';
export type AuditCategory = 'auth' | 'governance' | 'policy' | 'provisioning' | 'runtime';

export type AuditEvent = {
  id: string;
  category: AuditCategory;
  actor: string;
  action: string;
  target?: string;
  severity: AuditSeverity;
  timestamp: Date;
  metadata?: Record<string, unknown>;
};

export type MetricsSink = {
  record: (metric: string, value: number, tags?: Record<string, string>) => Promise<void>;
};

export type AuditExporter = {
  export: (event: AuditEvent) => Promise<Result<void>>;
};

export type AuditOptions = {
  redactionFields?: string[];
  retentionDays?: number;
};

const logger = getLogger();

export class InMemoryAuditExporter implements AuditExporter {
  public events: AuditEvent[] = [];

  async export(event: AuditEvent): Promise<Result<void>> {
    try {
      this.events.push(event);
      return ok(undefined);
    } catch (error) {
      logger.error('Failed to export audit event to memory', {
        error: String(error),
        eventId: event.id,
      });
      return err(
        createError('auth/audit_export_failed', {
          cause: error as Error,
          context: { operation: 'memoryExport', eventId: event.id },
        })
      );
    }
  }
}

export class ConsoleAuditExporter implements AuditExporter {
  async export(event: AuditEvent): Promise<Result<void>> {
    try {
      logger.info('Audit event', event);
      return ok(undefined);
    } catch (error) {
      logger.error('Failed to export audit event to console', {
        error: String(error),
        eventId: event.id,
      });
      return err(
        createError('auth/audit_export_failed', {
          cause: error as Error,
          context: { operation: 'consoleExport', eventId: event.id },
        })
      );
    }
  }
}

export class AuditService {
  private readonly logger = getLogger();
  private readonly exporters: AuditExporter[];
  private readonly metrics?: MetricsSink;
  private readonly options: AuditOptions;

  constructor(exporters: AuditExporter[], options: AuditOptions = {}, metrics?: MetricsSink) {
    this.exporters = exporters;
    this.metrics = metrics;
    this.options = options;
  }

  async record(event: AuditEvent): Promise<Result<void>> {
    try {
      const sanitized = this.redact(event);

      // Export to all exporters and collect results
      const exportResults = await Promise.all(
        this.exporters.map((exporter) => exporter.export(sanitized))
      );

      // Check if any exporter failed
      for (const result of exportResults) {
        if (!result.ok) {
          return result;
        }
      }

      // Record metrics using modern logger metrics registry
      try {
        const metricsRegistry = getMetricsRegistry();
        if (metricsRegistry) {
          const counter = metricsRegistry.registerCounter(
            'auth.audit.events_total',
            'Audit events recorded'
          );
          counter.inc(1, {
            category: sanitized.category,
            severity: sanitized.severity,
            source: 'audit_service',
          });
        }
      } catch (metricsError) {
        this.logger.debug('Failed to record audit metrics', { error: String(metricsError) });
      }

      // Also support legacy metrics sink if provided
      if (this.metrics) {
        try {
          await this.metrics.record('auth.audit.count', 1, {
            category: sanitized.category,
            severity: sanitized.severity,
          });
        } catch (metricsError) {
          this.logger.debug('Failed to record metrics via sink', { error: String(metricsError) });
        }
      }

      return ok(undefined);
    } catch (error) {
      this.logger.error('Failed to record audit event', {
        error: String(error),
        eventId: event.id,
      });
      return err(
        createError('auth/audit_record_failed', {
          cause: error as Error,
          context: { eventId: event.id, category: event.category },
        })
      );
    }
  }

  private redact(event: AuditEvent): AuditEvent {
    if (!this.options.redactionFields?.length) {
      return event;
    }

    const metadata = { ...event.metadata };
    for (const field of this.options.redactionFields) {
      if (metadata && Object.prototype.hasOwnProperty.call(metadata, field)) {
        metadata[field] = '[REDACTED]';
      }
    }

    return { ...event, metadata };
  }
}

export function createDefaultAuditService(): AuditService {
  const exporter = new ConsoleAuditExporter();
  return new AuditService([exporter], { redactionFields: ['password', 'token'] });
}

