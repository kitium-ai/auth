import { createLogger } from '@kitiumai/logger';

export type AuditSeverity = 'info' | 'warning' | 'critical';
export type AuditCategory = 'auth' | 'governance' | 'policy' | 'provisioning' | 'runtime';

export interface AuditEvent {
  id: string;
  category: AuditCategory;
  actor: string;
  action: string;
  target?: string;
  severity: AuditSeverity;
  timestamp: Date;
  metadata?: Record<string, unknown>;
}

export interface MetricsSink {
  record: (metric: string, value: number, tags?: Record<string, string>) => Promise<void>;
}

export interface AuditExporter {
  export: (event: AuditEvent) => Promise<void>;
}

export interface AuditOptions {
  redactionFields?: string[];
  retentionDays?: number;
}

const logger = createLogger();

export class InMemoryAuditExporter implements AuditExporter {
  public events: AuditEvent[] = [];

  async export(event: AuditEvent): Promise<void> {
    this.events.push(event);
  }
}

export class ConsoleAuditExporter implements AuditExporter {
  async export(event: AuditEvent): Promise<void> {
    logger.info('Audit event', event);
  }
}

export class AuditService {
  private exporters: AuditExporter[];
  private metrics?: MetricsSink;
  private options: AuditOptions;

  constructor(exporters: AuditExporter[], options: AuditOptions = {}, metrics?: MetricsSink) {
    this.exporters = exporters;
    this.metrics = metrics;
    this.options = options;
  }

  async record(event: AuditEvent): Promise<void> {
    const sanitized = this.redact(event);
    await Promise.all(this.exporters.map((exporter) => exporter.export(sanitized)));
    if (this.metrics) {
      await this.metrics.record('auth.audit.count', 1, {
        category: sanitized.category,
        severity: sanitized.severity,
      });
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
