/* eslint-disable @typescript-eslint/naming-convention */
import https from 'node:https';
import path from 'node:path';
import { Buffer } from 'node:buffer';
import fs from 'fs-extra';
import { getLogger } from '@kitiumai/logger';

export interface EmailProvider {
  send(to: string, subject: string, html: string): Promise<void>;
}

export interface EmailMessage {
  to: string;
  subject: string;
  html: string;
  sentAt: Date;
  provider: string;
}

export interface EmailProviderFactoryConfig {
  type?: string;
  from?: string;
  apiKey?: string;
  domain?: string;
  outputDir?: string;
  baseUrl?: string;
  [key: string]: unknown;
}

const logger = getLogger();

abstract class BaseEmailProvider implements EmailProvider {
  protected constructor(private readonly providerName: string) {}

  abstract send(to: string, subject: string, html: string): Promise<void>;

  protected logDelivery(to: string, subject: string): void {
    logger.info(`Email sent via ${this.providerName}`, { to, subject });
  }
}

export interface SMTPEmailProviderConfig {
  from?: string;
  outputDir?: string;
}

/**
 * Simple SMTP provider that spools messages to disk. External agents can read the .eml
 * files and forward them through a real SMTP service.
 */
export class SMTPEmailProvider extends BaseEmailProvider {
  constructor(private readonly config: SMTPEmailProviderConfig = {}) {
    super('smtp');
  }

  async send(to: string, subject: string, html: string): Promise<void> {
    const dir = this.config.outputDir || path.join(process.cwd(), '.kitium', 'emails');
    await fs.ensureDir(dir);
    const sanitized = to.replace(/[^a-z0-9]/gi, '_');
    const filename = path.join(dir, `${Date.now()}_${sanitized}.eml`);
    const contents = [
      `From: ${this.config.from || 'no-reply@localhost'}`,
      `To: ${to}`,
      `Subject: ${subject}`,
      'Content-Type: text/html; charset=utf-8',
      '',
      html,
    ].join('\r\n');

    await fs.writeFile(filename, contents, 'utf8');
    this.logDelivery(to, subject);
  }
}

export interface SendGridEmailProviderConfig {
  apiKey: string;
  from: string;
}

export class SendGridEmailProvider extends BaseEmailProvider {
  constructor(private readonly config: SendGridEmailProviderConfig) {
    super('sendgrid');
  }

  async send(to: string, subject: string, html: string): Promise<void> {
    const payload = {
      personalizations: [{ to: [{ email: to }], subject }],
      from: { email: this.config.from },
      content: [{ type: 'text/html', value: html }],
    };

    await postJson('https://api.sendgrid.com/v3/mail/send', payload, {
      Authorization: `Bearer ${this.config.apiKey}`,
    });

    this.logDelivery(to, subject);
  }
}

export interface MailgunEmailProviderConfig {
  apiKey: string;
  domain: string;
  from: string;
}

export class MailgunEmailProvider extends BaseEmailProvider {
  constructor(private readonly config: MailgunEmailProviderConfig) {
    super('mailgun');
  }

  async send(to: string, subject: string, html: string): Promise<void> {
    const params = new URLSearchParams();
    params.set('from', this.config.from);
    params.set('to', to);
    params.set('subject', subject);
    params.set('html', html);

    await postForm(`https://api.mailgun.net/v3/${this.config.domain}/messages`, params, {
      Authorization: `Basic ${Buffer.from(`api:${this.config.apiKey}`).toString('base64')}`,
    });

    this.logDelivery(to, subject);
  }
}

export interface ResendEmailProviderConfig {
  apiKey: string;
  from: string;
}

export class ResendEmailProvider extends BaseEmailProvider {
  constructor(private readonly config: ResendEmailProviderConfig) {
    super('resend');
  }

  async send(to: string, subject: string, html: string): Promise<void> {
    const payload = {
      from: this.config.from,
      to: [to],
      subject,
      html,
    };

    await postJson('https://api.resend.com/emails', payload, {
      Authorization: `Bearer ${this.config.apiKey}`,
    });

    this.logDelivery(to, subject);
  }
}

export class MockEmailProvider extends BaseEmailProvider {
  private readonly sent: EmailMessage[] = [];

  constructor(private readonly storeResults: boolean = true) {
    super('mock');
  }

  async send(to: string, subject: string, html: string): Promise<void> {
    if (this.storeResults) {
      this.sent.push({
        to,
        subject,
        html,
        sentAt: new Date(),
        provider: 'mock',
      });
    }

    this.logDelivery(to, subject);
  }

  getSentMessages(): EmailMessage[] {
    return [...this.sent];
  }
}

export async function createEmailProvider(
  config?: EmailProviderFactoryConfig
): Promise<EmailProvider> {
  if (!config || !config.type) {
    return new MockEmailProvider();
  }

  const type = String(config.type).toLowerCase();
  switch (type) {
    case 'smtp':
      return new SMTPEmailProvider({
        from: config.from as string | undefined,
        outputDir: config.outputDir as string | undefined,
      });
    case 'sendgrid':
      assertRequired(config.apiKey, 'apiKey', 'SendGrid');
      assertRequired(config.from, 'from', 'SendGrid');
      return new SendGridEmailProvider({
        apiKey: String(config.apiKey),
        from: String(config.from),
      });
    case 'mailgun':
      assertRequired(config.apiKey, 'apiKey', 'Mailgun');
      assertRequired(config.from, 'from', 'Mailgun');
      assertRequired(config.domain, 'domain', 'Mailgun');
      return new MailgunEmailProvider({
        apiKey: String(config.apiKey),
        domain: String(config.domain),
        from: String(config.from),
      });
    case 'resend':
      assertRequired(config.apiKey, 'apiKey', 'Resend');
      assertRequired(config.from, 'from', 'Resend');
      return new ResendEmailProvider({
        apiKey: String(config.apiKey),
        from: String(config.from),
      });
    default:
      logger.warn(`Unknown email provider type "${type}", using mock provider`);
      return new MockEmailProvider();
  }
}

function assertRequired(value: unknown, field: string, providerName: string): asserts value {
  if (!value) {
    throw new Error(`${providerName} configuration requires "${field}"`);
  }
}

async function postJson(
  url: string,
  payload: Record<string, unknown>,
  headers: Record<string, string>
): Promise<void> {
  const body = JSON.stringify(payload);
  await httpRequest(url, body, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body).toString(),
    ...headers,
  });
}

async function postForm(
  url: string,
  payload: URLSearchParams,
  headers: Record<string, string>
): Promise<void> {
  const body = payload.toString();
  await httpRequest(url, body, {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(body).toString(),
    ...headers,
  });
}

async function httpRequest(
  url: string,
  body: string,
  headers: Record<string, string>
): Promise<void> {
  const target = new URL(url);
  await new Promise<void>((resolve, reject) => {
    const request = https.request(
      {
        method: 'POST',
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        headers,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          if ((response.statusCode ?? 500) >= 400) {
            const message = Buffer.concat(chunks).toString('utf8');
            reject(new Error(`Email provider request failed: ${response.statusCode} ${message}`));
            return;
          }
          resolve();
        });
      }
    );

    request.on('error', reject);
    request.write(body);
    request.end();
  });
}
