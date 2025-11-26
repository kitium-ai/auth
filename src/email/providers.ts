/**
 * Email providers
 */

export interface EmailProvider {
  send(to: string, subject: string, html: string): Promise<void>;
}

export class SMTPEmailProvider implements EmailProvider {
  async send(_to: string, _subject: string, _html: string): Promise<void> {}
}

export class SendGridEmailProvider implements EmailProvider {
  async send(_to: string, _subject: string, _html: string): Promise<void> {}
}

export class MailgunEmailProvider implements EmailProvider {
  async send(_to: string, _subject: string, _html: string): Promise<void> {}
}

export class ResendEmailProvider implements EmailProvider {
  async send(_to: string, _subject: string, _html: string): Promise<void> {}
}

export class MockEmailProvider implements EmailProvider {
  async send(_to: string, _subject: string, _html: string): Promise<void> {}
}

export async function createEmailProvider(_config: any): Promise<EmailProvider> {
  return new MockEmailProvider();
}
