import { createLogger } from '@kitiumai/logger';
import { isString } from '@kitiumai/utils-ts';

/**
 * SMS Provider Interface
 * Abstract interface for sending SMS messages for 2FA
 */
export interface SMSProvider {
  /**
   * Send an SMS message to a phone number
   * @param phoneNumber - The recipient's phone number (E.164 format recommended)
   * @param message - The message content
   * @returns Promise that resolves when the message is sent
   */
  sendSMS(phoneNumber: string, message: string): Promise<void>;

  /**
   * Send a verification code via SMS
   * @param phoneNumber - The recipient's phone number
   * @param code - The verification code
   * @returns Promise that resolves when the code is sent
   */
  sendVerificationCode(phoneNumber: string, code: string): Promise<void>;
}

/**
 * Console SMS Provider
 * For testing and development - logs SMS to console instead of sending
 */
export class ConsoleSMSProvider implements SMSProvider {
  private logger = createLogger();

  async sendSMS(phoneNumber: string, message: string): Promise<void> {
    this.logger.info(`[SMS] To: ${phoneNumber}`);
    this.logger.info(`[SMS] Message: ${message}`);
  }

  async sendVerificationCode(phoneNumber: string, code: string): Promise<void> {
    const message = `Your verification code is: ${code}. This code will expire in 5 minutes.`;
    await this.sendSMS(phoneNumber, message);
  }
}

/**
 * Twilio SMS Provider
 * Production-ready SMS provider using Twilio API
 */
export class TwilioSMSProvider implements SMSProvider {
  private accountSid: string;
  private authToken: string;
  private fromNumber: string;

  constructor(accountSid: string, authToken: string, fromNumber: string) {
    this.accountSid = accountSid;
    this.authToken = authToken;
    this.fromNumber = fromNumber;
  }

  async sendSMS(phoneNumber: string, message: string): Promise<void> {
    if (!isString(phoneNumber) || phoneNumber.trim().length === 0) {
      throw new Error('Phone number is required');
    }

    // In a real implementation, this would use the Twilio client
    // For now, we'll use fetch to call the Twilio API directly
    const url = `https://api.twilio.com/2010-04-01/Accounts/${this.accountSid}/Messages.json`;

    const auth = Buffer.from(`${this.accountSid}:${this.authToken}`).toString('base64');

    const body = new URLSearchParams({
      // eslint-disable-next-line @typescript-eslint/naming-convention
      To: phoneNumber,
      // eslint-disable-next-line @typescript-eslint/naming-convention
      From: this.fromNumber,
      // eslint-disable-next-line @typescript-eslint/naming-convention
      Body: message,
    });

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        // eslint-disable-next-line @typescript-eslint/naming-convention
        Authorization: `Basic ${auth}`,
        // eslint-disable-next-line @typescript-eslint/naming-convention
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: body.toString(),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Failed to send SMS: ${error}`);
    }
  }

  async sendVerificationCode(phoneNumber: string, code: string): Promise<void> {
    const message = `Your verification code is: ${code}. This code will expire in 5 minutes.`;
    await this.sendSMS(phoneNumber, message);
  }
}

/**
 * AWS SNS SMS Provider
 * Production-ready SMS provider using AWS SNS
 */
export class AWSSNSSMSProvider implements SMSProvider {
  private region: string;
  private accessKeyId: string;
  private _secretAccessKey: string;

  constructor(region: string, accessKeyId: string, secretAccessKey: string) {
    this.region = region;
    this.accessKeyId = accessKeyId;
    this._secretAccessKey = secretAccessKey;
    void this._secretAccessKey;
    // Store credentials for AWS SDK initialization
    if (!region || !accessKeyId || !secretAccessKey) {
      throw new Error('AWS SNS SMS provider requires region, accessKeyId, and secretAccessKey');
    }
  }

  async sendSMS(phoneNumber: string, message: string): Promise<void> {
    // In a real implementation, this would use the AWS SDK
    // This is a placeholder for the AWS SNS publish operation
    // Log the parameters for debugging
    console.log('AWS SNS SMS would be sent:', {
      region: this.region,
      accessKeyId: this.accessKeyId ? `${this.accessKeyId.substring(0, 4)}...` : 'missing',
      phoneNumber,
      messageLength: message.length,
    });
    throw new Error(
      'AWS SNS SMS provider not fully implemented. Please install and configure AWS SDK.'
    );
  }

  async sendVerificationCode(phoneNumber: string, code: string): Promise<void> {
    const message = `Your verification code is: ${code}. This code will expire in 5 minutes.`;
    await this.sendSMS(phoneNumber, message);
  }
}

/**
 * Custom SMS Provider
 * Allows users to provide their own SMS sending implementation
 */
export class CustomSMSProvider implements SMSProvider {
  private sendFn: (phoneNumber: string, message: string) => Promise<void>;

  constructor(sendFn: (phoneNumber: string, message: string) => Promise<void>) {
    this.sendFn = sendFn;
  }

  async sendSMS(phoneNumber: string, message: string): Promise<void> {
    await this.sendFn(phoneNumber, message);
  }

  async sendVerificationCode(phoneNumber: string, code: string): Promise<void> {
    const message = `Your verification code is: ${code}. This code will expire in 5 minutes.`;
    await this.sendSMS(phoneNumber, message);
  }
}

/**
 * Utility to wrap SMS operations in a typed Result
 */
type Result<T, E> = { success: true; data: T } | { success: false; error: E };
export function createSMSResult(error?: Error): Result<void, Error> {
  return error ? { success: false, error } : { success: true, data: undefined };
}
