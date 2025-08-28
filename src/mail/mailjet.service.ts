// src/mail/mailjet.service.ts
import { Injectable, Logger } from '@nestjs/common';
// eslint-disable-next-line @typescript-eslint/no-var-requires
const mailjet = require('node-mailjet');

@Injectable()
export class MailjetService {
  private readonly logger = new Logger(MailjetService.name);
  private client?: any;
  private enabled = false;
  private fromEmail?: string;
  private fromName?: string;

  constructor() {
    const key = process.env.MAILJET_API_KEY;
    const secret = process.env.MAILJET_SECRET_KEY;
    this.fromEmail = process.env.MAILJET_FROM_EMAIL;
    this.fromName = process.env.MAILJET_FROM_NAME;

    // Ha nincs minden szükséges env, a service no-op módba vált
    if (!key || !secret || !this.fromEmail || !this.fromName) {
      this.enabled = false;
      this.logger.warn(
        'Mailjet disabled: missing MAILJET_* env vars. Emails will NOT be sent.',
      );
      return;
    }

    this.client = mailjet.apiConnect(key, secret);
    this.enabled = true;
  }

  async sendEmail(to: string, subject: string, html: string) {
    if (!this.enabled || !this.client) {
      // no-op: szándékosan nem dobunk hibát
      this.logger.debug(`Skipping email to ${to} (Mailjet disabled).`);
      return;
    }

    try {
      await this.client.post('send', { version: 'v3.1' }).request({
        Messages: [
          {
            From: { Email: this.fromEmail!, Name: this.fromName! },
            To: [{ Email: to }],
            Subject: subject,
            HTMLPart: html,
          },
        ],
      });
    } catch (err) {
      this.logger.error('Mailjet send error', err as Error);
      // Ha teljes no-op kell, itt se dobj tovább hibát:
      // return;
      throw err;
    }
  }
}
