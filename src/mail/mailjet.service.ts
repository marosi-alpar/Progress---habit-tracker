// src/mail/mailjet.service.ts
import { Injectable } from '@nestjs/common';
// @ts-ignore következő sorra, különben TS hibát ad CommonJS miatt
// eslint-disable-next-line @typescript-eslint/no-var-requires
const mailjet = require('node-mailjet');

@Injectable()
export class MailjetService {
  private client: any;

  constructor() {
    this.client = mailjet.apiConnect(
      process.env.MAILJET_API_KEY!,
      process.env.MAILJET_SECRET_KEY!,
    );
  }

  async sendEmail(to: string, subject: string, html: string) {
    try {
      const request = await this.client
        .post('send', { version: 'v3.1' })
        .request({
          Messages: [
            {
              From: {
                Email: process.env.MAILJET_FROM_EMAIL!,
                Name: process.env.MAILJET_FROM_NAME!,
              },
              To: [{ Email: to }],
              Subject: subject,
              HTMLPart: html,
            },
          ],
        });

      // console.log('✅ Mailjet response:', request.body);
    } catch (err) {
      console.error('❌ Mailjet send error:', err);
      throw err;
    }
  }
}
