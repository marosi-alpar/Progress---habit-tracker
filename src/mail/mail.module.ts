// src/mail/mail.module.ts
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MailjetService } from './mailjet.service';
import { NoopMailjetService } from './noop-mailjet.service';

@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: MailjetService,
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => {
        const key = cfg.get<string>('MAILJET_API_KEY');
        const secret = cfg.get<string>('MAILJET_SECRET_KEY');
        const fromEmail = cfg.get<string>('MAILJET_FROM_EMAIL');
        const fromName = cfg.get<string>('MAILJET_FROM_NAME');

        // Ha bármelyik hiányzik: no-op
        if (!key || !secret || !fromEmail || !fromName) {
          return new NoopMailjetService() as unknown as MailjetService;
        }

        // Minden megvan → valódi service (0 paraméter!)
        return new MailjetService();
      },
    },
  ],
  exports: [MailjetService],
})
export class MailModule {}
