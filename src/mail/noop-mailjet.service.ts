// src/mail/noop-mailjet.service.ts
export class NoopMailjetService {
  async send(..._args: any[]) { /* no-op */ }
  async sendResetPasswordEmail(..._args: any[]) { /* no-op */ }
  // ha van még publikus metódus, ide teheted
}
