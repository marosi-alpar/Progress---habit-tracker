import { MailjetService } from 'src/mail/mailjet.service';
import { FirebaseService } from 'src/firebase/firebase.service';
import * as admin from 'firebase-admin';
import {
  Injectable,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { UserService } from 'src/user/user.service';

@Injectable()
export class PasswordResetService {
  constructor(
    private readonly userService: UserService,
    private readonly mailjetService: MailjetService,
    private readonly firebaseService: FirebaseService, // ✅ FirebaseService injection
  ) {}

  async sendResetPasswordEmail(email: string) {
    if (!email || !email.includes('@')) {
      throw new BadRequestException('Invalid email address');
    }

    const user = await this.userService.findOne(email);
    if (!user) throw new NotFoundException('User not found');

    // ✅ Ellenőrizzük, hogy a Firebase engedélyezett-e
    if (!this.isFirebaseAvailable()) {
      throw new BadRequestException(
        'Password reset service is currently unavailable',
      );
    }

    const actionCodeSettings = {
      url: 'https://progr3ss-czhubtascvc8ehfx.westeurope-01.azurewebsites.net/auth/reset-password-complete',
      handleCodeInApp: false,
    };

    const resetLink = await admin
      .auth()
      .generatePasswordResetLink(email, actionCodeSettings);

    // Küldjük el Mailjeten keresztül
    const html = `
      <h2>Jelszó visszaállítás</h2>
      <p>Kattints az alábbi linkre a jelszó visszaállításához:</p>
      <a href="${resetLink}">${resetLink}</a>
    `;

    await this.mailjetService.sendEmail(
      email,
      'Progr3ss - Jelszó visszaállítás',
      html,
    );

    return { message: 'Reset password email sent' };
  }

  private isFirebaseAvailable(): boolean {
    // Ellenőrizzük, hogy van-e inicializált Firebase app
    return admin.apps.length > 0;
  }
}
