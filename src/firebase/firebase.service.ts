// src/firebase/firebase.service.ts
import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as path from 'path';
import * as fs from 'fs';

@Injectable()
export class FirebaseService implements OnModuleInit {
  private readonly logger = new Logger(FirebaseService.name);
  private enabled = false;

  onModuleInit() {
    try {
      // 1) ENV-ből base64 (opcionális, nem kötelező)
      const b64 = process.env.FIREBASE_CREDENTIALS_B64;
      if (b64) {
        const creds = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
        this.init(creds);
        return;
      }

      // 2) Fájlból (alapértelmezett útvonal vagy env PATH)
      const filePath =
        process.env.FIREBASE_CREDENTIALS_PATH ||
        path.resolve(process.cwd(), 'progr3ss-firebase-adminsdk.json');

      if (!fs.existsSync(filePath)) {
        this.logger.warn(
          `Firebase disabled: credentials not found at ${filePath}.`,
        );
        return; // ⬅️ nincs init, no-op módban marad
      }

      const creds = JSON.parse(fs.readFileSync(filePath, 'utf8'));
      this.init(creds);
    } catch (err) {
      this.logger.warn(`Firebase disabled: ${String(err)}`);
      // no-op
    }
  }

  private init(creds: any) {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(creds),
      });
      this.enabled = true;
      this.logger.log('✅ Firebase initialized');
    } else {
      this.enabled = true;
      this.logger.log('Firebase already initialized');
    }
  }

  async sendNotification(
    token: string,
    title: string,
    body: string,
    data: Record<string, string> = {},
  ) {
    if (!this.enabled) {
      this.logger.debug('Skipping push (Firebase disabled).');
      return; // no-op
    }
    const message = { token, notification: { title, body }, data };
    const response = await admin.messaging().send(message);
    this.logger.log(`✅ Push notification sent: ${response}`);
    return response;
  }
}
