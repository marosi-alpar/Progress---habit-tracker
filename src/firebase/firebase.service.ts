import { Injectable, OnModuleInit } from '@nestjs/common';
import * as admin from 'firebase-admin';
import * as path from 'path';

@Injectable()
export class FirebaseService implements OnModuleInit {
  onModuleInit() {
    const serviceAccountPath = path.resolve(
      process.cwd(),
      'progr3ss-firebase-adminsdk.json',
    );
    //console.log(serviceAccountPath);
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert(require(serviceAccountPath)),
      });
      console.log('✅ Firebase initialized');
    }
  }

  async sendNotification(
    token: string,
    title: string,
    body: string,
    data: Record<string, string> = {},
  ) {
    const message = {
      token,
      notification: { title, body },
      data,
    };

    try {
      const response = await admin.messaging().send(message);
      console.log(`✅ Push notification sent: ${response}`);
      return response;
    } catch (error) {
      console.error('❌ Error sending push notification', error);
      throw error;
    }
  }
}
