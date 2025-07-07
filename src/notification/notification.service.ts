import { Injectable } from '@nestjs/common';
import { FirebaseService } from '../firebase/firebase.service';
import { CreateNotificationDto } from './dto/create-notification.dto';

@Injectable()
export class NotificationService {
  constructor(private readonly firebaseService: FirebaseService) {}

  async send(createNotificationDto: CreateNotificationDto) {
    try {
      const response = await this.firebaseService.sendNotification(
        createNotificationDto.token,
        createNotificationDto.title,
        createNotificationDto.body,
      );
      return { message: 'Notification sent successfully', response };
    } catch (error) {
      return { message: 'Failed to send notification', error: error.message };
    }
  }
}
