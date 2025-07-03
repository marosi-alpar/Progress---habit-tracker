import { Injectable } from '@nestjs/common';
import { CreateNotificationDto } from './dto/create-notification.dto';
import { FirebaseService } from '../firebase/firebase.service';

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
