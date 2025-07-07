import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { Schedule } from '../schedule/entities/schedule.entity';

@Injectable()
export class NotificationQueueService {
  constructor(@InjectQueue('notification') private queue: Queue) {}

  async scheduleNotification(schedule: Schedule, notifyBeforeMinutes = 10) {
    const startTime = new Date(schedule.start_time);
    const notifyTime = new Date(
      startTime.getTime() - notifyBeforeMinutes * 60 * 1000,
    );
    const delay = notifyTime.getTime() - Date.now();
    console.log(
      `Schedule: ${schedule.id}, Start Time: ${startTime}, Notify Time: ${notifyTime}, Delay: ${delay}`,
    );
    if (delay > 0) {
      await this.queue.add(
        'send-notification',
        { scheduleId: schedule.id },
        { delay },
      );
    }
  }
}
