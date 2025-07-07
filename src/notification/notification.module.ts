import { Module } from '@nestjs/common';
import { NotificationService } from './notification.service';
import { NotificationQueueService } from './notification-queue.service';
import { NotificationProcessor } from './notification.processor';
import { BullModule } from '@nestjs/bullmq';
import { FirebaseModule } from '../firebase/firebase.module';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Schedule } from '../schedule/entities/schedule.entity';

@Module({
  imports: [
    FirebaseModule,
    TypeOrmModule.forFeature([Schedule]),
    BullModule.registerQueue({
      name: 'notification',
    }),
  ],
  providers: [
    NotificationService,
    NotificationQueueService,
    NotificationProcessor,
  ],
  exports: [NotificationService, NotificationQueueService],
})
export class NotificationModule {}
