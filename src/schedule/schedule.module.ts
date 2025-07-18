import { Module } from '@nestjs/common';
import { ScheduleService } from './schedule.service';
import { ScheduleController } from './schedule.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Schedule } from './entities/schedule.entity';
import { Habit } from 'src/habit/entities/habit.entity';
import { NotificationModule } from 'src/notification/notification.module';
import { User } from 'src/user/entities/user.entity';

@Module({
  imports: [
    TypeOrmModule.forFeature([Schedule, Habit, User]),
    NotificationModule,
  ],
  providers: [ScheduleService],
  controllers: [ScheduleController],
  exports: [ScheduleService],
})
export class ScheduleModule {}
