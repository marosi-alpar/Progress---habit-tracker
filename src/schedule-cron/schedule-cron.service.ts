// schedule-cron.service.ts
import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { ScheduleService } from 'src/schedule/schedule.service';

@Injectable()
export class ScheduleCronService {
  private readonly logger = new Logger(ScheduleCronService.name);

  constructor(private readonly scheduleService: ScheduleService) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleCron() {
    this.logger.log('Running daily check for missed schedules...');
    await this.scheduleService.markMissedSchedulesAsSkipped();
  }
}
