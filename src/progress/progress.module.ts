import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { Progress } from './entities/progress.entity';
import { Schedule } from '../schedule/entities/schedule.entity'; // ez kell!
import { ProgressService } from './progress.service';
import { ProgressController } from './progress.controller';

@Module({
  imports: [TypeOrmModule.forFeature([Progress, Schedule])],
  controllers: [ProgressController],
  providers: [ProgressService],
})
export class ProgressModule {}
