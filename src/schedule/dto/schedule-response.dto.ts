import { ApiProperty } from '@nestjs/swagger';
import { ScheduleStatus } from '../entities/schedule.entity';
import { HabitResponseDto } from 'src/habit/dto/habit-response.dto';
import { IsOptional } from 'class-validator';
import { ProgressResponseDto } from 'src/progress/dto/progress-response.dto';
export class ScheduleResponseDto {
  @ApiProperty()
  id: number;

  @ApiProperty()
  start_time: Date;

  @ApiProperty({ required: false })
  end_time?: Date;

  @ApiProperty({ enum: ScheduleStatus })
  status: ScheduleStatus;

  @ApiProperty()
  date: Date;

  @ApiProperty()
  is_custom: boolean;

  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;

  @ApiProperty({ type: () => HabitResponseDto })
  habit: HabitResponseDto;

  @ApiProperty({ required: false, nullable: true })
  @IsOptional()
  progress?: ProgressResponseDto | null;
}
