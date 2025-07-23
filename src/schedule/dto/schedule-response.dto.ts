import { ApiProperty } from '@nestjs/swagger';
import { ScheduleStatus } from '../entities/schedule.entity';
import { HabitResponseDto } from 'src/habit/dto/habit-response.dto';
import { IsOptional } from 'class-validator';
import { ProgressResponseDto } from 'src/progress/dto/progress-response.dto';
import { ScheduleType } from '../enums/schedule-type.enum';
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

  @ApiProperty({ required: false, type: [ProgressResponseDto] })
  @IsOptional()
  progress?: ProgressResponseDto[];

  @ApiProperty({
    required: false,
    isArray: true,
    type: 'object',
    example: [
      {
        id: 2,
        name: 'Anna',
        email: 'anna@example.com',
        profile_image: 'https://example.com/images/anna.jpg',
      },
      {
        id: 3,
        name: 'Tom',
        email: 'tom@example.com',
        profile_image: 'https://example.com/images/tom.jpg',
      },
    ],
  })
  participants?: {
    id: number;
    name: string;
    email: string;
    profile_image: string;
  }[];

  @ApiProperty({ enum: ScheduleType })
  type: ScheduleType;

  @ApiProperty({ required: false, example: 30 })
  @IsOptional()
  duration_minutes?: number;
}
