import {
  IsArray,
  IsDateString,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ScheduleStatus } from '../entities/schedule.entity';

export class CreateScheduleDto {
  @ApiProperty()
  @IsNumber()
  habitId: number;

  @ApiProperty()
  @IsDateString()
  start_time: Date;

  @ApiProperty({ required: false })
  @IsDateString()
  @IsOptional()
  end_time?: Date;

  @ApiProperty({ enum: ScheduleStatus })
  @IsEnum(ScheduleStatus)
  status: ScheduleStatus;

  @ApiProperty()
  @IsDateString()
  date: Date;

  @ApiProperty({ default: false })
  is_custom: boolean;

  @ApiProperty({
    required: false,
    type: [Number],
    description: 'List of user IDs who participated in the schedule',
    example: [2, 3, 7],
  })
  @IsOptional()
  @IsArray()
  @IsInt({ each: true })
  participantIds?: number[];
}
