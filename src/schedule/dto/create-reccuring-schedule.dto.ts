import {
  IsArray,
  IsDateString,
  IsEnum,
  IsInt,
  IsOptional,
  IsBoolean,
  IsNumber,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export enum RepeatPattern {
  NONE = 'none',
  DAILY = 'daily',
  WEEKDAYS = 'weekdays',
  WEEKENDS = 'weekends',
}

export class CreateRecurringScheduleDto {
  @ApiProperty()
  @IsInt()
  habitId: number;

  @ApiProperty()
  @IsDateString()
  start_time: Date;

  @ApiProperty({
    required: false,
    description: 'Optional end time if duration is not provided',
  })
  @IsOptional()
  @IsDateString()
  end_time?: Date;

  @ApiProperty({
    required: false,
    description: 'Duration in minutes if end_time is not provided',
    example: 30,
  })
  @IsOptional()
  @IsInt()
  duration_minutes?: number;

  @ApiProperty({
    enum: RepeatPattern,
    default: RepeatPattern.NONE,
    description: 'How the schedule should repeat',
  })
  @IsEnum(RepeatPattern)
  repeatPattern: RepeatPattern;

  @ApiProperty({ required: false, default: 30 })
  @IsOptional()
  @IsNumber()
  repeatDays?: number = 30;

  @ApiProperty({ default: true })
  @IsBoolean()
  @IsOptional()
  is_custom: boolean = true;

  @ApiProperty({
    required: false,
    type: [Number],
    description: 'List of user IDs who participate',
    example: [2, 3, 7],
  })
  @IsOptional()
  @IsArray()
  @IsInt({ each: true })
  participantIds?: number[];

  @ApiProperty({
    required: false,
    description: 'Optional notes for the schedule',
    example: 'Weekly standup meeting',
  })
  @IsOptional()
  notes?: string;
}
