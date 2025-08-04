import { ApiProperty } from '@nestjs/swagger';
import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsEnum,
  IsInt,
  IsOptional,
  IsString,
} from 'class-validator';
import { ScheduleStatus } from '../entities/schedule.entity';

export class UpdateScheduleDto {
  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  start_time?: Date;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  end_time?: Date;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsInt()
  duration_minutes?: number;

  @ApiProperty({ required: false, enum: ScheduleStatus })
  @IsOptional()
  @IsEnum(ScheduleStatus)
  status?: ScheduleStatus;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  date?: Date;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsBoolean()
  is_custom?: boolean;

  @ApiProperty({
    required: false,
    type: [Number],
    description: 'List of participant user IDs',
    example: [2, 3, 7],
  })
  @IsOptional()
  @IsArray()
  @IsInt({ each: true })
  participantIds?: number[];

  @ApiProperty({
    required: false,
    description: 'Optional notes for the schedule',
    example: 'Rescheduled to the afternoon',
  })
  @IsOptional()
  @IsString()
  notes?: string;
}
