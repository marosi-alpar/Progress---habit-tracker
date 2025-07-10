import {
  IsDateString,
  IsEnum,
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
}
