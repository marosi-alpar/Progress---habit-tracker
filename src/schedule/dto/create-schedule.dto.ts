import {
  IsArray,
  IsBoolean,
  IsDateString,
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsNumber,
  IsOptional,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ScheduleStatus } from '../entities/schedule.entity';
import { RepeatPattern } from '../enums/repeat-pattern.enum';

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
  @IsOptional() // <-- ezt add hozzá
  @IsBoolean() // <-- ez is fontos!
  is_custom?: boolean;

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

  @ApiProperty({
    enum: RepeatPattern,
    description: 'How the schedule should repeat',
    default: RepeatPattern.NONE,
  })
  @IsEnum(RepeatPattern)
  repeatPattern: RepeatPattern;

  @ApiProperty({ required: false, default: 30 })
  @IsOptional()
  @IsNumber()
  repeatDays?: number;
}
