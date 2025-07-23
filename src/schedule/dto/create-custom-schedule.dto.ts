import {
  IsArray,
  IsDateString,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsBoolean,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateCustomScheduleDto {
  @ApiProperty()
  @IsInt()
  habitId: number;

  @ApiProperty()
  @IsDateString()
  date: Date;

  @ApiProperty()
  @IsDateString()
  start_time: Date;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  end_time?: Date;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsInt()
  duration_minutes?: number;

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
}
