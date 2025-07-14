import {
  IsInt,
  IsDateString,
  IsOptional,
  IsBoolean,
  Min,
  MaxLength,
  IsDate,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Type } from 'class-transformer';

export class CreateProgressDto {
  @ApiProperty()
  @IsInt()
  scheduleId: number;

  @ApiProperty()
  @Type(() => Date)
  @IsDate()
  date: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsInt()
  @Min(0)
  logged_time?: number;

  @ApiProperty({ required: false })
  @IsOptional()
  @MaxLength(255)
  notes?: string;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsBoolean()
  is_completed?: boolean;
}
