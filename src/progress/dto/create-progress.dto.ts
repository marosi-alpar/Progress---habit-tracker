import {
  IsInt,
  IsDateString,
  IsOptional,
  IsBoolean,
  Min,
  MaxLength,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class CreateProgressDto {
  @ApiProperty()
  @IsInt()
  scheduleId: number;

  @ApiProperty()
  @IsDateString()
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
