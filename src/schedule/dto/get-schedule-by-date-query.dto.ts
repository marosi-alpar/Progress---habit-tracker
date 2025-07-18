import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsDateString } from 'class-validator';

export class GetSchedulesByDateQueryDto {
  @ApiPropertyOptional({
    description: 'Date in YYYY-MM-DD format',
    example: '2025-07-14',
  })
  @IsOptional()
  @IsDateString()
  date?: string;
}
