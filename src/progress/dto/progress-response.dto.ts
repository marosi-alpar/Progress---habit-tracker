// progress/dto/progress-response.dto.ts
import { ApiProperty } from '@nestjs/swagger';

export class ProgressResponseDto {
  @ApiProperty()
  id: number;

  @ApiProperty()
  scheduleId: number;

  @ApiProperty()
  date: string;

  @ApiProperty({ required: false })
  logged_time?: number;

  @ApiProperty({ required: false })
  notes?: string;

  @ApiProperty()
  is_completed: boolean;

  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;
}
