import { ApiProperty } from '@nestjs/swagger';
import { HabitFrequency } from '../entities/habit.entity';
import { HabitCategory } from '../entities/habit-category.entity';

export class HabitResponseDto {
  @ApiProperty()
  id: number;

  @ApiProperty()
  name: string;

  @ApiProperty({ required: false })
  description?: string;

  @ApiProperty({ type: () => HabitCategory })
  category: HabitCategory;

  @ApiProperty()
  goal: string;

  @ApiProperty({ enum: HabitFrequency })
  frequency: HabitFrequency;

  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;
}
