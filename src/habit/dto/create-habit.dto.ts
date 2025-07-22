import { IsNotEmpty, IsOptional, IsString, IsNumber } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { HabitFrequency } from '../entities/habit.entity';

export class CreateHabitDto {
  @ApiProperty({ example: 'Morning Run' })
  @IsString()
  @IsNotEmpty()
  name: string;

  @ApiProperty({ example: 'Run 2km every morning', required: false })
  @IsString()
  @IsOptional()
  description?: string;

  @ApiProperty({ example: 1, description: 'ID of the Habit Category' })
  @IsNumber()
  @IsNotEmpty()
  categoryId: number;

  @ApiProperty({ example: 'Run 10 times in 2 weeks' })
  @IsString()
  @IsNotEmpty()
  goal: string;

  @ApiProperty({ enum: HabitFrequency, example: HabitFrequency.DAILY })
  @IsNotEmpty()
  frequency: HabitFrequency;
}
