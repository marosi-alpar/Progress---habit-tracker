import { ApiProperty } from '@nestjs/swagger';
import { IsArray, IsDateString, IsInt, IsOptional, Min } from 'class-validator';

export enum WeekDay {
  MONDAY = 1,
  TUESDAY = 2,
  WEDNESDAY = 3,
  THURSDAY = 4,
  FRIDAY = 5,
  SATURDAY = 6,
  SUNDAY = 7,
}

export class CreateWeekdayRecurringDto {
  @ApiProperty()
  @IsInt()
  habitId: number;

  @ApiProperty()
  @IsDateString()
  start_time: Date; // Óra + perc innen lesz átvéve

  @ApiProperty({ required: false })
  @IsOptional()
  @IsInt()
  duration_minutes?: number;

  @ApiProperty({ required: false })
  @IsOptional()
  @IsDateString()
  end_time?: Date;

  @ApiProperty({
    type: [Number],
    description: 'Days of the week (1=Monday ... 7=Sunday)',
    example: [1, 2, 3], // Hétfő, Kedd, Szerda
  })
  @IsArray()
  daysOfWeek: WeekDay[];

  @ApiProperty({
    default: 4,
    description: 'Number of weeks ahead to generate schedules for',
  })
  @IsInt()
  @Min(1)
  numberOfWeeks: number = 4;

  @ApiProperty({
    required: false,
    type: [Number],
    description: 'List of user IDs who participate',
    example: [2, 3, 7],
  })
  @IsOptional()
  @IsArray()
  participantIds?: number[];
}
