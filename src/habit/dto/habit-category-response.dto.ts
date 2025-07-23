import { ApiProperty } from '@nestjs/swagger';

export class HabitCategoryResponseDto {
  @ApiProperty({ example: 1 })
  id: number;

  @ApiProperty({ example: 'Exercise' })
  name: string;

  @ApiProperty({ example: 'https://example.com/icons/exercise.svg' })
  iconUrl: string;
}
