import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class CreateNotificationDto {
  @ApiProperty({ example: 'device_fcm_token_here' })
  @IsString()
  token: string;

  @ApiProperty({ example: 'New Habit Reminder' })
  @IsString()
  title: string;

  @ApiProperty({ example: 'Time to complete your morning run!' })
  @IsString()
  body: string;
}
