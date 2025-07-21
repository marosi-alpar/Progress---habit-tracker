import { ApiProperty } from '@nestjs/swagger';
import { IsString } from 'class-validator';

export class UpdateFcmTokenDto {
  @ApiProperty({ description: 'FCM token string' })
  @IsString()
  token: string;
}