import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty } from 'class-validator';

export class RequestPasswordResetDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'The email address associated with the user account',
  })
  @IsEmail()
  @IsNotEmpty()
  email: string;
}
