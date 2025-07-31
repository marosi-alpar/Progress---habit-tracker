import { ApiProperty } from '@nestjs/swagger';

export class ProfileResponseDto {
  @ApiProperty()
  id: number;

  @ApiProperty()
  username?: string;

  @ApiProperty()
  description?: string;

  @ApiProperty()
  profileImageUrl?: string;

  @ApiProperty({ required: false })
  profileImageBase64?: string;

  @ApiProperty()
  coverImageUrl?: string;

  @ApiProperty()
  fcmToken: string;

  @ApiProperty()
  preferences: any;

  @ApiProperty()
  created_at: Date;

  @ApiProperty()
  updated_at: Date;
}
