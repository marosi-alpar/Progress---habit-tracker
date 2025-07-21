import {
  Controller,
  Get,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  ParseIntPipe,
} from '@nestjs/common';
import { ProfileService } from './profile.service';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { GetCurrentUser, Public } from 'src/auth/common/decorators';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
} from '@nestjs/swagger';
import { ProfileResponseDto } from './dto/profile-response.dto';
import { UpdateFcmTokenDto } from './dto/update-fcm-token.dto';

@ApiTags('Profile')
@ApiBearerAuth('access-token')
@Controller('profile')
export class ProfileController {
  constructor(private readonly profileService: ProfileService) {}

  @Post()
  @ApiOperation({ summary: 'Create Profile' })
  @ApiResponse({
    status: 201,
    description: 'Profile created.',
    type: ProfileResponseDto,
  })
  async create(@Body() createProfileDto: CreateProfileDto) {
    return await this.profileService.create(createProfileDto);
  }

  @Get('all')
  @ApiOperation({ summary: 'List All Profiles' })
  @ApiResponse({
    status: 200,
    description: 'All profiles.',
    type: [ProfileResponseDto],
  })
  async findAll() {
    return await this.profileService.findAll();
  }

  @Get()
  @ApiOperation({ summary: 'Get My Profile' })
  @ApiResponse({
    status: 200,
    description: 'Current user profile.',
    type: ProfileResponseDto,
  })
  async findMe(@GetCurrentUser('profileId') id: number) {
    return await this.profileService.findOne(id, id);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get Profile by ID' })
  @ApiResponse({
    status: 200,
    description: 'Profile by ID.',
    type: ProfileResponseDto,
  })
  async findOne(
    @Param('id', ParseIntPipe) id: number,
    @GetCurrentUser('profileId') currentUserId: number,
  ) {
    return await this.profileService.findOne(id, currentUserId);
  }

  @Patch()
  @ApiOperation({ summary: 'Update My Profile' })
  @ApiResponse({
    status: 200,
    description: 'Profile updated.',
    type: ProfileResponseDto,
  })
  async update(
    @GetCurrentUser('profileId') id: number,
    @Body() updateProfileDto: UpdateProfileDto,
  ) {
    return await this.profileService.update(id, updateProfileDto);
  }

  @Delete(':id')
  @HttpCode(204)
  @ApiOperation({ summary: 'Delete Profile by ID' })
  @ApiResponse({ status: 204, description: 'Profile deleted.' })
  async remove(@Param('id', ParseIntPipe) id: number) {
    await this.profileService.remove(id);
  }

  @Post('update-fcm-token')
  @ApiOperation({ summary: 'Update FCM Token' })
  @ApiResponse({ status: 200, description: 'FCM token updated.' })
  async updateFcmToken(
    @GetCurrentUser('profileId') id: number,
    @Body() token: UpdateFcmTokenDto,
  ) {
    return await this.profileService.updateFcmToken(id, token);
  }
}
