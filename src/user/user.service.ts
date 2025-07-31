import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { AuthDto } from 'src/auth/dto';
import { Profile } from '../profile/entities/profile.entity';
import { ProfileService } from 'src/profile/profile.service';
import { GoogleAuthDto } from 'src/auth/dto/google.auth.dto';
import { UserResponseDto } from './dtos/user-response.dto';
import { ProfileResponseDto } from 'src/profile/dto/profile-response.dto';
@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User) private readonly userRepo: Repository<User>,
    private readonly profileService: ProfileService,
  ) {}
  async findOne(email: string) {
    return this.userRepo.findOne({
      where: { email },
      relations: ['profile'],
    });
  }
  async findOneById(id: number) {
    return this.userRepo.findOneBy({ id });
  }
  async findAll(): Promise<UserResponseDto[]> {
    const users = await this.userRepo.find();
    return users.map((user) => this.mapToResponseDto(user));
  }
  async createUser({ username, email, password }: AuthDto) {
    const user = this.userRepo.create({ email, password });

    // blank profile for the user
    const profile = await this.profileService.create({
      username,
      userId: user.id,
    });

    user.profile = profile;

    return this.userRepo.save(user);
  }

  async createGoogleUser({
    username,
    email,
    profileImageUrl,
    authProviderId,
    authProvider,
  }: GoogleAuthDto) {
    const user = this.userRepo.create({
      email,
      auth_provider: authProvider,
      auth_provider_id: authProviderId,
    });

    const profile = await this.profileService.create({
      username,
      userId: user.id,
      profileImageUrl: profileImageUrl,
    });

    user.profile = profile;

    return this.userRepo.save(user);
  }

  async updateRefreshToken(userId: number, refreshToken: string | null) {
    if (refreshToken === null) {
      return await this.userRepo.update(
        { id: userId },
        {
          hashedRt: null,
        },
      );
    } else {
      return await this.userRepo.update(
        { id: userId },
        {
          hashedRt: refreshToken,
        },
      );
    }
  }

  async getProfileIdByUserId(userId: number): Promise<number | null> {
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['profile'],
    });

    if (!user || !user.profile) {
      return null;
    }

    return user.profile.id;
  }

  private mapToResponseDto(user: User): UserResponseDto {
    return {
      id: user.id,
      email: user.email,
      auth_provider: user.auth_provider,
      profile: this.mapToProfileResponseDto(user.profile),
    };
  }

  private mapToProfileResponseDto(profile: Profile): ProfileResponseDto {
    if (!profile) return null;
    return {
      id: profile.id,
      username: profile.username,
      description: profile.description,
      profileImageUrl: profile.profileImageUrl,
      profileImageBase64: profile.profileImageData
        ? profile.profileImageData.toString('base64')
        : undefined,
      coverImageUrl: profile.coverImageUrl,
      fcmToken: profile.fcmToken,
      preferences: profile.preferences,
      created_at: profile.created_at,
      updated_at: profile.updated_at,
    };
  }

  async updatePassword(userId: number, newHashedPassword: string) {
    await this.userRepo.update({ id: userId }, { password: newHashedPassword });
  }

  async updateUserProfile(
    userId: number,
    updates: Partial<Profile>,
  ): Promise<Profile> {
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['profile'],
    });

    if (!user || !user.profile) {
      throw new Error('User or profile not found');
    }

    Object.assign(user.profile, updates);

    return this.profileService.save(user.profile);
  }

  async findFullProfileByUserId(userId: number): Promise<Profile> {
    const user = await this.userRepo.findOne({
      where: { id: userId },
      relations: ['profile'],
    });

    if (!user?.profile) throw new Error('Profile not found');
    return this.profileService.findOneWithImage(user.profile.id);
  }
}
