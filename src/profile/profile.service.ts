import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Profile } from './entities/profile.entity';
import { CreateProfileDto } from './dto/create-profile.dto';
import { UpdateProfileDto } from './dto/update-profile.dto';
import { UpdateFcmTokenDto } from './dto/update-fcm-token.dto';

@Injectable()
export class ProfileService {
  constructor(
    @InjectRepository(Profile)
    private profileRepository: Repository<Profile>,
  ) {}

  async searchProfiles(
    query: string,
    page: number = 1,
    limit: number = 10,
    orderBy: string = 'username',
    order: 'ASC' | 'DESC' = 'ASC',
  ): Promise<Profile[]> {
    const offset = (page - 1) * limit;

    return this.profileRepository
      .createQueryBuilder('profile')
      .where('LOWER(profile.username) LIKE :query', {
        query: `%${query.toLowerCase()}%`,
      })
      .orWhere('LOWER(profile.description) LIKE :query', {
        query: `%${query.toLowerCase()}%`,
      })
      .orderBy(`profile.${orderBy}`, order)
      .skip(offset)
      .take(limit)
      .getMany();
  }

  async create(createProfileDto: CreateProfileDto): Promise<Profile> {
    const profile = this.profileRepository.create(createProfileDto);
    return this.profileRepository.save(profile);
  }

  async findAll(): Promise<Profile[]> {
    return this.profileRepository.find();
  }

  async findOne(id: number, currentUserId?: number): Promise<any> {
    const profile = await this.profileRepository.findOne({
      where: { id },
      select: [
        'id',
        'username',
        'description',
        'profileImageUrl',
        'profileImageData',
        'profileImageMimeType',
        'coverImageUrl',
        'fcmToken',
        'preferences',
        'created_at',
        'updated_at',
      ],
    });
    if (!profile) {
      throw new NotFoundException(`Profile with ID ${id} not found`);
    }

    return profile;
  }

  async update(
    id: number,
    updateProfileDto: UpdateProfileDto,
  ): Promise<Profile> {
    const profile = await this.profileRepository.preload({
      id,
      ...updateProfileDto,
    });
    if (!profile) {
      throw new NotFoundException(`Profile with ID ${id} not found`);
    }
    return this.profileRepository.save(profile);
  }

  async remove(id: number): Promise<void> {
    const result = await this.profileRepository.delete(id);
    if (result.affected === 0) {
      throw new NotFoundException(`Profile with ID ${id} not found`);
    }
  }

  async updateFcmToken(id: number, token: UpdateFcmTokenDto): Promise<Profile> {
    const profile = await this.profileRepository.findOne({ where: { id } });
    if (!profile) {
      throw new NotFoundException(`Profile with ID ${id} not found`);
    }
    console.log(token);
    profile.fcmToken = token.token;
    return this.profileRepository.save(profile);
  }

  async save(profile: Profile): Promise<Profile> {
    return this.profileRepository.save(profile);
  }

  async findOneWithImage(id: number): Promise<Profile> {
    return this.profileRepository.findOne({
      where: { id },
      select: [
        'id',
        'username',
        'description',
        'profileImageUrl',
        'profileImageData',
        'profileImageMimeType',
        'coverImageUrl',
        'fcmToken',
        'preferences',
        'created_at',
        'updated_at',
      ],
    });
  }
}
