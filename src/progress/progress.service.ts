import { ForbiddenException, Injectable } from '@nestjs/common';
import { CreateProgressDto } from './dto/create-progress.dto';
import { UpdateProgressDto } from './dto/update-progress.dto';
import { InjectRepository } from '@nestjs/typeorm';
import {
  Schedule,
  ScheduleStatus,
} from 'src/schedule/entities/schedule.entity';
import { Progress } from './entities/progress.entity';
import { Repository } from 'typeorm';
import { ProgressResponseDto } from './dto/progress-response.dto';

@Injectable()
export class ProgressService {
  constructor(
    @InjectRepository(Schedule)
    private readonly scheduleRepo: Repository<Schedule>,
    @InjectRepository(Progress)
    private readonly progressRepo: Repository<Progress>,
  ) {}

  async create(
    dto: CreateProgressDto,
    userId: number,
  ): Promise<ProgressResponseDto> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id: dto.scheduleId },
      relations: ['user'],
    });

    if (!schedule || schedule.user.id !== userId) {
      throw new ForbiddenException('Not your schedule.');
    }

    const progress = this.progressRepo.create({
      ...dto,
      user: { id: userId },
      schedule: { id: dto.scheduleId },
    });

    const saved = await this.progressRepo.save(progress);

    if (dto.is_completed === true) {
      schedule.status = ScheduleStatus.COMPLETED; // vagy ScheduleStatus.COMPLETED ha enumot használsz
      await this.scheduleRepo.save(schedule);
    }

    return this.toResponse(saved);
  }

  async update(
    id: number,
    dto: UpdateProgressDto,
    userId: number,
  ): Promise<ProgressResponseDto> {
    const progress = await this.progressRepo.findOne({
      where: { id },
      relations: ['user', 'schedule'],
    });

    if (!progress || progress.user.id !== userId) {
      throw new ForbiddenException('You cannot update this progress.');
    }

    Object.assign(progress, dto);
    const updated = await this.progressRepo.save(progress);

    if (updated.is_completed === true) {
      const schedule = await this.scheduleRepo.findOne({
        where: { id: updated.schedule.id },
      });
      if (schedule) {
        schedule.status = ScheduleStatus.COMPLETED;
        await this.scheduleRepo.save(schedule);
      }
    }

    return this.toResponse(updated);
  }

  async remove(id: number, userId: number) {
    const progress = await this.progressRepo.findOne({
      where: { id },
      relations: ['user'],
    });

    if (!progress || progress.user.id !== userId) {
      throw new ForbiddenException('You cannot delete this progress.');
    }

    await this.progressRepo.remove(progress);
    return { message: 'Progress deleted successfully' };
  }

  private toResponse(progress: Progress): ProgressResponseDto {
    return {
      id: progress.id,
      scheduleId: progress.schedule.id,
      date: progress.date.toISOString(),
      logged_time: progress.logged_time,
      notes: progress.notes,
      is_completed: progress.is_completed,
      created_at: progress.created_at,
      updated_at: progress.updated_at,
    };
  }
}
