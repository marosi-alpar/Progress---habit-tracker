import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Schedule } from './entities/schedule.entity';
import { CreateScheduleDto } from './dto/create-schedule.dto';
import { UpdateScheduleDto } from './dto/update-schedule.dto';
import { ScheduleResponseDto } from './dto/schedule-response.dto';
import { Habit } from '../habit/entities/habit.entity';
import { NotificationQueueService } from 'src/notification/notification-queue.service';

@Injectable()
export class ScheduleService {
  constructor(
    @InjectRepository(Schedule)
    private scheduleRepo: Repository<Schedule>,

    @InjectRepository(Habit)
    private habitRepo: Repository<Habit>,

    private notificationQueueService: NotificationQueueService,
  ) {}

  async create(
    createScheduleDto: CreateScheduleDto,
  ): Promise<ScheduleResponseDto> {
    const habit = await this.habitRepo.findOne({
      where: { id: createScheduleDto.habitId },
    });
    if (!habit) {
      throw new NotFoundException('Habit not found');
    }

    const schedule = this.scheduleRepo.create({
      ...createScheduleDto,
      habit: habit,
    });

    const saved = await this.scheduleRepo.save(schedule);

    await this.notificationQueueService.scheduleNotification(saved);

    return this.mapToResponseDto(saved, habit);
  }

  async findAll(): Promise<ScheduleResponseDto[]> {
    const schedules = await this.scheduleRepo.find({ relations: ['habit'] });
    return schedules.map((s) => this.mapToResponseDto(s, s.habit));
  }

  async findOne(id: number): Promise<ScheduleResponseDto> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id },
      relations: ['habit'],
    });
    return this.mapToResponseDto(schedule, schedule.habit);
  }

  async update(
    id: number,
    updateScheduleDto: UpdateScheduleDto,
  ): Promise<ScheduleResponseDto> {
    await this.scheduleRepo.save({ id, ...updateScheduleDto });
    const schedule = await this.scheduleRepo.findOne({
      where: { id },
      relations: ['habit'],
    });
    return this.mapToResponseDto(schedule, schedule.habit);
  }

  async remove(id: number): Promise<void> {
    await this.scheduleRepo.delete(id);
  }

  private mapToResponseDto(
    schedule: Schedule,
    habit: Habit,
  ): ScheduleResponseDto {
    return {
      id: schedule.id,
      start_time: schedule.start_time,
      end_time: schedule.end_time,
      status: schedule.status,
      date: schedule.date,
      is_custom: schedule.is_custom,
      created_at: schedule.created_at,
      updated_at: schedule.updated_at,
      habit: {
        id: habit.id,
        name: habit.name,
        description: habit.description,
        category: habit.category,
        goal: habit.goal,
        frequency: habit.frequency,
        created_at: habit.created_at,
        updated_at: habit.updated_at,
      },
    };
  }
}
