import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Between, Repository } from 'typeorm';
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
    userId: number,
  ): Promise<ScheduleResponseDto> {
    const habit = await this.habitRepo.findOne({
      where: { id: createScheduleDto.habitId, user: { id: userId } }, // csak saját habit legyen érvényes
    });
    if (!habit) {
      throw new NotFoundException('Habit not found or unauthorized');
    }

    const schedule = this.scheduleRepo.create({
      ...createScheduleDto,
      habit,
      user: { id: userId } as any, // csak id elég, nem kell lekérni
    });

    const saved = await this.scheduleRepo.save(schedule);
    await this.notificationQueueService.scheduleNotification(saved);

    return this.mapToResponseDto(saved, habit);
  }

  async findAll(userId: number): Promise<ScheduleResponseDto[]> {
    const schedules = await this.scheduleRepo.find({
      where: { user: { id: userId } },
      relations: ['habit'],
    });
    return schedules.map((s) => this.mapToResponseDto(s, s.habit));
  }

  async findOne(id: number, userId: number): Promise<ScheduleResponseDto> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id, user: { id: userId } },
      relations: ['habit'],
    });
    if (!schedule)
      throw new NotFoundException('Schedule not found or unauthorized');
    return this.mapToResponseDto(schedule, schedule.habit);
  }

  async update(
    id: number,
    updateScheduleDto: UpdateScheduleDto,
    userId: number,
  ): Promise<ScheduleResponseDto> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id, user: { id: userId } },
      relations: ['habit'],
    });
    if (!schedule)
      throw new NotFoundException('Schedule not found or unauthorized');

    await this.scheduleRepo.save({ ...schedule, ...updateScheduleDto });
    const updated = await this.scheduleRepo.findOne({
      where: { id },
      relations: ['habit'],
    });

    return this.mapToResponseDto(updated, updated.habit);
  }

  async remove(id: number, userId: number): Promise<void> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id, user: { id: userId } },
    });
    if (!schedule)
      throw new NotFoundException('Schedule not found or unauthorized');

    await this.scheduleRepo.remove(schedule);
  }

  async findByDate(
    userId: number,
    date: string,
  ): Promise<ScheduleResponseDto[]> {
    const start = new Date(date);
    start.setHours(0, 0, 0, 0);

    const end = new Date(date);
    end.setHours(23, 59, 59, 999);

    const schedules = await this.scheduleRepo.find({
      where: {
        user: { id: userId },
        date: Between(start, end),
      },
      relations: ['habit'],
    });

    return schedules.map((s) => this.mapToResponseDto(s, s.habit));
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
