import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Between, In, LessThan, Repository } from 'typeorm';
import { Schedule, ScheduleStatus } from './entities/schedule.entity';
import { CreateScheduleDto } from './dto/create-schedule.dto';
import { UpdateScheduleDto } from './dto/update-schedule.dto';
import { ScheduleResponseDto } from './dto/schedule-response.dto';
import { Habit } from '../habit/entities/habit.entity';
import { NotificationQueueService } from 'src/notification/notification-queue.service';
import { User } from 'src/user/entities/user.entity';
import { addDays } from 'date-fns';
import { CreateCustomScheduleDto } from './dto/create-custom-schedule.dto';
import {
  CreateRecurringScheduleDto,
  RepeatPattern,
} from './dto/create-reccuring-schedule.dto';
import { ScheduleType } from './enums/schedule-type.enum';

@Injectable()
export class ScheduleService {
  constructor(
    @InjectRepository(Schedule)
    private scheduleRepo: Repository<Schedule>,

    @InjectRepository(Habit)
    private habitRepo: Repository<Habit>,

    private notificationQueueService: NotificationQueueService,

    @InjectRepository(User)
    private userRepo: Repository<User>,
  ) {}

  async createCustom(
    dto: CreateCustomScheduleDto,
    userId: number,
  ): Promise<ScheduleResponseDto> {
    const {
      habitId,
      start_time,
      end_time,
      duration_minutes,
      date,
      participantIds = [],
      is_custom = true,
    } = dto;

    // 🔍 1. Validáció: date és start_time nap egyezzen
    const dateStr = new Date(date).toISOString().split('T')[0];
    const startStr = new Date(start_time).toISOString().split('T')[0];
    if (dateStr !== startStr) {
      throw new BadRequestException(
        'start_time must be on the same day as date',
      );
    }

    // 🔍 2. Legalább end_time vagy duration_minutes kötelező
    if (!end_time && !duration_minutes) {
      throw new BadRequestException(
        'Either end_time or duration_minutes must be provided',
      );
    }

    // 🧠 3. Számoljuk ki a hiányzó értéket
    let computedEndTime = end_time;
    let computedDuration = duration_minutes;

    if (!computedEndTime && duration_minutes) {
      computedEndTime = new Date(
        new Date(start_time).getTime() + duration_minutes * 60000,
      );
    }

    if (!computedDuration && end_time) {
      const ms = new Date(end_time).getTime() - new Date(start_time).getTime();
      if (ms < 0) {
        throw new BadRequestException('end_time cannot be before start_time');
      }
      computedDuration = Math.floor(ms / 60000);
    }

    // 🔄 4. Habit és résztvevők betöltése
    const habit = await this.habitRepo.findOne({
      where: { id: habitId, user: { id: userId } },
    });
    if (!habit) throw new NotFoundException('Habit not found or unauthorized');

    const participants = participantIds.length
      ? await this.userRepo.findBy({ id: In(participantIds) })
      : [];

    // 🏗️ 5. Schedule létrehozása
    const schedule = this.scheduleRepo.create({
      user: { id: userId } as any,
      habit,
      start_time,
      end_time: computedEndTime,
      duration_minutes: computedDuration,
      date,
      is_custom,
      type: ScheduleType.CUSTOM,
      participants,
      status: ScheduleStatus.PLANNED,
    });

    const saved = await this.scheduleRepo.save(schedule);
    await this.notificationQueueService.scheduleNotification(saved);

    return this.mapToResponseDto(saved, habit);
  }

  async createRecurring(
    dto: CreateRecurringScheduleDto,
    userId: number,
  ): Promise<ScheduleResponseDto[]> {
    const {
      habitId,
      start_time,
      end_time,
      duration_minutes,
      repeatPattern,
      repeatDays = 30,
      participantIds = [],
      is_custom = true,
    } = dto;

    // 1. Validáció
    if (!end_time && !duration_minutes) {
      throw new BadRequestException(
        'Either end_time or duration_minutes must be provided',
      );
    }

    const baseStart = new Date(start_time);

    // 2. end_time kiszámítás ha kell
    let computedDuration = duration_minutes;
    let computedEndTime = end_time;

    if (!computedDuration && end_time) {
      const diff =
        new Date(end_time).getTime() - new Date(start_time).getTime();
      if (diff < 0)
        throw new BadRequestException('end_time cannot be before start_time');
      computedDuration = Math.floor(diff / 60000);
    }

    if (!computedEndTime && duration_minutes) {
      computedEndTime = new Date(
        baseStart.getTime() + duration_minutes * 60000,
      );
    }

    // extra védelem
    if (!computedDuration || isNaN(computedDuration)) {
      throw new BadRequestException('Could not calculate duration_minutes');
    }

    // 3. Habit + résztvevők
    const habit = await this.habitRepo.findOne({
      where: { id: habitId, user: { id: userId } },
    });
    if (!habit) throw new NotFoundException('Habit not found or unauthorized');

    const participants = participantIds.length
      ? await this.userRepo.findBy({ id: In(participantIds) })
      : [];

    const schedules: Schedule[] = [];
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    for (let i = 0; i < repeatDays; i++) {
      const currentDate = addDays(today, i);
      const day = currentDate.getDay(); // 0-6 (Sun-Sat)

      const isValid =
        repeatPattern === 'daily' ||
        (repeatPattern === 'weekdays' && day >= 1 && day <= 5) ||
        (repeatPattern === 'weekends' && (day === 0 || day === 6)) ||
        repeatPattern === 'none';

      if (!isValid) continue;

      const type: ScheduleType =
        repeatPattern && repeatPattern !== RepeatPattern.NONE
          ? ScheduleType.RECURRING
          : ScheduleType.CUSTOM;

      const scheduledStart = new Date(currentDate);
      scheduledStart.setHours(
        baseStart.getHours(),
        baseStart.getMinutes(),
        0,
        0,
      );

      const scheduledEnd = new Date(
        scheduledStart.getTime() + computedDuration * 60000,
      );

      schedules.push(
        this.scheduleRepo.create({
          user: { id: userId } as any,
          habit,
          date: currentDate,
          start_time: scheduledStart,
          end_time: scheduledEnd,
          duration_minutes,
          participants,
          is_custom,
          type,
          status: ScheduleStatus.PLANNED,
        }),
      );
    }

    const saved = await this.scheduleRepo.save(schedules);
    for (const s of saved) {
      await this.notificationQueueService.scheduleNotification(s);
    }

    return saved.map((s) => this.mapToResponseDto(s, habit));
  }

  async findAll(userId: number): Promise<ScheduleResponseDto[]> {
    const schedules = await this.scheduleRepo.find({
      where: { user: { id: userId } },
      relations: ['habit', 'participants', 'progress'],
    });
    return schedules.map((s) => this.mapToResponseDto(s, s.habit));
  }

  async findOne(id: number, userId: number): Promise<ScheduleResponseDto> {
    const schedule = await this.scheduleRepo.findOne({
      where: { id, user: { id: userId } },
      relations: ['habit', 'progress', 'participants'],
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
      relations: ['habit', 'progress', 'participants'],
    });

    return schedules.map((s) => this.mapToResponseDto(s, s.habit));
  }

  async markMissedSchedulesAsSkipped() {
    const now = new Date();

    const expiredSchedules = await this.scheduleRepo.find({
      where: {
        end_time: LessThan(now),
        status: ScheduleStatus.PLANNED,
      },
      relations: ['progress'],
    });

    for (const schedule of expiredSchedules) {
      const hasCompletedProgress = schedule.progress?.some(
        (p) => p.is_completed === true,
      );

      if (!hasCompletedProgress) {
        schedule.status = ScheduleStatus.SKIPPED;
        await this.scheduleRepo.save(schedule);
      }
    }
  }

  private mapToResponseDto(
    schedule: Schedule,
    habit: Habit,
  ): ScheduleResponseDto {
    const latestProgress = schedule.progress; // vagy logika szerint választhatsz

    console.log(latestProgress);

    return {
      id: schedule.id,
      start_time: schedule.start_time,
      end_time: schedule.end_time,
      status: schedule.status,
      date: schedule.date,
      is_custom: schedule.is_custom,
      created_at: schedule.created_at,
      updated_at: schedule.updated_at,
      type: schedule.type,
      duration_minutes: schedule.duration_minutes,
      participants:
        schedule.participants?.map((u) => ({
          id: u.id,
          name: u.profile.username,
          email: u.email,
          profile_image: u.profile.profileImageUrl,
        })) || [],
      habit: {
        id: habit.id,
        name: habit.name,
        description: habit.description,
        category: habit.category,
        goal: habit.goal,
        created_at: habit.created_at,
        updated_at: habit.updated_at,
      },
      progress:
        schedule.progress?.map((p) => ({
          id: p.id,
          scheduleId: schedule.id,
          date: p.date.toISOString(),
          logged_time: p.logged_time,
          is_completed: p.is_completed,
          notes: p.notes,
          created_at: p.created_at,
          updated_at: p.updated_at,
        })) || [],
    };
  }
}
