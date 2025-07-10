import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Habit } from './entities/habit.entity';
import { Repository } from 'typeorm';
import { HabitResponseDto } from './dto/habit-response.dto';
import { CreateHabitDto } from './dto/create-habit.dto';
import { UpdateHabitDto } from './dto/update-habit.dto';

@Injectable()
export class HabitService {
  constructor(
    @InjectRepository(Habit)
    private habitRepo: Repository<Habit>,
  ) {}

  async findAll(userId: number): Promise<HabitResponseDto[]> {
    const habits = await this.habitRepo.find({
      where: { user: { id: userId } },
    });
    return habits.map(this.mapToResponseDto);
  }

  async create(
    habitData: CreateHabitDto,
    userId: number,
  ): Promise<HabitResponseDto> {
    const habit = this.habitRepo.create({
      ...habitData,
      user: { id: userId } as any,
    });
    const saved = await this.habitRepo.save(habit);
    return this.mapToResponseDto(saved);
  }

  async findByUserId(userId: number): Promise<HabitResponseDto[]> {
    const habits = await this.habitRepo.find({
      where: { user: { id: userId } },
      relations: ['user'],
    });
    return habits.map(this.mapToResponseDto);
  }

  async findById(habitId: number, userId: number): Promise<HabitResponseDto> {
    const habit = await this.habitRepo.findOne({
      where: {
        id: habitId,
        user: { id: userId },
      },
    });

    if (!habit) throw new NotFoundException('Habit not found or unauthorized');

    return this.mapToResponseDto(habit);
  }

  async update(
    habitId: number,
    dto: UpdateHabitDto,
    userId: number,
  ): Promise<HabitResponseDto> {
    const habit = await this.habitRepo.findOne({
      where: { id: habitId, user: { id: userId } },
    });
    if (!habit) throw new NotFoundException('Habit not found or unauthorized');

    Object.assign(habit, dto);
    const saved = await this.habitRepo.save(habit);
    return this.mapToResponseDto(saved);
  }

  async remove(habitId: number, userId: number): Promise<void> {
    const habit = await this.habitRepo.findOne({
      where: { id: habitId, user: { id: userId } },
    });
    if (!habit) throw new NotFoundException('Habit not found or unauthorized');

    await this.habitRepo.remove(habit);
  }

  private mapToResponseDto(habit: Habit): HabitResponseDto {
    return {
      id: habit.id,
      name: habit.name,
      description: habit.description,
      category: habit.category,
      goal: habit.goal,
      frequency: habit.frequency,
      created_at: habit.created_at,
      updated_at: habit.updated_at,
    };
  }
}
