import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  OneToMany,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Progress } from '../../progress/entities/progress.entity';
import { Schedule } from '../../schedule/entities/schedule.entity';
import { HabitCategory } from './habit-category.entity';

export enum HabitFrequency {
  DAILY = 'Daily',
  WEEKLY = 'Weekly',
}

@Entity()
export class Habit {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.habits)
  user: User;

  @Column()
  name: string;

  @Column({ nullable: true })
  description: string;

  @ManyToOne(() => HabitCategory, (category) => category.habits, {
    eager: true,
  })
  category: HabitCategory;

  @Column()
  goal: string;

  @Column({ type: 'enum', enum: HabitFrequency })
  frequency: HabitFrequency;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;

  @OneToMany(() => Schedule, (schedule) => schedule.habit)
  schedules: Schedule[];
}
