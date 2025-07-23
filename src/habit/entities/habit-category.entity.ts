import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToMany,
  Unique,
} from 'typeorm';
import { Habit } from './habit.entity';

@Entity()
@Unique(['name'])
export class HabitCategory {
  @PrimaryGeneratedColumn()
  id: number;

  @Column()
  name: string;

  @Column()
  iconUrl: string;

  @OneToMany(() => Habit, (habit) => habit.category)
  habits: Habit[];
}
