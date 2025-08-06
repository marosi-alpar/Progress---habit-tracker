import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  ManyToOne,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
import { Habit } from '../../habit/entities/habit.entity';
import { Schedule } from '../../schedule/entities/schedule.entity';

@Entity()
export class Progress {
  @PrimaryGeneratedColumn()
  id: number;

  @ManyToOne(() => User, (user) => user.progress)
  user: User;

  @ManyToOne(() => Schedule, (schedule) => schedule.progress, {
    onDelete: 'CASCADE',
  })
  schedule: Schedule;

  @Column({ nullable: true })
  logged_time: number;

  @Column()
  date: Date;

  @Column({ nullable: true })
  notes: string;

  @Column({ default: false })
  is_completed: boolean;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
