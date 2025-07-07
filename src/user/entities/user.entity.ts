import {
  Entity,
  Column,
  PrimaryGeneratedColumn,
  OneToOne,
  JoinColumn,
  OneToMany,
} from 'typeorm';
import { Profile } from '../../profile/entities/profile.entity';
import { AuthProvider } from 'src/auth/enums';
import { Schedule } from 'src/schedule/entities/schedule.entity';
import { Progress } from 'src/progress/entities/progress.entity';
import { Habit } from 'src/habit/entities/habit.entity';

@Entity()
export class User {
  @PrimaryGeneratedColumn()
  id: number;
  @Column({ unique: true })
  email: string;
  @Column({ nullable: true })
  password: string;
  @Column({ nullable: true })
  hashedRt: string | null;

  @Column({
    type: 'enum',
    enum: AuthProvider,
    default: AuthProvider.LOCAL,
  })
  auth_provider: AuthProvider;

  @Column({ default: '0' })
  auth_provider_id: string;

  @OneToOne(() => Profile, (profile) => profile.user, { eager: true })
  @JoinColumn()
  profile: Profile;

  @OneToMany(() => Schedule, (schedule) => schedule.user)
  schedules: Schedule[];

  @OneToMany(() => Progress, (progress) => progress.user)
  progress: Progress[];

  @OneToMany(() => Habit, (habit) => habit.user)
  habits: Habit[];

  @Column({ nullable: true })
  fcm_token: string;
}
