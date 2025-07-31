import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  OneToOne,
  JoinTable,
  ManyToMany,
  CreateDateColumn,
  UpdateDateColumn,
} from 'typeorm';
import { User } from '../../user/entities/user.entity';
@Entity()
export class Profile {
  @PrimaryGeneratedColumn()
  id: number;

  @OneToOne(() => User, (user) => user.profile, { cascade: true })
  user: User;

  @Column({ type: 'varchar', length: 100, nullable: false, unique: true })
  username?: string;

  @Column({ type: 'text', nullable: true })
  description?: string;

  @Column({ type: 'text', nullable: true })
  profileImageUrl?: string;

  @Column({ type: 'bytea', nullable: true })
  profileImageData?: Buffer;

  @Column({ type: 'varchar', nullable: true })
  profileImageMimeType?: string;

  @Column({ type: 'text', nullable: true })
  coverImageUrl?: string;

  @Column({ type: 'text', nullable: true, default: '' })
  fcmToken: string;

  @Column({ type: 'json', nullable: true })
  preferences: any;

  @CreateDateColumn()
  created_at: Date;

  @UpdateDateColumn()
  updated_at: Date;
}
