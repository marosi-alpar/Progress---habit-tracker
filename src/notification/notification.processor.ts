import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Injectable } from '@nestjs/common';
import { FirebaseService } from 'src/firebase/firebase.service';
import { Schedule } from 'src/schedule/entities/schedule.entity';
import { Repository } from 'typeorm';
import { InjectRepository } from '@nestjs/typeorm';

@Injectable()
@Processor('notification')
export class NotificationProcessor extends WorkerHost {
  constructor(
    @InjectRepository(Schedule)
    private readonly scheduleRepo: Repository<Schedule>,
    private readonly firebaseService: FirebaseService,
  ) {
    super();
  }

  async process(job: Job) {
    const { scheduleId } = job.data;

    const schedule = await this.scheduleRepo.findOne({
      where: { id: scheduleId },
      relations: ['user', 'user.profile', 'habit'],
    });
    if (!schedule || !schedule.user || !schedule.user.profile.fcmToken) {
      console.log('Hiba: nem található a felhasználói token.');
      return;
    }

    console.log(schedule.habit.name);
    await this.firebaseService.sendNotification(
      schedule.user.profile.fcmToken,
      'Emlékeztető',
      `Nemsokára kezdődik a(z) ${schedule.habit.name ?? 'feladat'}!`,
    );

    console.log(
      `Értesítés elküldve Schedule ID: ${scheduleId} felhasználónak.`,
    );
  }
}
