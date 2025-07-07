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
      relations: ['user'],
    });
    console.log(schedule);
    if (!schedule || !schedule.user || !schedule.user.fcm_token) {
      console.log('Hiba: nem található a felhasználói token.');
      return;
    }

    await this.firebaseService.sendNotification(
      'dyp2VF9nSzGwheGTeA4vUT:APA91bG45VxFIIoTqrjzPGaL2W_7kFspPezyPpcTMpt8tdEs5nIHbGETfn5ElfojhTNMmUmfCq6EZ7q7ka0BUmT4fVoOqO7Ty-t6XHbANT2mYkEe1OJAlzY',
      'Emlékeztető',
      `Nemsokára kezdődik a(z) ${schedule.habit?.name ?? 'feladat'}!`,
    );

    console.log(
      `Értesítés elküldve Schedule ID: ${scheduleId} felhasználónak.`,
    );
  }
}
