import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import googleOauthConfig from './config/google-oauth.config';
import { UserModule } from 'src/user/user.module';
import { AuthService } from './auth.service';
import { JwtModule } from '@nestjs/jwt';
import { JwtStrategy } from './strategies/jwt.strategy';
import { AtStrategy, RtStrategy } from './strategies';
import { PasswordResetService } from './password.reset.service';
import { FirebaseService } from 'src/firebase/firebase.service';
import { MailModule } from 'src/mail/mail.module';

@Module({
  imports: [
    // AppModule-ban legyen: ConfigModule.forRoot({ isGlobal: true })
    ConfigModule.forFeature(googleOauthConfig),
    UserModule,
    MailModule, // ha nincs MAILJET_* env, a MailModule a NoopMailjetService-t adja
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (cfg: ConfigService) => ({
        secret: cfg.get<string>('AT_SECRET'),
        signOptions: { expiresIn: '10h' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    { provide: 'AUTH_SERVICE', useClass: AuthService },
    JwtStrategy,
    AtStrategy,
    RtStrategy,
    PasswordResetService,
    FirebaseService,
  ],
  exports: ['AUTH_SERVICE'],
})
export class AuthModule {}
