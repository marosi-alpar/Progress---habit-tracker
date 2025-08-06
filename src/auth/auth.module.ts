import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
// import { GoogleStrategy } from './strategies/google.strategy';
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
    ConfigModule.forFeature(googleOauthConfig),
    ConfigModule.forRoot({ isGlobal: true }),
    UserModule,
    MailModule,
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => ({
        secret: configService.get<string>('AT_SECRET'),
        signOptions: { expiresIn: '10h' },
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    // GoogleStrategy,
    {
      provide: 'AUTH_SERVICE',
      useClass: AuthService,
    },
    JwtStrategy,
    AtStrategy,
    RtStrategy,
    PasswordResetService,
    FirebaseService,
  ],
})
export class AuthModule {}
