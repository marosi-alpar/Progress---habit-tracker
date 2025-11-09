import {
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from 'src/user/dtos/create-user.dto';
import { UserService } from 'src/user/user.service';
import { AuthDto, AuthResponseDto, SignInDto } from './dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';
import { OAuth2Client } from 'google-auth-library';
import { GoogleAuthDto } from './dto/google.auth.dto';
import { UserResponseDto } from 'src/user/dtos/user-response.dto';
import { AuthProvider } from './enums';
import { User } from 'src/user/entities/user.entity';
import { ResetPasswordDto } from './dto/reset.password.dto';
import * as Multer from 'multer';
import { ProfileResponseDto } from 'src/profile/dto/profile-response.dto';
import { MailjetService } from 'src/mail/mailjet.service';
@Injectable()
export class AuthService {
  private client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly mailjetService: MailjetService,
  ) {}

  // async validateGitHubUser({ accessToken }: GithubSignUpDto) {
  //   // Fetch GitHub user data
  //   const userResponse = await fetch('https://api.github.com/user', {
  //     headers: { Authorization: `Bearer ${accessToken}` },
  //   });
  //   const userData = await userResponse.json();
  //   console.log('GitHub User', userData);
  //   const { id: githubId, login: username, avatar_url, email } = userData;

  //   let user = await this.userService.findByGithubId(githubId);
  //   console.log('user: ', user);
  //   if (!user) {
  //     // User doesn't exist, create a new one
  //     user = await this.userService.createUser({
  //       githubId: githubId,
  //       username: username,
  //       email: email || `${username}@github.com`,
  //       password: '',
  //     });
  //   }

  //   user.profile.profileImageUrl = avatar_url;

  //   console.log('user: ', user);

  //   const tokens = await this.getTokens(user.id, user.email, user.profile.id);
  //   console.log('tokens ', tokens);
  //   return tokens;
  // }

  private async createUserResponseForAuth(
    user: User,
    tokens: Tokens,
    message = 'Login successful',
  ): Promise<AuthResponseDto> {
    const profileDto: ProfileResponseDto | null = user.profile
      ? {
          id: user.profile.id,
          email: user.email,
          username: user.profile.username,
          description: user.profile.description,
          profileImageUrl: user.profile.profileImageUrl,
          profileImageBase64: user.profile.profileImageData
            ? user.profile.profileImageData.toString('base64')
            : undefined,
          coverImageUrl: user.profile.coverImageUrl,
          fcmToken: user.profile.fcmToken,
          preferences: user.profile.preferences,
          created_at: user.profile.created_at,
          updated_at: user.profile.updated_at,
        }
      : null;

    const safeUser: UserResponseDto = {
      id: user.id,
      email: user.email,
      auth_provider: user.auth_provider,
      profile: profileDto,
    };

    return {
      message,
      user: safeUser,
      tokens,
    };
  }

  async handleGoogleAuth(idToken: string) {
    const ticket = await this.client.verifyIdToken({
      idToken,
      audience: process.env.GOOGLE_WEB_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (!payload?.email) {
      throw new UnauthorizedException('Invalid Google token');
    }

    const { email, name, picture, sub } = payload;

    let user = await this.userService.findOne(email);

    if (!user) {
      const auth: GoogleAuthDto = {
        email,
        username: name,
        profileImageUrl: picture,
        authProviderId: sub,
        authProvider: AuthProvider.GOOGLE,
      };
      user = await this.userService.createGoogleUser(auth);
    }

    const tokens = await this.getTokens(user.id, user.email, user.profile.id);

    await this.updateRtHash(user.id, tokens.refreshToken);

    return await this.createUserResponseForAuth(user, tokens);
  }

  async findUserById(id: number) {
    return this.userService.findOneById(id);
  }

  //this is function is not used temporarly
  async validateGoogleUser(googleUser: CreateUserDto) {
    const user = await this.userService.findOne(googleUser.email);
    if (user) return user;
    return this.userService.createUser(googleUser);
  }

  async signupLocal(
    dto: AuthDto,
    profileImage?: Multer.File,
  ): Promise<AuthResponseDto> {
    // 1. Jelszó hash-elése
    const hash = await this.hashData(dto.password);

    // 2. Felhasználó és profil létrehozása
    const createdUser = await this.userService.createUser({
      username: dto.username,
      email: dto.email,
      password: hash,
    });

    // 3. Kép mentése, ha van
    if (profileImage) {
      await this.userService.updateUserProfile(createdUser.id, {
        profileImageData: profileImage.buffer,
        profileImageMimeType: profileImage.mimetype,
      });
    }

    // 4. Újratöltjük a user-t, hogy a frissített profil benne legyen
    const freshUser = await this.userService.findOne(dto.email);
    const fullProfile = await this.userService.findFullProfileByUserId(
      freshUser.id,
    );
    freshUser.profile = fullProfile;
    // 5. Tokenek generálása
    const tokens = await this.getTokens(
      freshUser.id,
      freshUser.email,
      freshUser.profile.id,
    );
    await this.updateRtHash(freshUser.id, tokens.refreshToken);

    // 6. Válasz összeállítása
    return await this.createUserResponseForAuth(
      freshUser,
      tokens,
      'Signup successful',
    );
  }

  async signinLocal(dto: SignInDto): Promise<AuthResponseDto> {
    const user = await this.userService.findOne(dto.email);

    if (!user) throw new ForbiddenException('Access denied');
    const checkPassword = await bcrypt.compare(dto.password, user.password);
    if (!checkPassword) throw new ForbiddenException('Access denied');
    if (user.profile === null) {
      throw new ForbiddenException('Access denied - profile null');
    }
    const tokens = await this.getTokens(user.id, user.email, user.profile.id);
    await this.updateRtHash(user.id, tokens.refreshToken);

    return await this.createUserResponseForAuth(user, tokens);
  }

  async logout(userId: number) {
    return await this.userService.updateRefreshToken(userId, null);
  }
  async refreshTokens(userId: number, rt: string) {
    const user = await this.findUserById(userId);
    if (!user || !user.hashedRt) throw new ForbiddenException('Access denied');
    const checkRefreshTokens = await bcrypt.compare(rt, user.hashedRt);
    if (!checkRefreshTokens) throw new ForbiddenException('Access denied');
    if (user.profile === null) {
      throw new ForbiddenException('Access denied - profile null');
    }
    const tokens = await this.getTokens(userId, user.email, user.profile.id);
    await this.updateRtHash(userId, tokens.refreshToken);
    return tokens;
  }

  async updateRtHash(userId: number, refreshToken: string) {
    const hash = await this.hashData(refreshToken);
    await this.userService.updateRefreshToken(userId, hash);
  }

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }

  async getTokens(userId: number, email: string, profileId: number) {
    const jwtPayload = { sub: userId, email, profileId };
    const [at, rt] = await Promise.all([
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.AT_SECRET,
        expiresIn: process.env.AT_EXPIRES_IN || '7d',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.RT_SECRET,
        expiresIn: process.env.RT_EXPIRES_IN || '30d',
      }),
    ]);

    return {
      accessToken: at,
      refreshToken: rt,
    };
  }
  async resetPassword(userId: number, dto: ResetPasswordDto): Promise<string> {
    const user = await this.findUserById(userId);
    if (!user) throw new ForbiddenException('User not found');

    const isMatch = await bcrypt.compare(dto.oldPassword, user.password);
    if (!isMatch) throw new ForbiddenException('Incorrect current password');

    const hashedPassword = await this.hashData(dto.newPassword);
    await this.userService.updatePassword(userId, hashedPassword);

    return 'Password updated successfully';
  }

  async resetPasswordViaEmail(email: string): Promise<void> {
    const user = await this.userService.findOne(email);

    if (!user) {
      throw new NotFoundException('No user found with that email');
    }

    const newPassword = this.generateRandomPassword();
    const hashed = await bcrypt.hash(newPassword, 10);

    // jelszó frissítése
    await this.userService.updatePassword(user.id, hashed);

    const html = `
  <div style="font-family: 'Segoe UI', Arial, sans-serif; background: #f9fafb; padding: 40px 20px; color: #333;">
  <div style="max-width: 520px; margin: 0 auto; background: #ffffff; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.08); overflow: hidden;">

    <!-- Header -->
    <div style="background: linear-gradient(90deg, #4CAF50, #66BB6A); padding: 25px; text-align: center;">
      <h1 style="color: #fff; margin: 0; font-size: 24px; letter-spacing: 0.5px;">Password Reset</h1>
    </div>

    <!-- Body -->
    <div style="padding: 30px;">
      <p style="font-size: 15px; margin-bottom: 16px;">Hello,</p>

      <p style="font-size: 15px; margin-bottom: 8px;">Your new password is:</p>
      <p style="font-size: 20px; font-weight: bold; color: #333; background: #f3f4f6; padding: 12px 18px; border-radius: 8px; display: inline-block; letter-spacing: 0.5px;">
        ${newPassword}
      </p>

      <p style="font-size: 15px; margin-top: 20px; line-height: 1.6;">
        Please log in to your account and change your password as soon as possible for security reasons.
      </p>

      <p style="font-size: 13px; color: #999; margin-top: 30px; border-top: 1px solid #eee; padding-top: 15px; line-height: 1.5;">
        🔒 This is an automated no-reply email. Please do not respond to this message.
      </p>
    </div>

    <!-- Footer -->
    <div style="background: #f9fafb; padding: 15px; text-align: center; font-size: 12px; color: #888;">
      © ${new Date().getFullYear()} <strong>Progr3ss</strong>. All rights reserved.
    </div>
  </div>
</div>
`;

    await this.mailjetService.sendEmail(user.email, 'Your New Password', html);
  }

  generateRandomPassword(length = 10): string {
    const chars =
      'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  }
}
