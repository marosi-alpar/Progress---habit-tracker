import {
  ForbiddenException,
  Injectable,
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

@Injectable()
export class AuthService {
  private client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
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
    message: string = 'Login successful',
  ): Promise<AuthResponseDto> {
    const safeUser: UserResponseDto = {
      id: user.id,
      email: user.email,
      auth_provider: user.auth_provider,
      profile: user.profile,
    };

    const response: AuthResponseDto = {
      message,
      user: safeUser,
      tokens,
    };

    return response;
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

  async signupLocal(dto: AuthDto): Promise<AuthResponseDto> {
    const hash = await this.hashData(dto.password);

    const createdUser = await this.userService.createUser({
      username: dto.username,
      email: dto.email,
      password: hash,
    });

    const tokens = await this.getTokens(
      createdUser.id,
      createdUser.email,
      createdUser.profile.id,
    );
    await this.updateRtHash(createdUser.id, tokens.refreshToken);

    return await this.createUserResponseForAuth(
      createdUser,
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
        expiresIn: '1d',
      }),
      this.jwtService.signAsync(jwtPayload, {
        secret: process.env.RT_SECRET,
        expiresIn: '3d',
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
}
