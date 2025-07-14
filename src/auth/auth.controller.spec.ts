import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthDto, SignInDto } from './dto';
import { AuthResponseDto } from './dto/auth.response.dto';
import { UpdateResult } from 'typeorm';

describe('AuthController', () => {
  let controller: AuthController;
  let mockAuthService: Partial<AuthService>;

  beforeEach(async () => {
    mockAuthService = {
      signupLocal: jest.fn().mockResolvedValue({
        message: 'Signup successful',
        user: {
          id: 1,
          email: 'test@example.com',
          auth_provider: 'local',
          profile: {},
        },
        tokens: {
          accessToken: 'mockAccessToken',
          refreshToken: 'mockRefreshToken',
        },
      } as AuthResponseDto),

      signinLocal: jest.fn().mockResolvedValue({
        message: 'Signin successful',
        user: {
          id: 1,
          email: 'test@example.com',
          auth_provider: 'local',
          profile: {},
        },
        tokens: {
          accessToken: 'mockAccessToken',
          refreshToken: 'mockRefreshToken',
        },
      } as AuthResponseDto),

      logout: jest.fn().mockResolvedValue({
        affected: 1,
      } as UpdateResult),

      refreshTokens: jest.fn().mockResolvedValue({
        accessToken: 'newAccessToken',
        refreshToken: 'newRefreshToken',
      }),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: 'AUTH_SERVICE',
          useValue: mockAuthService,
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should signup a user locally', async () => {
    const dto: AuthDto = {
      username: 'testuser',
      email: 'test@example.com',
      password: 'secret',
    };

    const result = await controller.signupLocal(dto);
    expect(result.message).toBe('Signup successful');
    expect(mockAuthService.signupLocal).toHaveBeenCalledWith(dto);
  });

  it('should sign in a user locally', async () => {
    const dto: SignInDto = {
      email: 'test@example.com',
      password: 'secret',
    };

    const result = await controller.signinLocal(dto);
    expect(result.message).toBe('Signin successful');
    expect(mockAuthService.signinLocal).toHaveBeenCalledWith(dto);
  });

  it('should logout a user', async () => {
    const userId = 1;

    const result = await controller.logout(userId);
    expect(result.affected).toBe(1);
    expect(mockAuthService.logout).toHaveBeenCalledWith(userId);
  });

  it('should refresh tokens', async () => {
    const userId = 1;
    const refreshToken = 'oldRefreshToken';

    const result = await controller.refreshTokens(userId, refreshToken);
    expect(result.accessToken).toBe('newAccessToken');
    expect(mockAuthService.refreshTokens).toHaveBeenCalledWith(
      userId,
      refreshToken,
    );
  });
});
