import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { AuthResponseDto } from './dto/auth.response.dto';

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
});
