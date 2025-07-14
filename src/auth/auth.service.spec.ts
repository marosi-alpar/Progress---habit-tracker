import { Test, TestingModule } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { UserService } from 'src/user/user.service';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import { AuthDto, SignInDto } from './dto';

describe('AuthService', () => {
  let service: AuthService;
  let mockUserService: any;
  let mockJwtService: any;

  beforeEach(async () => {
    mockUserService = {
      findOne: jest.fn().mockResolvedValue(null), // ez kell mindenhol
      createUser: jest.fn().mockImplementation((dto) => ({
        id: 1,
        email: dto.email,
        auth_provider: 'local',
        profile: {},
      })),
      updateRefreshToken: jest.fn().mockResolvedValue(undefined),
      findOneById: jest
        .fn()
        .mockResolvedValue({ id: 1, email: '...', profile: {} }),
      updatePassword: jest.fn().mockResolvedValue(undefined),
    };

    mockJwtService = {
      signAsync: jest
        .fn()
        .mockImplementation((payload) => `token-for-${payload.sub}`),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: UserService, useValue: mockUserService },
        { provide: JwtService, useValue: mockJwtService },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('signupLocal', () => {
    it('should hash the password, create a user, and return tokens', async () => {
      const dto: AuthDto = {
        email: 'test@example.com',
        username: 'testuser',
        password: 'password123',
      };

      jest.spyOn(bcrypt, 'hash').mockResolvedValue('hashed-password');

      const result = await service.signupLocal(dto);

      expect(result.user.email).toBe(dto.email);
      expect(result.tokens.accessToken).toContain('token-for-');
      expect(mockUserService.createUser).toHaveBeenCalledWith({
        ...dto,
        password: 'hashed-password',
      });
    });
  });

  describe('signinLocal', () => {
    it('should return tokens if credentials are correct', async () => {
      const dto: SignInDto = {
        email: 'test@example.com',
        password: 'password123',
      };

      const hashedPassword = await bcrypt.hash(dto.password, 10);

      mockUserService.findOne.mockResolvedValueOnce({
        id: 1,
        email: dto.email,
        password: hashedPassword,
        auth_provider: 'local',
        profile: {},
      });

      jest.spyOn(bcrypt, 'compare').mockResolvedValue(true);

      const result = await service.signinLocal(dto);

      expect(result.user.email).toBe(dto.email);
      expect(result.tokens.accessToken).toContain('token-for-');
      expect(mockUserService.findOne).toHaveBeenCalledWith(dto.email);
    });

    it('should throw if user is not found', async () => {
      mockUserService.findOne.mockResolvedValue(null);

      await expect(
        service.signinLocal({
          email: 'notfound@example.com',
          password: 'irrelevant',
        }),
      ).rejects.toThrow('Access denied'); // fontos: kisbetűvel
    });

    it('should throw if password is incorrect', async () => {
      const dto: SignInDto = {
        email: 'test@example.com',
        password: 'wrongpass',
      };

      mockUserService.findOne.mockResolvedValue({
        id: 1,
        email: dto.email,
        password: await bcrypt.hash('correctpass', 10),
        auth_provider: 'local',
        profile: {},
      });

      jest.spyOn(bcrypt, 'compare').mockResolvedValue(false);

      await expect(service.signinLocal(dto)).rejects.toThrow('Access denied');
    });
  });
});
