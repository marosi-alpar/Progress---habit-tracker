import {
  Body,
  Controller,
  Post,
  HttpStatus,
  UseGuards,
  Inject,
  HttpCode,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto, AuthResponseDto, SignInDto } from './dto';
import { RtGuard } from './common/guards';
import { GetCurrentUser, GetCurrentUserId, Public } from './common/decorators';
import {
  ApiTags,
  ApiOperation,
  ApiBody,
  ApiResponse,
  ApiBearerAuth,
  ApiConsumes,
} from '@nestjs/swagger';
import { ResetPasswordDto } from './dto/reset.password.dto';
import { FileInterceptor } from '@nestjs/platform-express';
import * as Multer from 'multer';
import { Tokens } from './types';

@ApiTags('Authentication')
@Controller('auth')
export class AuthController {
  constructor(
    @Inject('AUTH_SERVICE')
    private authService: AuthService,
  ) {}

  @Public()
  @Post('google')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Google Sign-In',
    description: 'Authenticate user with Google ID token.',
  })
  @ApiBody({ schema: { example: { idToken: 'eyJhbGciOiJSUzI1NiIsInR5c...' } } })
  @ApiResponse({
    status: 200,
    description: 'Successful Google login.',
    type: AuthResponseDto,
  })
  async googleAuth(@Body('idToken') idToken: string): Promise<AuthResponseDto> {
    return this.authService.handleGoogleAuth(idToken);
  }

  @Public()
  @Post('local/signup')
  @HttpCode(HttpStatus.CREATED)
  @UseInterceptors(FileInterceptor('profileImage'))
  @ApiOperation({
    summary: 'Local Sign-Up with optional profile image',
    description:
      'Register user with email, password and optional profile image.',
  })
  @ApiResponse({
    status: 201,
    description: 'Successful registration.',
    type: AuthResponseDto,
  })
  @ApiConsumes('multipart/form-data') // 💡 Ezt feltétlenül add hozzá
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        username: { type: 'string', example: 'john_doe' },
        email: { type: 'string', format: 'email', example: 'john@example.com' },
        password: {
          type: 'string',
          format: 'password',
          example: 'StrongPass123!',
        },
        profileImage: {
          type: 'string',
          format: 'binary',
        },
      },
      required: ['username', 'email', 'password'],
    },
  })
  async signupLocal(
    @UploadedFile() profileImage: Multer.File,
    @Body() dto: AuthDto,
  ): Promise<AuthResponseDto> {
    console.log('profile image binary: ', profileImage);
    return this.authService.signupLocal(dto, profileImage);
  }

  @Public()
  @Post('local/signin')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Local Sign-In',
    description: 'Authenticate with email and password.',
  })
  @ApiResponse({
    status: 200,
    description: 'Successful login.',
    type: AuthResponseDto,
  })
  async signinLocal(@Body() dto: SignInDto): Promise<AuthResponseDto> {
    return this.authService.signinLocal(dto);
  }

  @Post('local/logout')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout', description: 'Logs out the user.' })
  @ApiBearerAuth('access-token')
  @ApiResponse({ status: 200, description: 'Successfully logged out.' })
  async logout(@GetCurrentUser('sub') userId: number) {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('local/refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Refresh Tokens',
    description: 'Refresh access and refresh tokens.',
  })
  @ApiBearerAuth('refresh-token')
  @ApiResponse({
    status: 200,
    description: 'Tokens refreshed successfully.',
    type: Tokens,
  })
  async refreshTokens(
    @GetCurrentUserId() userId: number,
    @GetCurrentUser('refreshToken') refreshToken: string,
  ) {
    return this.authService.refreshTokens(userId, refreshToken);
  }

  @Post('local/reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiBearerAuth('access-token')
  @ApiOperation({
    summary: 'Reset Password',
    description:
      'Allows authenticated users to change their password by providing the current password.',
  })
  @ApiResponse({ status: 200, description: 'Password reset successful.' })
  @ApiResponse({ status: 403, description: 'Incorrect current password.' })
  @ApiResponse({ status: 404, description: 'User not found.' })
  async resetPassword(
    @GetCurrentUserId() userId: number,
    @Body() dto: ResetPasswordDto,
  ): Promise<{ message: string }> {
    const msg = await this.authService.resetPassword(userId, dto);
    return { message: msg };
  }
}
