import {
  Controller,
  Post,
  Body,
  Patch,
  Param,
  Delete,
  HttpCode,
  ParseIntPipe,
} from '@nestjs/common';
import { ProgressService } from './progress.service';
import { CreateProgressDto } from './dto/create-progress.dto';
import { UpdateProgressDto } from './dto/update-progress.dto';
import { ProgressResponseDto } from './dto/progress-response.dto';
import {
  ApiTags,
  ApiBearerAuth,
  ApiOperation,
  ApiResponse,
  ApiParam,
} from '@nestjs/swagger';
import { GetCurrentUserId } from 'src/auth/common/decorators';

@ApiTags('Progress')
@ApiBearerAuth('access-token')
@Controller('progress')
export class ProgressController {
  constructor(private readonly progressService: ProgressService) {}

  @Post()
  @ApiOperation({ summary: 'Create progress for a schedule' })
  @ApiResponse({ status: 201, type: ProgressResponseDto })
  async create(
    @GetCurrentUserId() userId: number,
    @Body() dto: CreateProgressDto,
  ): Promise<ProgressResponseDto> {
    return this.progressService.create(dto, userId);
  }

  @Patch(':id')
  @HttpCode(200)
  @ApiOperation({ summary: 'Update your own progress' })
  @ApiParam({ name: 'id', type: Number })
  @ApiResponse({ status: 200, type: ProgressResponseDto })
  async update(
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: UpdateProgressDto,
    @GetCurrentUserId() userId: number,
  ): Promise<ProgressResponseDto> {
    return this.progressService.update(id, dto, userId);
  }

  @Delete(':id')
  @HttpCode(200)
  @ApiOperation({ summary: 'Delete your own progress' })
  @ApiParam({ name: 'id', type: Number })
  @ApiResponse({ status: 200, description: 'Progress deleted successfully' })
  async remove(
    @Param('id', ParseIntPipe) id: number,
    @GetCurrentUserId() userId: number,
  ): Promise<{ message: string }> {
    return this.progressService.remove(id, userId);
  }
}
