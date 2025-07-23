import {
  Controller,
  Get,
  Param,
  ParseIntPipe,
  Post,
  Body,
} from '@nestjs/common';
import { HabitService } from './habit.service';
import { HabitResponseDto } from './dto/habit-response.dto';
import { CreateHabitDto } from './dto/create-habit.dto';
import {
  ApiTags,
  ApiOperation,
  ApiResponse,
  ApiBearerAuth,
  ApiParam,
} from '@nestjs/swagger';
import { GetCurrentUserId } from 'src/auth/common/decorators';
import { HabitCategory } from './entities/habit-category.entity';
import { HabitCategoryResponseDto } from './dto/habit-category-response.dto';

@ApiTags('Habit')
@ApiBearerAuth('access-token')
@Controller('habit')
export class HabitController {
  constructor(private habitService: HabitService) {}

  @Get()
  @ApiOperation({ summary: 'List all habits' })
  @ApiResponse({ status: 200, type: [HabitResponseDto] })
  async findAll(
    @GetCurrentUserId() userId: number,
  ): Promise<HabitResponseDto[]> {
    return this.habitService.findAll(userId);
  }

  @Post()
  @ApiOperation({ summary: 'Create a new habit' })
  @ApiResponse({ status: 201, type: HabitResponseDto })
  async create(
    @GetCurrentUserId() userId: number,
    @Body() habitData: CreateHabitDto,
  ): Promise<HabitResponseDto> {
    return this.habitService.create(habitData, userId);
  }

  @Get('user/:userId')
  @ApiOperation({ summary: 'Find habits by user ID' })
  @ApiParam({ name: 'userId', type: Number })
  @ApiResponse({ status: 200, type: [HabitResponseDto] })
  async findByUserId(
    @Param('userId', ParseIntPipe) userId: number,
  ): Promise<HabitResponseDto[]> {
    return this.habitService.findByUserId(userId);
  }

  @Get('categories')
  @ApiOperation({ summary: 'Get habit categories' })
  @ApiResponse({ status: 200, type: [HabitCategoryResponseDto] })
  async getCategories(): Promise<HabitCategoryResponseDto[]> {
    const categories = await this.habitService.findAllCategories();
    return categories.map((cat) => ({
      id: cat.id,
      name: cat.name,
      iconUrl: cat.iconUrl,
    }));
  }

  @Get(':habitId')
  @ApiOperation({ summary: 'Find habit by habit ID' })
  @ApiParam({ name: 'habitId', type: Number })
  @ApiResponse({ status: 200, type: HabitResponseDto })
  async findById(
    @Param('habitId', ParseIntPipe) habitId: number,
    @GetCurrentUserId() userId: number,
  ): Promise<HabitResponseDto> {
    return this.habitService.findById(habitId, userId);
  }
}
