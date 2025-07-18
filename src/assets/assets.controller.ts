import { Controller, Get, Param, Res, NotFoundException } from '@nestjs/common';
import { Response } from 'express';
import { join } from 'path';
import { existsSync } from 'fs';
import { ApiTags, ApiOperation, ApiParam } from '@nestjs/swagger';
import { Public } from 'src/auth/common/decorators';

@ApiTags('Assets')
@Public()
@Controller()
export class AssetsController {
  private readonly publicPath = join(process.cwd(), 'public');

  @Get('icons/:filename')
  @ApiOperation({ summary: 'Get icon file' })
  @ApiParam({ name: 'filename', description: 'Icon filename with extension' })
  async getIcon(
    @Param('filename') filename: string,
    @Res() res: Response,
  ): Promise<void> {
    // Biztonsági ellenőrzés
    if (!/^[a-zA-Z0-9\-_.]+\.(svg|png|jpg|jpeg|gif|webp)$/i.test(filename)) {
      throw new NotFoundException('Invalid filename');
    }

    const filePath = join(this.publicPath, 'icons', filename);

    console.log('Looking for file at:', filePath);
    console.log('File exists:', existsSync(filePath));

    if (!existsSync(filePath)) {
      throw new NotFoundException(`Icon file not found: ${filename}`);
    }

    // Content-type beállítása a fájl kiterjesztés alapján
    const ext = filename.split('.').pop()?.toLowerCase();
    const contentTypes = {
      svg: 'image/svg+xml',
      png: 'image/png',
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      gif: 'image/gif',
      webp: 'image/webp',
    };

    res.setHeader(
      'Content-Type',
      contentTypes[ext] || 'application/octet-stream',
    );
    res.setHeader('Cache-Control', 'public, max-age=31536000');

    res.sendFile(filePath);
  }
}
