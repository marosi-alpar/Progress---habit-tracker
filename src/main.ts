import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AllExceptionsFilter } from './filters/all-exceptions.filter';
import { join } from 'path';
import { NestExpressApplication } from '@nestjs/platform-express';
import { HabitCategory } from './habit/entities/habit-category.entity';
import { DataSource } from 'typeorm';
async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);

  // Statikus fájlok kiszolgálása
  // A public mappa a projekt gyökérben van (src mellett)
  app.useStaticAssets(join(__dirname, '..', 'public'));

  app.useGlobalFilters(new AllExceptionsFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );

  const config = new DocumentBuilder()
    .setTitle('Progr3SS API')
    .setDescription('The backend API documentation')
    .setVersion('1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Enter your JWT access token',
        in: 'header',
      },
      'access-token',
    )
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        bearerFormat: 'JWT',
        name: 'Authorization',
        description: 'Enter your JWT refresh token',
      },
      'refresh-token',
    )
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  console.log('Static assets path:', join(__dirname, '..', 'public'));
  console.log('Server running on host ', process.env.HOST || '0.0.0.0');
  console.log('Server running on port ', process.env.PORT || 8080);

  const dataSource = app.get(DataSource);

  const categoryRepo = dataSource.getRepository(HabitCategory);

  const defaults = [
    { name: 'Exercise', iconUrl: '/icons/gym.svg' },
    { name: 'Reading', iconUrl: '/icons/read.svg' },
    { name: 'Study', iconUrl: '/icons/code.svg' },
    { name: 'Hydration', iconUrl: '/icons/water.svg' },
    { name: 'Writing', iconUrl: '/icons/write.svg' },
    { name: 'Running', iconUrl: '/icons/run.svg' },
    { name: 'Other', iconUrl: '/icons/other.svg' }, // ⬅️ EZ HIÁNYZOTT
  ];

  for (const data of defaults) {
    await categoryRepo.upsert(data, ['name']);
  }

  console.log('💾 HabitCategory újratöltve a public/icons mappából.');

  await app.listen(process.env.PORT || 8080, process.env.HOST || '0.0.0.0');
}
bootstrap();
