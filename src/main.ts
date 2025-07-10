import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { ValidationPipe } from '@nestjs/common';
import { AllExceptionsFilter } from './filters/all-exceptions.filter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  app.useGlobalFilters(new AllExceptionsFilter());
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // csak DTO-ban definiált mezők mennek át
      forbidNonWhitelisted: true, // tiltja az extra mezőket
      transform: true, // automatikusan konvertál típusokra
    }),
  );

  // 🔧 Swagger configuration with Bearer Token
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
      'access-token', // You can name this, see below how to match it in controllers
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

  // 📄 Create and mount the Swagger document
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document); // Swagger UI at /api

  await app.listen(3000);
}
bootstrap();
