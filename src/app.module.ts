// THIS IS AUTO GENERATED CODE
//DO NOT UPDATE IT!!

import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { CONFIG } from 'src/constants/config';
import { AuthModule } from './modules/auth/auth.module';
import { MediaModule } from './modules/media/media.module';

//AUTO GENERATED MODULES
import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';

@Module({
  imports: [
      AuthModule,
MediaModule,
 // load the appropriate env file, cache it and make it available globally
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      envFilePath: `.env.${process.env.NODE_ENV}`,
    }),
    // connection for central db
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (configService: ConfigService) => ({
        uri: configService.get<string>(CONFIG.MONGODB_URI),
      }),
      inject: [ConfigService],
    }),
    ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
