import { Module } from '@nestjs/common';

// import { LoggerService } from 'src/shared/logger/logger.service';
import { MediaService } from './media.service';
import { MediaController } from './media.controller';

@Module({
  controllers: [MediaController],
  providers: [MediaService],
})
export class MediaModule {}
