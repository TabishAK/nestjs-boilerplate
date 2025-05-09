import { Module } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

import { EmailService } from './services/email.service';

@Module({
  providers: [EmailService, ConfigService],
  exports: [EmailService],
})
export class EmailModule {}
