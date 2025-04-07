import * as fs from 'fs';
import * as path from 'path';
import * as sgMail from '@sendgrid/mail';
import * as Handlebars from 'handlebars';
import { ConfigService } from '@nestjs/config';
import { Injectable, Logger } from '@nestjs/common';

import { SendEmailDto } from '../dto/send-email.dto';
import { CONFIG } from 'src/constants/config';
@Injectable()
export class EmailService {
  private readonly logger = new Logger(EmailService.name);

  constructor(private readonly configService: ConfigService) {
    const sendGridApiKey = this.configService.get<string>(
      CONFIG.SENDGRID_API_KEY
    );
    sgMail.setApiKey(sendGridApiKey ?? '');
  }

  async loadTemplate(templateName: string, context: Record<string, any>) {
    const filePath = path.resolve(`src/email-templates/${templateName}.hbs`);
    const templateSource = fs.readFileSync(filePath, 'utf-8');
    const template = Handlebars.compile(templateSource);
    return template(context);
  }

  async sendEmail(email: SendEmailDto) {
    const msg = {
      to: email.to,
      html: email.html,
      subject: email.subject,
      from: this.configService.get<string>(CONFIG.SENDGRID_SENDER) ?? '',
    };

    try {
      await sgMail.send(msg);
    } catch (error) {
      console.error('Error sending dynamic email:', error);
      if (error.response) {
        console.error(error.response.body);
      }
    }
  }
}
