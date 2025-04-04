import { Model } from 'mongoose';
import * as OTPAuth from 'otpauth';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { HttpStatus, Injectable } from '@nestjs/common';
import { User } from './user.schema';
import { Otp } from './otp.schema';
import { EmailService } from '../email/services/email.service';
import { CONFIG } from 'src/constants/config';
import { GenerateOtpDto, OtpDto } from './dto/otp.dto';
import { OTP_TYPE } from 'src/types/otp.type';
import { EMAIL_SUBJECT } from 'src/types/email.type';
import { SerializeHttpResponse } from 'src/utils/serializer';
import { AUTH_ERRORS } from 'src/constants/api-response/auth.response';
import { getCurrentFullYear } from 'src/utils/auth.util';
import { ITemplates } from 'src/types/templates.type';
import {
  OTP_ERROR,
  OTP_SUCCESS,
} from 'src/constants/api-response/otp.response';

@Injectable()
export class OtpService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(Otp.name) private readonly otpModel: Model<Otp>,
    private readonly configService: ConfigService,
    private readonly emailService: EmailService
  ) {}
  private createTotpInstance(email: string) {
    return new OTPAuth.TOTP({
      issuer: this.configService.get<string>(CONFIG.ISSUER),
      label: email,
      algorithm: 'SHA1',
      digits: 6,
      period: 60,
      secret: this.configService.get<string>(CONFIG.OTP_SECRET),
    });
  }

  async generateOTP(
    userInput: GenerateOtpDto,
    accessType: OTP_TYPE,
    subject: EMAIL_SUBJECT
  ) {
    try {
      const user = await this.userModel.findOne({ email: userInput.email });
      if (!user) {
        return SerializeHttpResponse(
          null,
          HttpStatus.NOT_FOUND,
          AUTH_ERRORS.USER_NOT_FOUND
        );
      }

      const totp = this.createTotpInstance(userInput.email);
      const otp = totp.generate();

      await this.otpModel.create({
        email: userInput.email,
        accessType,
        otp,
        isVerified: false,
      });

      const emailData = {
        name: user.name,
        email: user.email,
        currentYear: getCurrentFullYear(),
        otp: otp,
      };

      const template = await this.emailService.loadTemplate(
        ITemplates.OTP,
        emailData
      );

      const msg = { to: user.email, subject: subject, html: template };

      await this.emailService.sendEmail(msg);

      return SerializeHttpResponse(
        null,
        HttpStatus.OK,
        OTP_SUCCESS.GENERATE_OTP
      );
    } catch (err) {
      return SerializeHttpResponse(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        OTP_ERROR.GENERATE_OTP
      );
    }
  }

  async validateOTP(userInput: OtpDto, accessType: OTP_TYPE) {
    try {
      const otpRecord = await this.otpModel.findOne({
        email: userInput.email,
        otp: userInput.otp,
        accessType: accessType,
      });

      if (!otpRecord) {
        return SerializeHttpResponse(
          null,
          HttpStatus.FORBIDDEN,
          OTP_ERROR.NOT_VERIFIED_OTP
        );
      }

      if (otpRecord.isVerified) {
        return SerializeHttpResponse(
          null,
          HttpStatus.FORBIDDEN,
          OTP_ERROR.NOT_VERIFIED_OTP
        );
      }

      const totp = this.createTotpInstance(userInput.email);
      const isValid = totp.validate({ token: userInput.otp, window: 1 });

      if (isValid !== null) {
        // Mark OTP as verified
        otpRecord.isVerified = true;
        await otpRecord.save();

        // Update user as email verified
        await this.userModel.findOneAndUpdate(
          { email: userInput.email },
          { emailVerified: true }
        );

        return SerializeHttpResponse(
          null,
          HttpStatus.OK,
          OTP_SUCCESS.VERIFIED_OTP
        );
      } else {
        return SerializeHttpResponse(
          null,
          HttpStatus.FORBIDDEN,
          OTP_ERROR.NOT_VERIFIED_OTP
        );
      }
    } catch (err) {
      return SerializeHttpResponse(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        OTP_ERROR.VERIFIED_OTP
      );
    }
  }
}
