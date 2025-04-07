import { Model } from 'mongoose';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { HttpStatus, Injectable } from '@nestjs/common';
import { Otp } from './otp.schema';
import { EmailService } from '../email/services/email.service';
import { CONFIG, EMAIL_TOKEN_VALIDITY } from 'src/constants/config';
import { OtpDto } from './dto/otp.dto';
import { OTP_TYPE } from 'src/types/otp.type';
import { EMAIL_SUBJECT } from 'src/types/email.type';
import { SerializeHttpResponse } from 'src/utils/serializer';
import { AUTH_ERRORS } from 'src/constants/api-response/auth.response';
import { generateRandomOTPNumber } from 'src/utils/auth.util';
import { ITemplates } from 'src/types/templates.type';
import {
  OTP_ERROR,
  OTP_SUCCESS,
} from 'src/constants/api-response/otp.response';
import { TOKEN_TYPES } from 'src/constants/auth';
import { JwtService } from '@nestjs/jwt';
import { UserEmailDto } from './dto/forgot-password.dto';
import { User } from '../user/user.schema';

@Injectable()
export class OtpService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    @InjectModel(Otp.name) private readonly otpModel: Model<Otp>,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService
  ) {}

  async generateOTP(
    userInput: UserEmailDto,
    accessType: OTP_TYPE,
    subject: EMAIL_SUBJECT
  ) {
    const user = await this.userModel.findOne({ email: userInput.email });

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        AUTH_ERRORS.USER_NOT_FOUND
      );
    }

    const otp = generateRandomOTPNumber(6);

    await this.otpModel.updateMany(
      { email: userInput.email, accessType },
      { isVerified: true }
    );

    await this.otpModel.create({
      otp,
      accessType,
      isVerified: false,
      email: userInput.email,
    });

    const emailData = { otp, name: user.firstName, email: user.email };
    const template = await this.emailService.loadTemplate(
      ITemplates.OTP,
      emailData
    );

    const msg = { to: user.email, subject, html: template };
    await this.emailService.sendEmail(msg);
    return SerializeHttpResponse(
      emailData,
      HttpStatus.OK,
      OTP_SUCCESS.GENERATE_OTP
    );
  }

  generateToken(
    userId: string,
    email: string,
    expiresIn: string,
    type: TOKEN_TYPES
  ) {
    const payload = { sub: userId, email, type };
    const secret = this.configService.get<string>(CONFIG.JWT_SECRET);

    return this.jwtService.sign(payload, { secret, expiresIn });
  }

  async validateOTP(userInput: OtpDto, accessType: OTP_TYPE) {
    const otpRecord = await this.otpModel.findOne({
      email: userInput.email,
      otp: userInput.otp,
      accessType: accessType,
    });

    if (!otpRecord) {
      return SerializeHttpResponse(
        null,
        HttpStatus.FORBIDDEN,
        OTP_ERROR.OTP_NOT_VERIFIED
      );
    }

    if (otpRecord.isVerified) {
      return SerializeHttpResponse(
        null,
        HttpStatus.FORBIDDEN,
        OTP_ERROR.OTP_EXPIRED
      );
    }

    otpRecord.isVerified = true;
    await otpRecord.save();

    const resetToken = this.generateToken(
      '',
      userInput.email,
      EMAIL_TOKEN_VALIDITY,
      TOKEN_TYPES.RESET_PASSWORD_TOKEN
    );

    return SerializeHttpResponse(
      { resetToken },
      HttpStatus.OK,
      OTP_SUCCESS.VERIFIED_OTP
    );
  }

  async verifySignupOtp(userInput: OtpDto) {
    const otpRecord = await this.otpModel.findOne({
      email: userInput.email,
      otp: userInput.otp,
      accessType: OTP_TYPE.SIGNUP,
    });

    if (!otpRecord) {
      return SerializeHttpResponse(
        null,
        HttpStatus.FORBIDDEN,
        OTP_ERROR.OTP_NOT_VERIFIED
      );
    }

    if (otpRecord.isVerified) {
      return SerializeHttpResponse(
        null,
        HttpStatus.FORBIDDEN,
        OTP_ERROR.OTP_EXPIRED
      );
    }

    otpRecord.isVerified = true;
    await otpRecord.save();

    await this.userModel.findOneAndUpdate(
      { email: userInput.email.toLowerCase() },
      { emailVerified: true }
    );

    return SerializeHttpResponse(true, HttpStatus.OK, OTP_SUCCESS.VERIFIED_OTP);
  }
}
