import * as bcrypt from 'bcrypt';
import { Model, Types } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { HttpStatus, Injectable } from '@nestjs/common';

import { SerializeHttpResponse } from 'src/utils/serializer';
import { OtpService } from './otp.service';
import { User } from './user.schema';
import { EmailService } from '../email/services/email.service';
import { SocialAuthService } from './social-auth.service';
import {
  AUTH_ERRORS,
  AUTH_SUCCESS,
} from 'src/constants/api-response/auth.response';
import {
  CONFIG,
  DEFAULT_TOKEN_VALIDITY,
  EMAIL_TOKEN_VALIDITY,
} from 'src/constants/config';
import { SignupDto } from './dto/signup.dto';
import { createHashPassword, getCurrentFullYear } from 'src/utils/auth.util';
import { OTP_TYPE } from 'src/types/otp.type';
import { EMAIL_SUBJECT } from 'src/types/email.type';
import { SignInDto } from './dto/signin.dto';
import {
  UserEmailDto,
  VerifyResetPasswordDto,
} from './dto/forgot-password.dto';
import { ITemplates } from 'src/types/templates.type';
import { GoogleDto } from './dto/google.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly jwtService: JwtService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService,
    private readonly socialAuthService: SocialAuthService
  ) {}

  async verifyPassword(plainTextPassword: string, hashedPassword: string) {
    return bcrypt.compare(plainTextPassword, hashedPassword);
  }

  async verifyToken(token: string) {
    try {
      const secret = this.configService.get<string>(CONFIG.JWT_SECRET);
      await this.jwtService.verify(token, { secret });
      return { success: true, msg: AUTH_SUCCESS.VALID_TOKEN };
    } catch (error) {
      return { success: false, msg: AUTH_ERRORS.INVALID_TOKEN };
    }
  }

  async signup(data: SignupDto) {
    const user = await this.userModel.findOne({
      email: data.email.toLowerCase(),
    });

    if (user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.BAD_REQUEST,
        AUTH_ERRORS.DUPLICATE_EMAIL
      );
    }

    const hashedPassword = await createHashPassword(data.password);

    await this.userModel.create({ ...data, password: hashedPassword });

    const otpData = { email: data.email };

    await this.otpService.generateOTP(
      otpData,
      OTP_TYPE.SIGNUP,
      EMAIL_SUBJECT.SIGNUP_OTP
    );

    return SerializeHttpResponse(
      null,
      HttpStatus.CREATED,
      AUTH_SUCCESS.ACCOUNT_CREATION
    );
  }

  async generateToken(
    userId: Types.ObjectId,
    email: string,
    expiresIn: string
  ) {
    const payload = { sub: userId, email };
    const secret = this.configService.get<string>(CONFIG.JWT_SECRET);

    return this.jwtService.sign(payload, { secret, expiresIn });
  }

  async signIn(data: SignInDto) {
    const user = await this.userModel.findOne({
      email: data.email.toLowerCase(),
    });

    if (!user || !user.emailVerified) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        AUTH_ERRORS.USER_NOT_FOUND
      );
    }

    const verify = await this.verifyPassword(data.password, user.password);

    if (!verify) {
      return SerializeHttpResponse(
        null,
        HttpStatus.UNAUTHORIZED,
        AUTH_ERRORS.INCORRECT_PASSWORD
      );
    }

    const token = await this.generateToken(
      user._id,
      user.email,
      DEFAULT_TOKEN_VALIDITY
    );

    const loggedUser = {
      email: user.email,
      name: user.name,
      _id: user._id,
      token: token,
    };

    return SerializeHttpResponse(
      loggedUser,
      HttpStatus.OK,
      AUTH_SUCCESS.ACCOUNT_LOGIN
    );
  }

  async forgotPassword(data: UserEmailDto) {
    const user = await this.userModel.findOne({
      email: data.email.toLowerCase(),
    });

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        AUTH_ERRORS.USER_NOT_FOUND
      );
    }

    const token = await this.generateToken(
      user._id,
      user.email,
      EMAIL_TOKEN_VALIDITY
    );
    const emailData = {
      name: user.name,
      email: data.email,
      currentYear: getCurrentFullYear(),
      token: token,
      url: this.configService.get<string>(CONFIG.FRONTEND_URL),
    };

    const template = await this.emailService.loadTemplate(
      ITemplates.FORGOT_PASSWORD,
      emailData
    );

    const msg = {
      to: data.email,
      subject: 'Reset Password',
      html: template,
    };
    await this.emailService.sendEmail(msg);

    return SerializeHttpResponse(
      null,
      HttpStatus.OK,
      AUTH_SUCCESS.FORGOT_PASSWORD
    );
  }

  async handleGoogleAuth(data: GoogleDto) {
    return await this.socialAuthService.verifyGoogleToken(data.token);
  }

  async verifyResetPassword(data: VerifyResetPasswordDto) {
    const verifiedToken = await this.verifyToken(data.token);

    if (!verifiedToken.success) {
      return SerializeHttpResponse(
        null,
        HttpStatus.FORBIDDEN,
        AUTH_ERRORS.INVALID_TOKEN
      );
    }

    const hashedPassword = await createHashPassword(data.password);

    await this.userModel.findOneAndUpdate(
      { email: data.email.toLowerCase() },
      { password: hashedPassword }
    );

    return SerializeHttpResponse(
      null,
      HttpStatus.OK,
      AUTH_SUCCESS.RESET_PASSWORD
    );
  }
}
