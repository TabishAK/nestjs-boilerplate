import * as bcrypt from 'bcrypt';
import { Model, Types } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { HttpStatus, Injectable, UnauthorizedException } from '@nestjs/common';

import { SerializeHttpResponse } from 'src/utils/serializer';
import { OtpService } from './otp.service';
import { EmailService } from '../email/services/email.service';

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
import { createHashPassword } from 'src/utils/auth.util';
import { OTP_TYPE } from 'src/types/otp.type';
import { EMAIL_SUBJECT } from 'src/types/email.type';
import { SignInDto } from './dto/signin.dto';
import {
  UserEmailDto,
  VerifyResetPasswordDto,
} from './dto/forgot-password.dto';
import { ITemplates } from 'src/types/templates.type';
import { TOKEN_TYPES } from 'src/constants/auth';
import { OtpDto } from './dto/otp.dto';
import { User } from '../user/user.schema';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly jwtService: JwtService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly configService: ConfigService
  ) {}

  async verifyPassword(plainTextPassword: string, hashedPassword: string) {
    return bcrypt.compare(plainTextPassword, hashedPassword);
  }

  async validateUser(email: string, password: string): Promise<any> {
    const user = await this.userModel.findOne({ email });
    if (user && (await bcrypt.compare(password, user.password))) {
      if (user.emailVerified) {
        throw new UnauthorizedException(AUTH_ERRORS.EMAIL_NOT_VERIFIED);
      }

      const { password, ...result } = user.toObject();
      return result;
    }
    return null;
  }

  async verifyToken(token: string, type: TOKEN_TYPES) {
    try {
      const secret = this.configService.get<string>(CONFIG.JWT_SECRET);
      const response = await this.jwtService.verify(token, { secret });
      if (response.type !== type) {
        return { success: false, msg: AUTH_ERRORS.INVALID_TOKEN };
      }
      return { success: true, msg: AUTH_SUCCESS.VALID_TOKEN };
    } catch {
      return { success: false, msg: AUTH_ERRORS.INVALID_TOKEN };
    }
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
      true,
      HttpStatus.CREATED,
      AUTH_SUCCESS.ACCOUNT_CREATION
    );
  }

  async signIn(data: SignInDto) {
    const user = await this.userModel.findOne({
      email: data.email.toLowerCase(),
    });

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        AUTH_ERRORS.INCORRECT_CREDENTIALS
      );
    }

    const verify = await this.verifyPassword(data.password, user.password);

    if (!verify) {
      return SerializeHttpResponse(
        null,
        HttpStatus.UNAUTHORIZED,
        AUTH_ERRORS.INCORRECT_CREDENTIALS
      );
    }

    const token = await this.generateToken(
      user._id.toString(),
      user.email,
      DEFAULT_TOKEN_VALIDITY,
      TOKEN_TYPES.SIGNIN_TOKEN
    );

    return SerializeHttpResponse(
      { token, user: user.toJSON() },
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
      user._id.toString(),
      user.email,
      EMAIL_TOKEN_VALIDITY,
      TOKEN_TYPES.RESET_PASSWORD_TOKEN
    );

    const emailData = {
      name: user.firstName,
      email: data.email,
      token: token,
      url: this.configService.get<string>(CONFIG.FRONTEND_URL),
    };

    const template = await this.emailService.loadTemplate(
      ITemplates.FORGOT_PASSWORD,
      emailData
    );

    const msg = {
      to: data.email,
      subject: 'Forgot Password',
      html: template,
    };

    await this.emailService.sendEmail(msg);

    return SerializeHttpResponse(
      null,
      HttpStatus.OK,
      AUTH_SUCCESS.FORGOT_PASSWORD
    );
  }

  async verifyResetPassword(data: VerifyResetPasswordDto) {
    const verifiedToken = await this.verifyToken(
      data.token,
      TOKEN_TYPES.RESET_PASSWORD_TOKEN
    );

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
