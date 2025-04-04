import { Response } from 'express';
import { ApiTags } from '@nestjs/swagger';
import { Body, Controller, Post, Res } from '@nestjs/common';
import { EMAIL_SUBJECT } from '../../types/email.type';
import { GoogleDto } from './dto/google.dto';
import { SignupDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';

import { GenerateOtpDto, OtpDto } from './dto/otp.dto';
import {
  UserEmailDto,
  VerifyResetPasswordDto,
} from './dto/forgot-password.dto';
import { AuthService } from './auth.service';
import { OtpService } from './otp.service';
import { OTP_TYPE } from 'src/types/otp.type';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly otpService: OtpService
  ) {}

  @Post('signup')
  signup(@Body() signUpDto: SignupDto) {
    return this.authService.signup(signUpDto);
  }

  @Post('login')
  async login(@Body() signInDto: SignInDto) {
    return this.authService.signIn(signInDto);
  }

  @Post('forgot-password')
  async forgotPassword(@Body() data: UserEmailDto) {
    return this.authService.forgotPassword(data);
  }

  @Post('google/callback')
  async handleGoogleAuth(@Body() googleDto: GoogleDto) {
    return this.authService.handleGoogleAuth(googleDto);
  }

  @Post('verify-reset-password')
  async verifyResetPassword(@Body() data: VerifyResetPasswordDto) {
    return this.authService.verifyResetPassword(data);
  }

  @Post('forgot-password-otp')
  async generate(@Body() userInput: GenerateOtpDto) {
    return this.otpService.generateOTP(
      userInput,
      OTP_TYPE.FORGOT_PASSWORD,
      EMAIL_SUBJECT.FORGOT_PASSWORD_OTP
    );
  }

  @Post('verify-forgot-password-otp')
  async verifyForgotPasswordOtp(@Body() userInput: OtpDto) {
    return this.otpService.validateOTP(userInput, OTP_TYPE.FORGOT_PASSWORD);
  }

  @Post('verify-signup-otp')
  async verifySignupOtp(@Body() userInput: OtpDto) {
    return this.otpService.validateOTP(userInput, OTP_TYPE.SIGNUP);
  }

  @Post('resend-signup-otp')
  async resendSignupOtp(@Body() userInput: GenerateOtpDto) {
    return this.otpService.generateOTP(
      userInput,
      OTP_TYPE.SIGNUP,
      EMAIL_SUBJECT.SIGNUP_OTP
    );
  }
}
