import { Response } from 'express';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { Body, Controller, Get, Post, Res, UseGuards } from '@nestjs/common';
import { EMAIL_SUBJECT } from '../../types/email.type';
import { GoogleDto } from './dto/google.dto';
import { SignupDto } from './dto/signup.dto';
import { SignInDto } from './dto/signin.dto';

import { OtpDto } from './dto/otp.dto';
import {
  UserEmailDto,
  VerifyResetPasswordDto,
} from './dto/forgot-password.dto';
import { AuthService } from './auth.service';
import { OtpService } from './otp.service';
import { OTP_TYPE } from 'src/types/otp.type';
import { JwtAuthGuard } from 'src/guards/jwt-auth.guard';
import { GetUser } from 'src/decorator/user.decorator';
import { UserService } from '../user/user.service';

@Controller('auth')
@ApiTags('Auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private readonly otpService: OtpService,
    private readonly userService: UserService
  ) {}

  @ApiBearerAuth()
  @Get('get-authenticated-user')
  @UseGuards(JwtAuthGuard)
  getAuthenticatedUser(@GetUser('id') userId: string) {
    return this.userService.findOne(userId);
  }

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
    return this.otpService.generateOTP(
      data,
      OTP_TYPE.FORGOT_PASSWORD,
      EMAIL_SUBJECT.FORGOT_PASSWORD_OTP
    );
  }

  @Post('verify-forgot-password-otp')
  async verifyForgotPasswordOtp(@Body() userInput: OtpDto) {
    return this.otpService.validateOTP(userInput, OTP_TYPE.FORGOT_PASSWORD);
  }

  @Post('verify-reset-password')
  async verifyResetPassword(@Body() data: VerifyResetPasswordDto) {
    return this.authService.verifyResetPassword(data);
  }

  @Post('verify-signup-otp')
  async verifySignupOtp(@Body() userInput: OtpDto) {
    return this.otpService.verifySignupOtp(userInput);
  }
}
