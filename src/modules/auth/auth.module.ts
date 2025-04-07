import { Module } from '@nestjs/common';
import { MongooseModule } from '@nestjs/mongoose';
import { JwtModule } from '@nestjs/jwt';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { EmailModule } from 'src/modules/email/email.module';
import { Otp, OtpSchema } from 'src/modules/auth/otp.schema';
import { CONFIG } from 'src/constants/config';
import { AuthController } from 'src/modules/auth/auth.controller';
import { AuthService } from 'src/modules/auth/auth.service';
import { OtpService } from 'src/modules/auth/otp.service';
import { User, UserSchema } from '../user/user.schema';
import { UserService } from '../user/user.service';
import { JwtStrategy } from 'src/strategies/jwt.strategy';

@Module({
  imports: [
    MongooseModule.forFeature([
      { name: User.name, schema: UserSchema },
      { name: Otp.name, schema: OtpSchema },
    ]),
    EmailModule,
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        return {
          secret: configService.get<string>(CONFIG.JWT_SECRET),
        };
      },
    }),
  ],
  controllers: [AuthController],
  providers: [AuthService, OtpService, UserService, JwtStrategy],
  exports: [AuthService, JwtStrategy],
})
export class AuthModule {}
