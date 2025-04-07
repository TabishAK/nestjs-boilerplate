import * as bcrypt from 'bcrypt';
import { Model, Types } from 'mongoose';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { InjectModel } from '@nestjs/mongoose';
import { OAuth2Client } from 'google-auth-library';
import { Injectable, HttpStatus } from '@nestjs/common';
import { User, UserDocument } from '../user/user.schema';
import { CONFIG, DEFAULT_TOKEN_VALIDITY } from 'src/constants/config';
import { generateRandomString } from 'src/utils/auth.util';
import { AUTH_PROVIDER } from 'src/constants/auth';
import { SerializeHttpResponse } from 'src/utils/serializer';
import {
  AUTH_ERRORS,
  AUTH_SUCCESS,
} from 'src/constants/api-response/auth.response';

@Injectable()
export class SocialAuthService {
  private googleClient: OAuth2Client;

  constructor(
    @InjectModel(User.name) private readonly userModel: Model<User>,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {
    this.googleClient = new OAuth2Client(
      this.configService.get<string>(CONFIG.GOOGLE_CLIENT_ID),
      this.configService.get<string>(CONFIG.GOOGLE_CLIENT_SECRET)
    );
  }

  private generateToken(
    userId: Types.ObjectId,
    email: string,
    expiresIn: string
  ) {
    const payload = { sub: userId, email };
    const secret = this.configService.get<string>(CONFIG.JWT_SECRET);

    return this.jwtService.sign(payload, { secret, expiresIn });
  }

  private async createNewUser(payload: any) {
    const saltOrRounds = 10;
    const password = generateRandomString();
    const hashedPassword = await bcrypt.hash(password, saltOrRounds);

    const newUser = new this.userModel({
      name: payload.name,
      email: payload.email,
      password: hashedPassword,
      isTermsAgree: true,
      provider: AUTH_PROVIDER.GOOGLE,
      emailVerified: true,
    });

    await newUser.save();
    return newUser;
  }

  private loginUser(user: UserDocument) {
    const token = this.generateToken(
      user._id as Types.ObjectId,
      user.email,
      DEFAULT_TOKEN_VALIDITY
    );
    return {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      _id: user._id,
      token,
    };
  }

  async verifyGoogleToken(idToken: string) {
    try {
      const ticket = await this.googleClient.verifyIdToken({
        idToken,
        audience: this.configService.get<string>(CONFIG.GOOGLE_CLIENT_ID),
      });

      const payload = ticket.getPayload();
      const user = await this.userModel.findOne({ email: payload?.email });

      if (!user) {
        const newUser = await this.createNewUser(payload);
        const loggedData = this.loginUser(newUser);

        return SerializeHttpResponse(
          loggedData,
          HttpStatus.CREATED,
          AUTH_SUCCESS.GOOGLE_ACCOUNT_CREATION
        );
      } else {
        const loggedUser = this.loginUser(user);

        return SerializeHttpResponse(
          loggedUser,
          HttpStatus.OK,
          AUTH_SUCCESS.ACCOUNT_LOGIN
        );
      }
    } catch {
      return SerializeHttpResponse(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        AUTH_ERRORS.ACCOUNT_LOGIN
      );
    }
  }
}
