import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Model } from 'mongoose';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from 'src/modules/user/user.schema';
import { USER_ROLES } from 'src/constants/user';
import { AUTH_ERRORS } from 'src/constants/api-response/auth.response';

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(
    private reflector: Reflector,
    @InjectModel(User.name) private userModel: Model<UserDocument>
  ) {}

  async canActivate(context: ExecutionContext) {
    const requiredRoles = this.reflector.getAllAndOverride<USER_ROLES[]>(
      'roles',
      [context.getHandler(), context.getClass()]
    );

    if (!requiredRoles) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest();
    const userData = await this.userModel.findById(user.id);

    if (!userData) {
      throw new UnauthorizedException(AUTH_ERRORS.UNAUTHORIZED);
    }

    return requiredRoles.some((role) => userData.role === role);
  }
}
