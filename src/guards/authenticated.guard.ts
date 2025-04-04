import {
  CanActivate,
  ExecutionContext,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import { JwtPayload } from 'jsonwebtoken';
import { AUTH_ERRORS } from 'src/constants/api-response/auth.response';

@Injectable()
export class AuthenticatedGuard implements CanActivate {
  // @ts-ignore
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const authorizationHeader = request.headers.authorization;
    if (authorizationHeader && authorizationHeader.startsWith('Bearer ')) {
      const token = authorizationHeader.substring(7); // Remove 'Bearer ' prefix
      try {
        const timestamp = Math.floor(Date.now() / 1000);
        const tokenPayload = jwt.decode(token) as JwtPayload;
        if (!tokenPayload?.exp || timestamp > tokenPayload.exp) {
          throw new HttpException(
            {
              msg: AUTH_ERRORS.UNAUTHORIZED,
              status: HttpStatus.UNAUTHORIZED,
              success: false,
              data: null,
            },
            HttpStatus.UNAUTHORIZED
          );
        }
        return true;
      } catch (err) {
        throw new HttpException(
          {
            msg: AUTH_ERRORS.UNAUTHORIZED,
            status: HttpStatus.UNAUTHORIZED,
            success: false,
            data: null,
          },
          HttpStatus.UNAUTHORIZED
        );
      }
    }
  }
}
