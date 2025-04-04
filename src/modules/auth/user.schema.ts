import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { AUTH_PROVIDER } from 'src/types/users.type';

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true })
  name: string;

  @Prop({ required: true, unique: true })
  email: string;

  @Prop({ required: true })
  password: string;

  @Prop({ required: true })
  isTermsAgree: boolean;

  @Prop({ required: true, default: false })
  emailVerified: boolean;

  @Prop({ required: true, default: AUTH_PROVIDER.CUSTOM })
  provider: AUTH_PROVIDER;
}

export const UserSchema = SchemaFactory.createForClass(User);

export type UserDocument = User & Document;
