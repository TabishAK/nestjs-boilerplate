import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';
import { USER_ROLES } from 'src/constants/user';

@Schema({ timestamps: true })
export class User {
  @Prop({ required: true, trim: true, type: String })
  firstName: string;

  @Prop({ required: true, trim: true, type: String })
  lastName: string;

  @Prop({ required: true, trim: true, lowercase: true, type: String })
  email: string;

  @Prop({ required: true, trim: true, type: String })
  phone: string;

  @Prop({ required: true, enum: USER_ROLES, type: String })
  role: USER_ROLES;

  @Prop({ required: true, type: String })
  password: string;

  @Prop({ required: true, default: false, type: Boolean })
  emailVerified: boolean;
}

export const UserSchema = SchemaFactory.createForClass(User);

export type UserDocument = User & Document;

UserSchema.methods.toJSON = function () {
  const user = this.toObject();
  delete user.password;
  return user;
};
