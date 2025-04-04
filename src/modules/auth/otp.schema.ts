import { Document } from 'mongoose';
import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { OTP_TYPE } from 'src/types/otp.type';

@Schema({ timestamps: true })
export class Otp {
  @Prop({ required: true })
  email: string;

  @Prop({ required: true })
  otp: string;

  @Prop({ required: true, enum: Object.values(OTP_TYPE) })
  accessType: OTP_TYPE;

  @Prop({ required: true, default: false })
  isVerified: boolean;
}

export const OtpSchema = SchemaFactory.createForClass(Otp);

export type OtpDocument = Otp & Document;
