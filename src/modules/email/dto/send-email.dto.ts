import { IsNotEmpty, IsString } from "class-validator";


export class SendEmailDto {
    @IsString()
    @IsNotEmpty()
    to: string;
  
    @IsString()
    @IsNotEmpty()
    subject: string;

    @IsString()
    @IsNotEmpty()
    html: string;
  }
  