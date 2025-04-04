import {ApiProperty} from '@nestjs/swagger';
import {IsNotEmpty, IsString} from 'class-validator';

export class GoogleDto {
  @ApiProperty()
  @IsString()
  @IsNotEmpty()
  token: string;
}
