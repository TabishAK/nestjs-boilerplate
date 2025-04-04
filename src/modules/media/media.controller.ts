import { Response, Express } from 'express';
import { ApiBody, ApiConsumes, ApiTags } from '@nestjs/swagger';
import { FileInterceptor } from '@nestjs/platform-express';
import {
  Controller,
  Param,
  Post,
  Res,
  UploadedFile,
  UseInterceptors,
} from '@nestjs/common';

import { MediaService } from './media.service';
import { FOLDER_NAME } from 'src/constants/media';

@Controller('mediabucket')
@ApiTags('Media Bucket')
export class MediaController {
  constructor(private readonly mediaBucketService: MediaService) {}
  s;
  @Post('upload-profile/:id')
  @UseInterceptors(FileInterceptor('file'))
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Upload profile file',
    schema: {
      type: 'object',
      properties: {
        file: {
          type: 'string',
          format: 'binary',
        },
      },
    },
  })
  async uploadProfile(
    @UploadedFile() file: Express.Multer.File,
    @Param('id') userId: string,
    @Res() res: Response
  ) {
    const response = await this.mediaBucketService.uploadProfile(
      FOLDER_NAME.PROFILE,
      file,
      userId
    );

    return res.status(response.status).json(response);
  }

  // @Post('upload-physiques')
  // @UseInterceptors(FileInterceptor('file'))
  // @ApiConsumes('multipart/form-data')
  // @ApiBody({
  //   description: 'Upload physique file',
  //   schema: {
  //     type: 'object',
  //     properties: {
  //       file: {
  //         type: 'string',
  //         format: 'binary',
  //       },
  //     },
  //   },
  // })
  // async uploadPhysiques(
  //   @UploadedFile() file: Express.Multer.File,
  //   @Res() res: Response
  // ) {
  //   const response = await this.mediaBucketService.uploadPhysiques(
  //     FolderName.Physiques,
  //     file
  //   );
  //   return res.status(response.status).json(response);
  // }
}
