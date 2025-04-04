import { S3 } from '@aws-sdk/client-s3';
import { Upload } from '@aws-sdk/lib-storage';
import { ConfigService } from '@nestjs/config';
import { HttpStatus, Injectable } from '@nestjs/common';

import { SerializeHttpResponse } from 'src/utils/serializer';
import {
  AWS_ERROR,
  AWS_SUCCESS,
} from 'src/constants/api-response/aws.response';
import { FOLDER_NAME } from 'src/constants/media';
import { CONFIG } from 'src/constants/config';

@Injectable()
export class MediaService {
  private s3: S3;
  private readonly bucketName: string;

  constructor(private readonly configService: ConfigService) {
    const region = this.configService.get(CONFIG.AWS_REGION);
    const bucketName = this.configService.get(CONFIG.AWS_BUCKET_NAME);
    const accessKeyId = this.configService.get(CONFIG.AWS_ACCESS_KEY_ID);
    const secretAccessKey = this.configService.get(
      CONFIG.AWS_SECRET_ACCESS_KEY
    );

    this.s3 = new S3({ credentials: { accessKeyId, secretAccessKey }, region });
    this.bucketName = bucketName;
  }

  async deleteImage(fileName: string) {
    const params = { Bucket: this.bucketName, Key: fileName };

    try {
      await this.s3.deleteObject(params);
      return SerializeHttpResponse(
        null,
        HttpStatus.NO_CONTENT,
        AWS_SUCCESS.DELETE_FILE
      );
    } catch (error) {
      return SerializeHttpResponse(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        AWS_ERROR.DELETE_FILE
      );
    }
  }

  async uploadFile(path: string, file: Express.Multer.File) {
    const fileName = path;
    const params = {
      Bucket: this.bucketName,
      Key: fileName,
      Body: file.buffer,
      ContentType: file.mimetype,
    };

    try {
      const response = await new Upload({
        client: this.s3,
        params: {
          Bucket: this.bucketName,
          Key: fileName,
          Body: file.buffer,
          ContentType: file.mimetype,
        },
      }).done();
      const data = { name: fileName, url: response.Location };
      return SerializeHttpResponse(
        data,
        HttpStatus.OK,
        AWS_SUCCESS.UPLOAD_FILE
      );
    } catch (error) {
      return SerializeHttpResponse(
        null,
        HttpStatus.INTERNAL_SERVER_ERROR,
        AWS_ERROR.UPLOAD_FILE
      );
    }
  }

  async uploadProfile(
    folderName: FOLDER_NAME,
    file: Express.Multer.File,
    fileName: string
  ) {
    const path = `${folderName}/${fileName}`;
    return await this.uploadFile(path, file);
  }

  async uploadPhysiques(folderName: FOLDER_NAME, file: Express.Multer.File) {
    const path = `${folderName}/${file.originalname}`;
    return await this.uploadFile(path, file);
  }
}
