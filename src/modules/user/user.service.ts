import { Injectable, HttpStatus } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User, UserDocument } from './user.schema';
import { CreateUserDto, UpdateUserDto } from './dto/user.dto';
import { SerializeHttpResponse } from 'src/utils/serializer';
import { createHashPassword } from 'src/utils/auth.util';

@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private readonly userModel: Model<UserDocument>
  ) {}

  async create(createUserDto: CreateUserDto) {
    const existingUser = await this.userModel.findOne({
      email: createUserDto.email.toLowerCase(),
    });

    if (existingUser) {
      return SerializeHttpResponse(
        null,
        HttpStatus.BAD_REQUEST,
        'User with this email already exists'
      );
    }

    const hashedPassword = await createHashPassword(createUserDto.password);
    const user = await this.userModel.create({
      ...createUserDto,
      password: hashedPassword,
    });

    return SerializeHttpResponse(
      user,
      HttpStatus.CREATED,
      'User created successfully'
    );
  }

  async findAll() {
    const users = await this.userModel.find().select('-password');
    return SerializeHttpResponse(
      users,
      HttpStatus.OK,
      'Users retrieved successfully'
    );
  }

  async findOne(id: string) {
    const user = await this.userModel.findById(id).select('-password');

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        'User not found'
      );
    }

    return SerializeHttpResponse(
      user,
      HttpStatus.OK,
      'User retrieved successfully'
    );
  }

  async update(id: string, updateUserDto: UpdateUserDto) {
    const user = await this.userModel.findById(id);

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        'User not found'
      );
    }

    if (updateUserDto.password) {
      updateUserDto.password = await createHashPassword(updateUserDto.password);
    }

    const updatedUser = await this.userModel
      .findByIdAndUpdate(id, updateUserDto, { new: true })
      .select('-password');

    return SerializeHttpResponse(
      updatedUser,
      HttpStatus.OK,
      'User updated successfully'
    );
  }

  async remove(id: string) {
    const user = await this.userModel.findById(id);

    if (!user) {
      return SerializeHttpResponse(
        null,
        HttpStatus.NOT_FOUND,
        'User not found'
      );
    }

    await this.userModel.findByIdAndDelete(id);

    return SerializeHttpResponse(
      null,
      HttpStatus.OK,
      'User deleted successfully'
    );
  }
}
