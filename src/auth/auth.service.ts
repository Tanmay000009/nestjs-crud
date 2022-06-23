import { ForbiddenException, Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { IAuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService) {}
  async signup(dto: IAuthDto) {
    // generate password hash
    const hash = await argon.hash(dto.password);

    try {
      // save user to db
      const user = await this.prisma.user.create({
        data: {
          email: dto.email,
          hash,
        },
      });

      delete user.hash;

      // return user
      return user;
    } catch (err) {
      if (err instanceof PrismaClientKnownRequestError) {
        if (err.code === 'P2002') {
          throw new ForbiddenException('User already exists');
        }
      }
      throw err;
    }
  }

  async login(dto: IAuthDto) {
    // find user by email
    const user = await this.prisma.user.findUnique({
      where: {
        email: dto.email,
      },
    });
    // if user not found, throw error
    if (!user) {
      throw new ForbiddenException('Incorrect email or password');
    }
    // if user found, compare password hash with hash in db
    const pass_match = await argon.verify(user.hash, dto.password);
    // if password hash is not equal, throw error
    if (!pass_match) {
      throw new ForbiddenException('Incorrect email or password');
    }
    // if password hash is equal, return user
    delete user.hash;
    return user;
  }
}
