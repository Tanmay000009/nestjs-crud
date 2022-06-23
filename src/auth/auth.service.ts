import { ForbiddenException, Injectable } from '@nestjs/common';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

import { IAuthDto } from './dto';
import { PrismaService } from '../../src/prisma/prisma.service';
@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
  ) {}
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

      // return user
      return this.signToken(user.id, user.email);
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
    return this.signToken(user.id, user.email);
  }

  signToken = async (
    userId: number,
    email: string,
  ): Promise<{ access_token: string }> => {
    const payload = {
      sub: userId,
      email,
    };

    const token = await this.jwt.signAsync(payload, {
      expiresIn: '1h',
      secret: this.config.get('JWT_SECRET'),
    });

    return {
      access_token: token,
    };
  };
}
