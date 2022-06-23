import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { Request } from 'express';
import { JwtGaurd } from 'src/auth/gaurd';

@Controller('users')
export class UserController {
  @UseGuards(JwtGaurd)
  @Get('me')
  getMe(@Req() req: Request) {
    return req.user;
  }
}
