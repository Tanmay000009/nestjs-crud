import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { IAuthDto } from './dto';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto: IAuthDto) {
    return this.authService.signup(dto);
  }

  @Post('login')
  login(@Body() dto: IAuthDto) {
    return this.authService.login(dto);
  }
}
