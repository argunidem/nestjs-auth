import { Body, Controller, Get, Post } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  signup(@Body() dto) {
    return this.authService.signup();
  }

  @Post('signin')
  signin() {
    return this.authService.signin();
  }

  @Get('signout')
  signout() {
    return this.authService.signout();
  }
}