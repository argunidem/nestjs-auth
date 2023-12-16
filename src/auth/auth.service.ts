import { BadRequestException, Injectable } from '@nestjs/common';
import { PrismaService } from 'prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { jwtSecret } from 'src/utils/constants';

@Injectable()
export class AuthService {
  constructor(private prisma: PrismaService, private jwt: JwtService) {}

  async signup(authDto: AuthDto) {
    const { email, password } = authDto;

    const foundUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (foundUser) {
      throw new BadRequestException('Email already exists');
    }

    const hashedPassword = await this.hashPassword(password);

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
      },
    });

    return { message: 'Sign up was successful', user };
  }

  async signin(authDto: AuthDto) {
    const { email, password } = authDto;

    const foundUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!foundUser) {
      throw new BadRequestException('Invalid credentials');
    }

    const validPassword = await this.comparePassword({
      password,
      hashedPassword: foundUser.password,
    });

    if (!validPassword) {
      throw new BadRequestException('Invalid credentials');
    }

    const token = await this.signToken({
      id: foundUser.id,
      email: foundUser.email,
    });

    return { message: 'Sign in was successful', token };
  }

  async signout() {
    return { message: 'Sign out was successful' };
  }

  async hashPassword(password: string) {
    return await bcrypt.hash(password, 10);
  }

  async comparePassword({
    password,
    hashedPassword,
  }: {
    password: string;
    hashedPassword: string;
  }) {
    return await bcrypt.compare(password, hashedPassword);
  }

  async signToken(payload: { id: string; email: string }) {
    return await this.jwt.signAsync(payload, { secret: jwtSecret });
  }
}
