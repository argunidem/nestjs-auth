import {
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { Request } from 'express';
import { PrismaService } from 'prisma/prisma.service';

@Injectable()
export class UsersService {
  constructor(private prisma: PrismaService) {}

  async getMe(id: string, req: Request) {
    const user = await this.prisma.user.findUnique({ where: { id } });

    if (!user) throw new NotFoundException();

    const decoded = req.user as { id: string; email: string };

    if (decoded.id !== user.id) {
      throw new UnauthorizedException(
        'You do not have permission to view this resource',
      );
    }

    delete user.password;

    return { user };
  }

  async getUsers() {
    const users = await this.prisma.user.findMany({
      select: { id: true, email: true },
    });
    return { users };
  }
}
