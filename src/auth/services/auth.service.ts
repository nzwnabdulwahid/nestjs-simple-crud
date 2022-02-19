import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { from, map, Observable, switchMap } from 'rxjs';
import { Repository } from 'typeorm';
import { UserEntity } from '../models/user.entity';
import { User } from '../models/user.interface';

@Injectable()
export class AuthService {
  constructor(
    @InjectRepository(UserEntity)
    private readonly userRepository: Repository<UserEntity>,
  ) {}
  hashPassword(password: string): Promise<string> {
    return bcrypt.hash(password, 12);
  }

  registerAccount(user: User): Promise<User> {
    const { firstName, lastName, email, password } = user;

    return this.hashPassword(password).then((hashedPassword): Promise<User> => {
      return this.userRepository
        .save({
          firstName,
          lastName,
          email,
          password: hashedPassword,
        })
        .then((user: User): User => {
          delete user.password;
          return user;
        });
    });
  }
}
