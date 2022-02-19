import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
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
    private jwtService: JwtService,
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

  validateUser(email: string, password: string): Promise<User> {
    return this.userRepository
      .findOne(
        { email },
        {
          select: ['id', 'firstName', 'lastName', 'email', 'password', 'role'],
        },
      )
      .then((user: User) => {
        return bcrypt
          .compare(password, user.password)
          .then((isValidPassword: boolean): User => {
            if (isValidPassword) {
              delete user.password;
              return user;
            }
          });
      });
  }

  login(user: User): Promise<string> {
    const { email, password } = user;

    return this.validateUser(email, password).then(
      (user: User): Promise<string> => {
        if (user) {
          // create JWT - creds
          return this.jwtService.signAsync({ user });
        }
      },
    );
  }
}
