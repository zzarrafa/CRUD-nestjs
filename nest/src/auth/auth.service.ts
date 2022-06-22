import { ForbiddenException, Injectable } from "@nestjs/common";
import { PrismaService } from "src/prisma/prisma.service";
import { AuthDto } from "./dto";
import * as argon2 from "argon2";
import { PrismaClientKnownRequestError } from '@prisma/client/runtime';
import { JwtService } from "@nestjs/jwt";
import { ConfigService } from "@nestjs/config";



@Injectable()
export class AuthService {
    constructor(private prisma: PrismaService, private jwt: JwtService, private config: ConfigService) {}
    
    async signup(dto: AuthDto){
        try {
            
        //generate hash password
        const hash = await argon2.hash(dto.password);
        // save user to database
       const user = await this.prisma.user.create({
            data: {
                email: dto.email,
                hash,
            },
       });
    //    delete user.hash;
        // return user
        return this.signToken(user.id, user.email); 
    } catch (error) {
        if (error instanceof PrismaClientKnownRequestError){
            if (error.code === 'P2002'){
                throw new ForbiddenException('Email already exists');
            }

        }
        throw error;
    }
    }

   async signin(dto: AuthDto){
    //find user by email
    const user = await this.prisma.user.findUnique({
        where: {
            email: dto.email,
        },
    });
    // if user not found throw exception
    if (!user)
        throw new ForbiddenException('Invalid credentials');
    //compare password
    const valid = await argon2.verify(user.hash, dto.password);
    // if psswd is not valid throw exception
    if (!valid)
        throw new ForbiddenException('Invalid credentials');
    // send back user
    // delete user.hash;
    return this.signToken(user.id, user.email); 
}

async signToken(userId: number,email: string,): Promise<{ access_token: string }> {
    const payload = {
      sub: userId,
      email,
    };
    const secret = this.config.get('JWT_SECRET');

    const token = await this.jwt.signAsync(
      payload,
      {
        expiresIn: '15m',
        secret: secret,
      },
    );

    return {
      access_token: token,
    };
  }

}