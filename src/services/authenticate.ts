import {UsersRepository} from "@/repositories/users-repository";
import {InvalidCredentialsError} from "./errors/invalid-credentials-error";
import {compare} from "bcryptjs";
import {User} from "@prisma/client";

interface AuthenticateUseCasesRequest {
  email: string;
  password: string;
}

interface AuthenticateUseCasesResponse {
  user: User;
}

export class AuthenticateUseCase {
  constructor(private usersRepository: UsersRepository) {}

  async execute({
    email,
    password,
  }: AuthenticateUseCasesRequest): Promise<AuthenticateUseCasesResponse> {
    const user = await this.usersRepository.findByEmail(email);

    if (!user) {
      throw new InvalidCredentialsError();
    }

    const doesPasswordMatches = await compare(password, user.password_hash);

    if (!doesPasswordMatches) {
      throw new InvalidCredentialsError();
    }

    return {
      user,
    };
  }
}
