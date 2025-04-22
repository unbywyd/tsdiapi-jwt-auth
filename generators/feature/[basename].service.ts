import { client } from '@tsdiapi/prisma';
import { getContext } from '@tsdiapi/server';
import { useEmailProvider } from '@tsdiapi/email';
import { useJWTAuthProvider } from '@tsdiapi/jwt-auth';
import { Service } from "typedi";
import { Type, Static } from '@sinclair/typebox';
import { useInforuProvider } from '@tsdiapi/inforu';

export const ErrorResponseDTO = Type.Object({
  error: Type.String(),
});
export type ErrorResponseType = Static<typeof ErrorResponseDTO>;

// === DTOs ===
export const SignInEmailDTO = Type.Object({
  email: Type.String({ format: 'email' })
});
export type SignInEmailDTOType = Static<typeof SignInEmailDTO>;

export const OutputSignInEmailDTO = Type.Object({
  email: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String(),
});
export type OutputSignInEmailDTOType = Static<typeof OutputSignInEmailDTO>;

export const SignInPhoneDTO = Type.Object({
  phoneNumber: Type.String(),
});
export type SignInPhoneDTOType = Static<typeof SignInPhoneDTO>;

export const OutputSignInPhoneDTO = Type.Object({
  phoneNumber: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String(),
});
export type OutputSignInPhoneDTOType = Static<typeof OutputSignInPhoneDTO>;

export const InputVerifyDTO = Type.Object({
  code: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String(),
});
export type InputVerifyDTOType = Static<typeof InputVerifyDTO>;

export const Output{{pascalCase userModelName}}DTO = Type.Object({
  id: Type.String(),
  email: Type.String(),
  phoneNumber: Type.String(),
});
export type Output{{pascalCase userModelName}}DTOType = Static<typeof Output{{pascalCase userModelName}}DTO>;

export const OutputVerifyDTO = Type.Object({
  accessToken: Type.String(),
  user: Output{{pascalCase userModelName}}DTO,
});
export type OutputVerifyDTOType = Static<typeof OutputVerifyDTO>;

export type {{pascalCase userModelName}}Session = {
  id: string;
  email: string;
  phoneNumber: string;
};

function generateRandomSixDigits(): number {
  return Math.floor(100000 + Math.random() * 900000);
}
const responseError = (message: string) => {
  throw new Error(message);
}
@Service()
export default class AuthService {
  async verify(data: InputVerifyDTOType): Promise<OutputVerifyDTOType> {
    const appContext = getContext();
    try {
      const session = await client.{{lowerCase sessionModelName}}.findUnique({
        where: { id: data.{{lowerCase sessionModelName}}Id }
      });

      const isDev = appContext.environment === 'development';

      if (!isDev) {
        if (!session) return responseError("Invalid session");
        if (session.code !== data.code) return responseError("Invalid code");
        if (session.deletedAt) return responseError("Session expired");
      }

      if (session) {
        await client.{{lowerCase sessionModelName}}.update({
          where: { id: session.id },
          data: { deletedAt: new Date() },
        });
      }

      const { email, phoneNumber } = session;
      let user = await client.{{lowerCase userModelName}}.findFirst({
        where: email ? { email } : { phoneNumber }
      });

      if (!user) {
        user = await client.{{lowerCase userModelName}}.create({
          data: { email, phoneNumber }
        });
      }

      const authProvider = useJWTAuthProvider();
      const accessToken = await authProvider.signIn<{{pascalCase userModelName}}Session>({
        id: user.id,
        email: user.email,
        phoneNumber: user.phoneNumber,
      });

      return {
        accessToken,
        user: user
      };

    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }

  async signInByPhone(data: SignInPhoneDTOType): Promise<OutputSignInPhoneDTOType> {
    try {
      const provider = useInforuProvider();
      const code = generateRandomSixDigits();

      const session = await client.{{lowerCase sessionModelName}}.create({
        data: { code: code.toString(), phoneNumber: data.phoneNumber },
      });

      provider.send(data.phoneNumber, `Your code is ${code}`).catch(console.error);

      return {
        phoneNumber: data.phoneNumber,
        {{lowerCase sessionModelName}}Id: session.id,
      };

    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }
  
  async getCurrentUser(session: {{pascalCase userModelName}}Session): Promise<Output{{pascalCase userModelName}}DTOType> {
    const user = await client.{{lowerCase userModelName}}.findUnique({
      where: { id: session.id }
    });

    if (!user) return responseError("{{pascalCase userModelName}} not found");

    return user;
  }

  async signInByEmail(data: SignInEmailDTOType): Promise<OutputSignInEmailDTOType> {
    try {
      const provider = useEmailProvider();
      const code = generateRandomSixDigits();

      const session = await client.{{lowerCase sessionModelName}}.create({
        data: { code: code.toString(), email: data.email },
      });

      provider.sendEmail(data.email, "Your code", `Your code is ${code}`).catch(console.error);

      return {
        email: data.email,
        {{lowerCase sessionModelName}}Id: session.id,
      };

    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }
}
