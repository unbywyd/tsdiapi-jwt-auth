import { client } from '@tsdiapi/prisma';
import { useEmailProvider } from '@tsdiapi/email';
import { useJWTAuthProvider, isBearerValid } from '@tsdiapi/jwt-auth';
import { CryptoService } from '@tsdiapi/crypto';
import { Service } from "typedi";
import { getContext, DateString } from '@tsdiapi/server';
import { useInforuProvider } from '@tsdiapi/inforu';
import { Type, Static } from '@sinclair/typebox';

export const ErrorResponseDTO = Type.Object({
  message: Type.String(),
});
export type ErrorResponseType = Static<typeof ErrorResponseDTO>;

export const OutputAdminDTO = Type.Object({
  id: Type.String(),
  email: Type.Optional(Type.String()),
  phoneNumber: Type.Optional(Type.String()),
  name: Type.Optional(Type.String()),
  createdAt: DateString(),
  updatedAt: DateString(),
});
export type OutputAdminDTOType = Static<typeof OutputAdminDTO>;

export const Output{{pascalCase userModelName}}DTO = Type.Object({
  id: Type.String(),
  email: Type.Optional(Type.String()),
  phoneNumber: Type.Optional(Type.String()),
  adminId: Type.Optional(Type.String()),
  createdAt: DateString(),
  updatedAt: DateString(),
  deletedAt: DateString(),
});

export const InputSignUpAdminDTO = Type.Object({
  phoneNumber: Type.String(),
  name: Type.String(),
  secret: Type.String(),
  email: Type.String(),
  password: Type.String({ minLength: 6 })
});
export type InputSignUpAdminDTOType = Static<typeof InputSignUpAdminDTO>;

export const InputSignInAdminDTO = Type.Object({
  phoneNumber: Type.String(),
  password: Type.String({ minLength: 6 })
});
export type InputSignInAdminDTOType = Static<typeof InputSignInAdminDTO>;

export const OutputAdminSessionDTO = Type.Object({
  accessToken: Type.String(),
  admin: OutputAdminDTO
});
export type OutputAdminSessionDTOType = Static<typeof OutputAdminSessionDTO>;

export const SignInEmailDTO = Type.Object({
  email: Type.String({ format: 'email' })
});
export type SignInEmailDTOType = Static<typeof SignInEmailDTO>;

export const OutputSignInEmailDTO = Type.Object({
  email: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String()
});
export type OutputSignInEmailDTOType = Static<typeof OutputSignInEmailDTO>;

export const SignInPhoneDTO = Type.Object({
  phoneNumber: Type.String()
});
export type SignInPhoneDTOType = Static<typeof SignInPhoneDTO>;

export const OutputSignInPhoneDTO = Type.Object({
  phoneNumber: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String()
});
export type OutputSignInPhoneDTOType = Static<typeof OutputSignInPhoneDTO>;

export const InputVerifyDTO = Type.Object({
  code: Type.String(),
  {{lowerCase sessionModelName}}Id: Type.String()
});
export type InputVerifyDTOType = Static<typeof InputVerifyDTO>;

export const OutputVerifyDTO = Type.Object({
  accessToken: Type.String(),
  {{lowerCase userModelName}}: Output{{pascalCase userModelName}}DTO
});
export type OutputVerifyDTOType = Static<typeof OutputVerifyDTO>;

export type {{pascalCase userModelName}}Session = {
  id: string;
  email?: string;
  phoneNumber?: string;
  adminId?: string;
};

export const AdminGuard = async (req: any) => {
  const session = await isBearerValid<UserSession>(req);
  if (!session) return false;
  return !!session?.adminId;
};

function generateRandomSixDigits(): number {
  return Math.floor(100000 + Math.random() * 900000);
}

const responseError = (message: string) => {
  throw new Error(message);
}

@Service()
export default class {{className}}Service {
  constructor(public cryptoService: CryptoService) {}

  async signInByAdmin(data: InputSignInAdminDTOType): Promise<OutputAdminSessionDTOType> {
    try {
      const admin = await client.admin.findUnique({ where: { phoneNumber: data.phoneNumber } });
      if (!admin) return responseError("User not found");

      const passwordIsValid = this.cryptoService.verifyPassword(data.password, admin.password);
      if (!passwordIsValid) return responseError("Invalid password");

      const accessToken = await useJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
        id: null,
        phoneNumber: admin.phoneNumber,
        adminId: admin.id
      });

      return { accessToken, admin };
    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }

  async signUpAdmin(data: InputSignUpAdminDTOType): Promise<OutputAdminSessionDTOType> {
    try {
      const appContext = getContext();     
      const secret =  appContext.projectConfig.get("JWT_ADMIN_SECRET");
      if (data.secret !== secret) return responseError("Invalid secret");

      const adminExists = await client.admin.findUnique({ where: { phoneNumber: data.phoneNumber } });
      if (adminExists) return responseError("User already exists");

      const password = await this.cryptoService.hashPassword(data.password);
      const newAdmin = await client.admin.create({
        data: {
          email: data.email,
          name: data.name,
          password,
          phoneNumber: data.phoneNumber
        }
      });

      const accessToken = await useJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
        id: null,
        phoneNumber: newAdmin.phoneNumber,
        adminId: newAdmin.id
      });

      return { accessToken, admin: newAdmin };
    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }

  async signInByEmail(data: SignInEmailDTOType): Promise<OutputSignInEmailDTOType> {
    try {
      const provider = useEmailProvider();
      const code = generateRandomSixDigits();

      const session = await client.{{lowerCase sessionModelName}}.create({
        data: { code: code.toString(), email: data.email }
      });

      await provider.sendEmail(data.email, "Your code", `Your code is ${code}`);

      return {
        email: data.email,
        {{lowerCase sessionModelName}}Id: session.id
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
        data: { code: code.toString(), phoneNumber: data.phoneNumber }
      });

      await provider.send(data.phoneNumber, `Your code is ${code}`);

      return {
        phoneNumber: data.phoneNumber,
        {{lowerCase sessionModelName}}Id: session.id
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

  async verify(data: InputVerifyDTOType): Promise<OutputVerifyDTOType> {
    try {
      const appContext = getContext();
      const isDev = appContext.environment === 'development';
      const session = await client.{{lowerCase sessionModelName}}.findUnique({ where: { id: data.{{lowerCase sessionModelName}}Id } });
      if (!isDev) {
        if (!session || session.code !== data.code || session.deletedAt) {
          return responseError("Invalid or expired code");
        }
      }

      await client.{{lowerCase sessionModelName}}.update({
        where: { id: session.id },
        data: { deletedAt: new Date() }
      });

      const { email, phoneNumber } = session;

      let user = await client.{{lowerCase userModelName}}.findFirst({
        where: email
          ? { email: { equals: email } }
          : { phoneNumber: { equals: phoneNumber } }
      });

      if (!user) {
        user = await client.{{lowerCase userModelName}}.create({ data: { email, phoneNumber } });
      }

      const accessToken = await useJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
        id: user.id,
        email: user.email,
        phoneNumber: user.phoneNumber
      });

      return {
        accessToken,
        {{lowerCase userModelName}}: user
      };
    } catch (e) {
      console.error(e);
      return responseError(e.message);
    }
  }
}
