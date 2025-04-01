import { client } from '@tsdiapi/prisma';
import { getEmailProvider } from '@tsdiapi/email';
import { getJWTAuthProvider, isJWTValid } from '@tsdiapi/jwt-auth';
import { CryptoService } from '@tsdiapi/crypto';
import { Service } from "typedi";
import { App, APIResponse, responseError } from '@tsdiapi/server';
import { getInforuProvider } from '@tsdiapi/inforu';
import { Type, Static } from '@sinclair/typebox';
import { OutputAdminDTO } from '@base/prisma-models/models/OutputAdminDTO.model.js';
import { Output{{pascalCase userModelName}}DTO } from '@base/prisma-models/models/Output{{pascalCase userModelName}}DTO.model.js';

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
  const session = await isJWTValid<{{pascalCase userModelName}}Session>(req);
  return !!session?.adminId;
};

function generateRandomSixDigits(): number {
  return Math.floor(100000 + Math.random() * 900000);
}

@Service()
export default class {{className}}Service {
  constructor(public cryptoService: CryptoService) {}

  async signInByAdmin(data: InputSignInAdminDTOType): Promise<APIResponse<OutputAdminSessionDTOType>> {
    try {
      const admin = await client.admin.findUnique({ where: { phoneNumber: data.phoneNumber } });
      if (!admin) return responseError("User not found");

      const passwordIsValid = this.cryptoService.verifyPassword(data.password, admin.password);
      if (!passwordIsValid) return responseError("Invalid password");

      const accessToken = await getJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
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

  async signUpAdmin(data: InputSignUpAdminDTOType): Promise<APIResponse<OutputAdminSessionDTOType>> {
    try {
      const secret = await App.env('JWT_ADMIN_SECRET');
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

      const accessToken = await getJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
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

  async signInByEmail(data: SignInEmailDTOType): Promise<APIResponse<OutputSignInEmailDTOType>> {
    try {
      const provider = getEmailProvider();
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

  async signInByPhone(data: SignInPhoneDTOType): Promise<APIResponse<OutputSignInPhoneDTOType>> {
    try {
      const provider = getInforuProvider();
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

  async verify(data: InputVerifyDTOType): Promise<APIResponse<OutputVerifyDTOType>> {
    try {
      const session = await client.{{lowerCase sessionModelName}}.findUnique({ where: { id: data.{{lowerCase sessionModelName}}Id } });
      if (!App.isDevelopment) {
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

      const accessToken = await getJWTAuthProvider().signIn<{{pascalCase userModelName}}Session>({
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
