import { usePrisma } from '@tsdiapi/prisma';
import { useEmailProvider } from '@tsdiapi/email';
import { useJWTAuthProvider, isBearerValid } from '@tsdiapi/jwt-auth';
import { CryptoService } from '@tsdiapi/crypto';
import { Service } from "typedi";
import { getContext, ResponseBadRequest, ResponseError} from '@tsdiapi/server';
import { useInforuProvider } from '@tsdiapi/inforu';
import { Type, Static } from '@sinclair/typebox';
import { Admin, PrismaClient, Session } from '@generated/prisma/index.js';

import { OutputAdminSchemaLite, OutputAdminSchemaType, Output{{pascalCase userModelName}}SchemaLite, Output{{pascalCase userModelName}}SchemaType } from '@base/api/typebox-schemas/models/index.js';

export const Output{{pascalCase userModelName}}SchemaLiteWithoutPassword = Type.Omit(Output{{pascalCase userModelName}}SchemaLite, ["password"]);
export const OutputAdminSchemaLiteWithoutPassword = Type.Omit(OutputAdminSchemaLite, ["password"]);

export const InputAdminSignUpSchema = Type.Object({
  email: Type.String({ format: 'email' }),
  phoneNumber: Type.Optional(Type.String()),
  name: Type.String(),
  secret: Type.String(),
  password: Type.String({ minLength: 6 })
});
export type InputAdminSignUpSchemaType = Static<typeof InputAdminSignUpSchema>;

export const InputAdminSignInSchema = Type.Object({
  phoneNumber: Type.Optional(Type.String()),
  email: Type.Optional(Type.String()),
  password: Type.Optional(Type.String({ minLength: 6 }))
});
export type InputAdminSignInSchemaType = Static<typeof InputAdminSignInSchema>;

export const OutputAdminAuthSchema = Type.Object({
  session: Type.Optional(Type.Object({
    accessToken: Type.String(),
    admin: OutputAdminSchemaLiteWithoutPassword
  })),
  otp: Type.Optional(Type.Object({
    sessionId: Type.String()
  }))
});
export type OutputAdminAuthSchemaType = Static<typeof OutputAdminAuthSchema>;

export const Input{{pascalCase userModelName}}SignInSchema = Type.Object({
  email: Type.Optional(Type.String({ format: 'email' })),
  phoneNumber: Type.Optional(Type.String()),
});
export type Input{{pascalCase userModelName}}SignInSchemaType = Static<typeof Input{{pascalCase userModelName}}SignInSchema>;

export const Output{{pascalCase userModelName}}SignInSchema = Type.Object({
  email: Type.Optional(Type.String({ format: 'email' })),
  phoneNumber: Type.Optional(Type.String()),
  sessionId: Type.String()
});
export type Output{{pascalCase userModelName}}SignInSchemaType = Static<typeof Output{{pascalCase userModelName}}SignInSchema>;

export const InputOtpVerifySchema = Type.Object({
  code: Type.String(),
  sessionId: Type.String()
});
export type InputOtpVerifySchemaType = Static<typeof InputOtpVerifySchema>;

export const Output{{pascalCase userModelName}}AuthSchema = Type.Object({
  session: Type.Object({
    accessToken: Type.String(),
    user: Output{{pascalCase userModelName}}SchemaLiteWithoutPassword
  })
});
export type Output{{pascalCase userModelName}}AuthSchemaType = Static<typeof Output{{pascalCase userModelName}}AuthSchema>;

export type AuthSession = {
  id: string;
  email?: string;
  phoneNumber?: string;
  adminId?: string;
};

export const AdminGuard = async (req: any) => {
  const session = await isBearerValid<AuthSession>(req);
  if (!session) return false;
  return !!session?.adminId;
};

export function generateRandomSixDigits(): number {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return 100000 + (array[0] % 900000);
}

@Service()
export default class {{className}}Service {
  client: PrismaClient;
  constructor(public cryptoService: CryptoService) {
    this.client = usePrisma<PrismaClient>();
  }

  async adminVerify(data: InputOtpVerifySchemaType): Promise<OutputAdminAuthSchemaType> {
    const { sessionId, code } = data;
    const session = await this.client.{{lowerCase sessionModelName}}.findUnique({ where: { id: sessionId } });
    if (!session) throw new ResponseBadRequest("Session not found");
    if (session.code !== code) throw new ResponseBadRequest("Invalid code");
    if (session.deletedAt) throw new ResponseBadRequest("Session expired");
    if (!session.email) throw new ResponseBadRequest("Session is not for email");
    const admin = await this.client.admin.findFirst({ where: { email: session.email } });
    if (!admin) throw new ResponseBadRequest("Admin not found");

    const accessToken = await useJWTAuthProvider().signIn<AuthSession>({
      id: "",
      phoneNumber: admin.phoneNumber,
      email: admin.email,
      adminId: admin.id
    });

    return {
      session: {
        accessToken,
        admin
      }
    }
  }

  async signInByAdmin(data: InputAdminSignInSchemaType): Promise<OutputAdminAuthSchemaType> {
    try {
      if (!data.phoneNumber && !data.email) throw new ResponseBadRequest("Phone number or email is required");
      let admin: Admin | null = null;
      if (data.phoneNumber) {
        admin = await this.client.admin.findFirst({
          where: {
            phoneNumber: {
              equals: data.phoneNumber
            }
          }
        });
      }
      if (data.email) {
        admin = await this.client.admin.findFirst({
          where: {
            email: {
              equals: data.email
            }
          }
        });
      }
      if (!admin) throw new ResponseBadRequest("{{pascalCase userModelName}} not found");

      const password = data.password;
      if (!password) {
        const email = data.email;
        if (!email) throw new ResponseBadRequest("Email is required for OTP");
        const otp = generateRandomSixDigits();
        const session = await this.client.{{lowerCase sessionModelName}}.create({
          data: { code: otp.toString(), email }
        });

        const emailProvider = useEmailProvider();
        await emailProvider.sendEmail(email, "Your OTP Code", `Your code is ${otp}`);
        return {
          otp: { sessionId: session.id }
        }
      }
      const passwordIsValid = this.cryptoService.verifyPassword(data.password, admin.password);
      if (!passwordIsValid) throw new ResponseBadRequest("Invalid password");
      const accessToken = await useJWTAuthProvider().signIn<AuthSession>({
        id: null,
        phoneNumber: admin.phoneNumber,
        email: admin.email,
        adminId: admin.id
      });

      return {
        session: {
          accessToken,
          admin
        }
      }
    } catch (e) {
      if (e instanceof ResponseError) {
        throw e;
      }
      console.error(e);
      throw new ResponseBadRequest(e.message);
    }
  }

  async signUpAdmin(data: InputAdminSignUpSchemaType): Promise<OutputAdminAuthSchemaType> {
    try {
      const appContext = getContext();
      const secret = appContext.projectConfig.get("JWT_ADMIN_SECRET");
      if (data.secret !== secret) throw new ResponseBadRequest("Invalid secret");

      const where = data?.phoneNumber ? { phoneNumber: data.phoneNumber } : { email: data.email };
      const adminExists = await this.client.admin.findUnique({ where });
      if (adminExists) throw new ResponseBadRequest("{{pascalCase userModelName}} already exists");

      const password = await this.cryptoService.hashPassword(data.password);
      const newAdmin = await this.client.admin.create({
        data: {
          email: data.email || null,
          name: data.name,
          password,
          phoneNumber: data.phoneNumber || null
        }
      });

      const accessToken = await useJWTAuthProvider().signIn<AuthSession>({
        id: null,
        phoneNumber: newAdmin.phoneNumber || null,
        email: newAdmin.email || null,
        adminId: newAdmin.id
      });

      return {
        session: {
          accessToken,
          admin: newAdmin
        }
      }
    } catch (e) {
      if (e instanceof ResponseError) {
        throw e;
      }
      console.error(e);
      throw new ResponseBadRequest(e.message);
    }
  }

  async signIn(data: Input{{pascalCase userModelName}}SignInSchemaType): Promise<Output{{pascalCase userModelName}}SignInSchemaType> {
    try {
      const code = generateRandomSixDigits();
      if (!data.phoneNumber && !data.email) throw new ResponseBadRequest("Phone number or email is required");

      let session: Session | null = null;
      if (data.phoneNumber) {
        const provider = useInforuProvider();

        session = await this.client.{{lowerCase sessionModelName}}.create({
          data: { code: code.toString(), phoneNumber: data.phoneNumber }
        });
        await provider.send(data.phoneNumber, `Your code is ${code}`);
      }

      if (data.email) {
        const emailProvider = useEmailProvider();

        session = await this.client.{{lowerCase sessionModelName}}.create({
          data: { code: code.toString(), email: data.email }
        });
        await emailProvider.sendEmail(data.email, `Your OTP Code`, `Your code is ${code}`);
      }

      return {
        phoneNumber: data.phoneNumber,
        email: data.email,
        sessionId: session.id
      };
    } catch (e) {
      if (e instanceof ResponseError) {
        throw e;
      }
      console.error(e);
      throw new ResponseBadRequest(e.message);
    }
  }

  async getCurrentAdmin(session: AuthSession): Promise<OutputAdminSchemaType> {
    if (!session.adminId) throw new ResponseBadRequest("Admin not found");
    const admin = await this.client.admin.findUnique({ where: { id: session.adminId } });
    if (!admin) throw new ResponseBadRequest("Admin not found");
    return admin;
  }

  async getCurrent{{pascalCase userModelName}}(session: AuthSession): Promise<Output{{pascalCase userModelName}}SchemaType> {
    if (!session.id) throw new ResponseBadRequest("{{pascalCase userModelName}} not found");
    const user = await this.client.{{lowerCase userModelName}}.findUnique({
      where: { id: session.id }
    });
    if (!user) throw new ResponseBadRequest("{{pascalCase userModelName}} not found");
    return user;
  }

  async verify(data: InputOtpVerifySchemaType): Promise<Output{{pascalCase userModelName}}AuthSchemaType> {
    try {
      const appContext = getContext();
      const isDev = appContext.environment === 'development';
      const session = await this.client.{{lowerCase sessionModelName}}.findUnique({ where: { id: data.sessionId } });
      if (!isDev) {
        if (!session || session.code !== data.code || session.deletedAt) {
          throw new ResponseBadRequest("Invalid or expired code");
        }
      } else if (!session) {
        throw new ResponseBadRequest("Session not found");
      }
      await this.client.{{lowerCase sessionModelName}}.update({
        where: { id: session.id },
        data: { deletedAt: new Date() }
      });
      const { email, phoneNumber } = session;
      let user = await this.client.{{lowerCase userModelName}}.findFirst({
        where: email
          ? { email: { equals: email } }
          : { phoneNumber: { equals: phoneNumber } }
      });
      if (!user) {
        user = await this.client.{{lowerCase userModelName}}.create({ data: { email, phoneNumber } });
      }
      const accessToken = await useJWTAuthProvider().signIn<AuthSession>({
        id: user.id,
        email: user.email,
        phoneNumber: user.phoneNumber
      });

      return {
        session: {
          accessToken,
          user
        }
      };
    } catch (e) {
      if (e instanceof ResponseError) {
        throw e;
      }
      console.error(e);
      throw new ResponseBadRequest(e.message);
    }
  }
}
