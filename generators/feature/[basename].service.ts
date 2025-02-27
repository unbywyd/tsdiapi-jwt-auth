import { client } from '@tsdiapi/prisma';
import { getEmailProvider } from '@tsdiapi/email';
import { getJWTAuthProvider } from '@tsdiapi/jwt-auth';

import { Service } from "typedi";
import { User } from "@prisma/client";
import { IsEmail, IsString } from "class-validator";
import { Expose } from "class-transformer";
import { APIResponse, IsEntity, responseError, toDTO } from "routing-controllers-openapi-extra";
import { getInforuProvider } from '@tsdiapi/inforu';
import { App } from '@tsdiapi/server';

export class SignInEmailDTO {
    @IsString()
    @Expose()
    @IsEmail()
    email: string;
}
export class SignInPhoneDTO {
    @IsString()
    @Expose()
    phoneNumber: string;
}

export class OutputSignInEmailDTO {
    @Expose()
    @IsString()
    email: string;

    @Expose()
    @IsString()
    sessionId: string;
}

export class OutputSignInPhoneDTO {
    @Expose()
    @IsString()
    phoneNumber: string;

    @Expose()
    @IsString()
    sessionId: string;
}

export class InputVerifyDTO {
    @IsString()
    @Expose()
    code: string;

    @IsString()
    @Expose()
    sessionId: string;
}

export class OutputUserDTO {
    @Expose()
    @IsString()
    id: string;

    @Expose()
    @IsString()
    email: string;

    @Expose()
    @IsString()
    phoneNumber: string;
}

export class OutputVerifyDTO {
    @Expose()
    @IsString()
    accessToken: string;

    @Expose()
    @IsEntity(() => OutputUserDTO)
    user: OutputUserDTO;
}

export type UserSession = Partial<User> & {
    id: User['id'];
}

function generateRandomSixDigits(): number {
    const min = 100000;
    const max = 999999;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

@Service()
export default class {{className}}Service {
    async verify(data: InputVerifyDTO): Promise<APIResponse<OutputVerifyDTO>> {
        try {
            const session = await client.session.findUnique({
                where: {
                    id: data.sessionId
                }
            });
            const isDev = App.isDevelopment;

            if (!isDev) {
                if (!session) {
                    return responseError("Invalid session");
                }

                if (session?.code !== data.code) {
                    return responseError("Invalid code");
                }

                if (session.isDeleted) {
                    return responseError("Session expired");
                }
            }

            if (session) {
                await client.session.update({
                    where: {
                        id: session.id
                    },
                    data: {
                        isDeleted: true
                    }
                });
            }
            const { email, phoneNumber } = session;

            let user = await client.user.findFirst({
                where: {
                    ...(email ? {
                        email: {
                            equals: email
                        }
                    } : {
                        phoneNumber:
                        {
                            equals: phoneNumber
                        }
                    })
                }
            });

            if (!user) {
                user = await client.user.create({
                    data: {
                        email: email,
                        phoneNumber: phoneNumber
                    }
                });
            }
            const authProvider = getJWTAuthProvider();

            const accessToken = await authProvider.signIn<UserSession>({
                id: user.id,
                email: user.email,
                phoneNumber: user.phoneNumber
            });

            return {
                accessToken: accessToken,
                user
            }

        } catch (e) {
            console.error(e);
            return responseError(e.message);
        }
    }
    async signInByPhone(data: SignInPhoneDTO) {
        try {
            const provider = getInforuProvider();
            const phoneNumber = data.phoneNumber;
            const code = generateRandomSixDigits();

            const session = await client.session.create({
                data: {
                    code: code.toString(),
                    phoneNumber: phoneNumber,
                }
            });

            provider.send(data.phoneNumber, `Your code is ${code}`).then(() => {
                console.log(`Code: ${code} sent to ${data.phoneNumber}`);
            }).catch((e) => {
                console.error(e);
            });

            return toDTO<OutputSignInEmailDTO>(OutputSignInEmailDTO, {
                sessionId: session.id,
                phoneNumber: phoneNumber
            });

        } catch (e) {
            console.error(e);
            return responseError(e.message);
        }
    }

    async signInByEmail(data: SignInEmailDTO) {
        try {
            const provider = getEmailProvider();
            const email = data.email;
            const code = generateRandomSixDigits();

            const session = await client.session.create({
                data: {
                    code: code.toString(),
                    email: email,
                }
            });

            provider.sendEmail(data.email, "Your code", `Your code is ${code}`).then(() => {
                console.log(`Code: ${code} sent to ${data.email}`);
            }).catch((e) => {
                console.error(e);
            });

            return toDTO<OutputSignInEmailDTO>(OutputSignInEmailDTO, {
                sessionId: session.id,
                email: email
            });

        } catch (e) {
            console.error(e);
            return responseError(e.message);
        }
    }
}