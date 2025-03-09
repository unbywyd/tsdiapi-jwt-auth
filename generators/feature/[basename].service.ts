import { client } from '@tsdiapi/prisma';
import { getEmailProvider } from '@tsdiapi/email';
import { getJWTAuthProvider } from '@tsdiapi/jwt-auth';

import { Service } from "typedi";
import { {{pascalCase userModelName}} } from "@prisma/client";
import { IsEmail, IsString } from "class-validator";
import { Expose } from "class-transformer";
import { APIResponse, responseError, toDTO, IsEntity } from "@tsdiapi/server";
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
    {{lowerCase sessionModelName}}Id: string;
}

export class OutputSignInPhoneDTO {
    @Expose()
    @IsString()
    phoneNumber: string;

    @Expose()
    @IsString()
    {{lowerCase sessionModelName}}Id: string;
}

export class InputVerifyDTO {
    @IsString()
    @Expose()
    code: string;

    @IsString()
    @Expose()
    {{lowerCase sessionModelName}}Id: string;
}

export class Output{{pascalCase userModelName}}DTO {
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
    @IsEntity(() => Output{{pascalCase userModelName}}DTO)
    {{lowerCase userModelName}}: Output{{pascalCase userModelName}}DTO;
}

export type {{pascalCase userModelName}}Session = Partial<{{pascalCase userModelName}}> & {
    id: {{pascalCase userModelName}}['id'];
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
            const {{lowerCase sessionModelName}} = await client.{{lowerCase sessionModelName}}.findUnique({
                where: {
                    id: data.{{lowerCase sessionModelName}}Id
                }
            });
            const isDev = App.isDevelopment;

            if (!isDev) {
                if (!{{lowerCase sessionModelName}}) {
                    return responseError("Invalid {{lowerCase sessionModelName}}");
                }

                if ({{lowerCase sessionModelName}}?.code !== data.code) {
                    return responseError("Invalid code");
                }

                if ({{lowerCase sessionModelName}}.deletedAt) {
                    return responseError("Session expired");
                }
            }

            if ({{lowerCase sessionModelName}}) {
                await client.{{lowerCase sessionModelName}}.update({
                    where: {
                        id: {{lowerCase sessionModelName}}.id
                    },
                    data: {
                        deletedAt: new Date()
                    }
                });
            }
            const { email, phoneNumber } = {{lowerCase sessionModelName}};

            let {{lowerCase userModelName}} = await client.{{lowerCase userModelName}}.findFirst({
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

            if (!{{lowerCase userModelName}}) {
                {{lowerCase userModelName}} = await client.{{lowerCase userModelName}}.create({
                    data: {
                        email: email,
                        phoneNumber: phoneNumber
                    }
                });
            }
            const authProvider = getJWTAuthProvider();

            const accessToken = await authProvider.signIn<{{pascalCase userModelName}}Session>({
                id: {{lowerCase userModelName}}.id,
                email: {{lowerCase userModelName}}.email,
                phoneNumber: {{lowerCase userModelName}}.phoneNumber
            });

            return {
                accessToken: accessToken,
                {{lowerCase userModelName}}
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

            const {{lowerCase sessionModelName}} = await client.{{lowerCase sessionModelName}}.create({
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
                {{lowerCase sessionModelName}}Id: {{lowerCase sessionModelName}}.id,
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

            const {{lowerCase sessionModelName}} = await client.{{lowerCase sessionModelName}}.create({
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
                {{lowerCase sessionModelName}}Id: {{lowerCase sessionModelName}}.id,
                email: email
            });

        } catch (e) {
            console.error(e);
            return responseError(e.message);
        }
    }
}