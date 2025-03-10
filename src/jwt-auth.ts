import { OpenAPI } from 'routing-controllers-openapi';
import { JWTPayload, jwtVerify, SignJWT } from 'jose'
import { createParamDecorator, UseBefore } from 'routing-controllers';
import type { Request, Response, NextFunction } from 'express';
import { PluginOptions } from './index.js';

export type ValidateSessionFunction<T> = (session: T) => Promise<boolean | string> | (boolean | string);

export type JWTGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    guardName?: keyof TGuards; // Имя зарегистрированного гуарда
    validateSession?: ValidateSessionFunction<Record<string, any>>; // Ручной валидатор
    errorMessage?: string;
    guardDescription?: string;
};
export interface AuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> {
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    verify<T>(token: string): Promise<T | null>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
}

export class JWTAuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>>
    implements AuthProvider<TGuards> {
    config: PluginOptions<TGuards> | null;

    init(config: PluginOptions<TGuards>) {
        this.config = config;
    }

    signIn<T extends Record<string, any>>(payload: T): Promise<string> {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        return new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
    }

    async verify<T>(token: string): Promise<T> {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.secretKey));
            return payload as T;
        } catch (e) {
            console.error(e);
            return null;
        }
    }

    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined {
        return this.config?.guards?.[name];
    }
}

const provider = new JWTAuthProvider();
export { provider }

export const JWTTokenAuthCheckHandler = async (
    token: string
) => {
    try {
        const session = await provider.verify(token)
        if (!session) {
            return new Error('Token is invalid!')
        }
        return session;
    } catch (_) {
        return new Error('Token is invalid!')
    }
}

export function JWTGuard<TGuards extends Record<string, ValidateSessionFunction<any>>>(
    options?: JWTGuardOptions<TGuards>
) {
    return function (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) {
        UseBefore(async (request: Request, response: Response, next: NextFunction) => {
            const authHeader = request.headers.authorization;

            if (!authHeader) {
                return response.status(403).send({ status: 403, message: 'Unauthorized!' });
            }

            const token = authHeader.split(/\s+/)[1];

            try {
                const session = await provider.verify(token);
                if (!session) {
                    return response.status(403).send({ status: 403, message: 'Invalid token!' });
                }

                let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

                // Если указано имя гуарда, ищем его в конфигурации
                if (options?.guardName) {
                    validateSession = provider.getGuard(options.guardName?.toString());
                    if (!validateSession) {
                        return response
                            .status(403)
                            .send({ status: 403, message: `Guard "${options.guardName?.toString()}" is not registered!` });
                    }
                }

                // Выполняем валидацию, если валидатор определён
                if (validateSession) {
                    const validationResult = await validateSession(session);
                    if (validationResult !== true) {
                        const errorMessage =
                            typeof validationResult === 'string' ? validationResult : options?.errorMessage || 'Unauthorized!';
                        return response.status(403).send({ status: 403, message: errorMessage });
                    }
                }

                (request as any).session = session; // Сохраняем сессию в запросе
                next();
            } catch {
                return response.status(403).send({ status: 403, message: 'Unauthorized!' });
            }
        })(target, propertyKey, descriptor);

        return OpenAPI((operation) => {
            operation.security = [{ bearerAuth: [] }];
            if (options?.guardDescription) {
                operation.description = operation?.description
                    ? `${operation.description} ${options.guardDescription}`
                    : options.guardDescription;
            }
            return operation;
        })(target, propertyKey, descriptor);
    };
}

export async function isJWTValid<T>(req: Request): Promise<false | T> {
    const authHeader = req.headers.authorization;
    if (!authHeader) return false;

    const token = authHeader.split(/\s+/)[1];
    try {
        const session = await provider.verify(token);
        if (!session) return false;
        return session as T;
    } catch (error) {
        console.error('JWT validation error:', error);
        return false;
    }
}

export function CurrentSession() {
    return createParamDecorator({
        value: (action) => {
            return action.request?.session || null
        },
    })
}