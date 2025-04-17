import { JWTPayload, jwtVerify, SignJWT } from 'jose'
import { APIKeyEntry, PluginOptions } from './index.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { TSchema, Type, Static } from '@sinclair/typebox';
import { GuardFn, ResponseUnion } from '@tsdiapi/server';

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

export class ApiKeyProvider {
    constructor() { }
    config: PluginOptions | null = null;
    init(config: PluginOptions) {
        this.config = config;
    }
    get keys() {
        return this.config?.apiKeys || {};
    }
    async verify(key: string): Promise<unknown> {
        const entry = this.keys[key];
        if (!(key in this.keys) || entry === 'JWT') {
            return provider.verify(key)
        }
        if (entry === true) {
            return true;
        }
        if (entry.validate) {
            return await entry.validate();
        }
        return true;
    }
}

const apiKeyProvider: ApiKeyProvider = new ApiKeyProvider();


export { provider, apiKeyProvider };

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

const forbiddenResponse = Type.Object({
    message: Type.String()
});
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};

export function JWTGuard(
    options?: JWTGuardOptions<any>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, reply: FastifyReply) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return {
                status: 403 as const,
                data: { message: 'Authorization header is missing' }
            } as ResponseUnion<ForbiddenResponses>;
        }

        const token = authHeader.split(/\s+/)[1];
        const session = await provider.verify(token);

        if (!session) {
            return {
                status: 403 as const,
                data: { message: 'Invalid token' }
            } as ResponseUnion<ForbiddenResponses>;
        }

        let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

        if (options?.guardName) {
            validateSession = provider.getGuard(options.guardName as keyof typeof provider.config.guards);
            if (!validateSession) {
                return {
                    status: 403 as const,
                    data: { message: `Guard "${String(options.guardName)}" is not registered` }
                } as ResponseUnion<ForbiddenResponses>;
            }
        }
        if (validateSession) {
            const result = await validateSession(session);
            if (result !== true) {
                return {
                    status: 403 as const,
                    data: {
                        message: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized'
                    }
                } as ResponseUnion<ForbiddenResponses>;
            }
        }
        req.session = session;
        return true;
    };
}

export function useSession<T>(req: FastifyRequest): T | undefined {
    return req.session as T | undefined;
}

export function APIKeyGuard(
    options?: JWTGuardOptions<any>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, _reply: FastifyReply) => {
        const apiKey = req.headers['x-api-key'] || req.headers.authorization;

        if (!apiKey) {
            return {
                status: 403,
                data: { message: 'X-API-Key header is missing' },
            } as ResponseUnion<ForbiddenResponses>;
        }

        const session = await apiKeyProvider.verify(apiKey as string);
        if (!session) {
            return {
                status: 403,
                data: { message: 'Invalid API key' },
            } as ResponseUnion<ForbiddenResponses>;
        }

        let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

        if (options?.guardName) {
            validateSession = provider.getGuard(options.guardName as keyof typeof provider.config.guards);
            if (!validateSession) {
                return {
                    status: 403,
                    data: { message: `Guard "${String(options.guardName)}" is not registered` },
                } as ResponseUnion<ForbiddenResponses>;
            }
        }

        if (validateSession) {
            const result = await validateSession(session);
            if (result !== true) {
                return {
                    status: 403,
                    data: {
                        message: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized',
                    },
                } as ResponseUnion<ForbiddenResponses>;
            }
        }

        req.session = session;
        return true;
    };
}

export async function isBearerValid<T>(req: FastifyRequest): Promise<false | T> {
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

export async function isApiKeyValid(req: FastifyRequest): Promise<false | unknown> {
    const apiKey = req.headers['x-api-key'] || req.headers.authorization;
    if (!apiKey) return false;
    try {
        const session = await apiKeyProvider.verify(apiKey as string);
        if (!session) return false;
        return session;
    } catch (error) {
        console.error('API key validation error:', error);
        return false;
    }
}