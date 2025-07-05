import { JWTPayload, jwtVerify, SignJWT } from 'jose'
import { PluginOptions } from './index.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { GuardFn, ResponseUnion } from '@tsdiapi/server';

export type ValidateSessionFunction<T> = (session: T) => Promise<boolean | string> | (boolean | string);

export type JWTGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    guardName?: keyof TGuards;
    validateSession?: ValidateSessionFunction<Record<string, any>>;
    errorMessage?: string;
    guardDescription?: string;
    optional?: boolean;
};
export type ValidateTokenPairFunction<T> = (accessPayload: any, refreshPayload: any) => (T | null) | Promise<(T | null)>;
export type TokenPair = {
    accessToken: string;
    refreshToken: string;
};

export interface AuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> {
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    signInWithRefresh<T extends Record<string, any>>(payload: T): Promise<TokenPair>;
    verify<T>(token: string): Promise<T | null>;
    verifyRefresh<T>(token: string): Promise<T | null>;
    validateTokens<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null>;
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

    async signInWithRefresh<T extends Record<string, any>>(payload: T): Promise<TokenPair> {
        const iat = Math.floor(Date.now() / 1000);
        const accessExp = iat + this.config.expirationTime;
        const refreshExp = iat + this.config.refreshExpirationTime;

        const accessToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));

        const refreshToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.refreshSecretKey));

        return {
            accessToken,
            refreshToken
        };
    }

    async verify<T>(token: string): Promise<T> {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.secretKey));
            return payload as T;
        } catch (e) {
            return null;
        }
    }

    async verifyRefresh<T>(token: string): Promise<T> {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.refreshSecretKey));
            return payload as T;
        } catch (e) {
            return null;
        }
    }

    async validateTokens<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null> {
        try {
            const accessPayload = await this.verify<T>(accessToken);
            const refreshPayload = await this.verifyRefresh<T>(refreshToken);

            if (!accessPayload || !refreshPayload) {
                return null;
            }

            // If custom validation function is provided, use it
            if (validateFn) {
                return await validateFn(accessPayload, refreshPayload);
            }

            // Default validation: check if both tokens belong to the same user
            // This assumes both tokens have the same structure and we can compare them
            // You can customize this logic based on your payload structure
            return JSON.stringify(accessPayload) === JSON.stringify(refreshPayload) ? refreshPayload : null;
        } catch (e) {
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
    error: Type.String(),
});
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};

export function JWTGuard(
    options?: JWTGuardOptions<any>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, reply: FastifyReply) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403 as const,
                    data: { error: 'Authorization header is missing' }
                } as ResponseUnion<ForbiddenResponses>;
            }

            const token = authHeader.split(/\s+/)[1];
            const session = await provider.verify(token);

            if (!session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403 as const,
                    data: { error: 'Invalid token' }
                } as ResponseUnion<ForbiddenResponses>;
            }

            let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

            if (options?.guardName) {
                validateSession = provider.getGuard(options.guardName as keyof typeof provider.config.guards);
                if (!validateSession) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403 as const,
                        data: { error: `Guard "${String(options.guardName)}" is not registered` }
                    } as ResponseUnion<ForbiddenResponses>;
                }
            }
            if (validateSession) {
                const result = await validateSession(session);
                if (result !== true) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403 as const,
                        data: {
                            error: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized'
                        }
                    } as ResponseUnion<ForbiddenResponses>;
                }
            }
            req.session = session;
            return true;
        } catch (error) {
            if (options?.optional) {
                return true;
            }
            return {
                status: 403 as const,
                data: { error: 'Unauthorized' }
            } as ResponseUnion<ForbiddenResponses>;
        }
    };
}

export function useSession<T>(req: FastifyRequest): T | undefined {
    return req.session as T | undefined;
}

export function APIKeyGuard(
    options?: JWTGuardOptions<any>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, _reply: FastifyReply) => {
        try {
            const apiKey = req.headers['x-api-key'] || req.headers.authorization;

            if (!apiKey) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'X-API-Key header is missing' },
                } as ResponseUnion<ForbiddenResponses>;
            }

            const session = await apiKeyProvider.verify(apiKey as string);
            if (!session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Invalid API key' },
                } as ResponseUnion<ForbiddenResponses>;
            }

            let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

            if (options?.guardName) {
                validateSession = provider.getGuard(options.guardName as keyof typeof provider.config.guards);
                if (!validateSession) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403,
                        data: { error: `Guard "${String(options.guardName)}" is not registered` },
                    } as ResponseUnion<ForbiddenResponses>;
                }
            }

            if (validateSession) {
                const result = await validateSession(session);
                if (result !== true) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403,
                        data: {
                            error: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized',
                        },
                    } as ResponseUnion<ForbiddenResponses>;
                }
            }

            req.session = session;
            return true;
        } catch (error) {
            if (options?.optional) {
                return true;
            }
            return {
                status: 403,
                data: { error: 'Unauthorized' }
            } as ResponseUnion<ForbiddenResponses>;
        }
    };
}

export async function isBearerValid<T>(req: FastifyRequest): Promise<false | T> {
    const authHeader = req.headers.authorization;
    if (!authHeader) return false;

    const token = authHeader.split(/\s+/)[1];
    try {
        const session = await provider.verify(token);
        if (!session) return false;
        req.session = session;
        return session as T;
    } catch (error) {
        return false;
    }
}

export async function isApiKeyValid(req: FastifyRequest): Promise<false | unknown> {
    const apiKey = req.headers['x-api-key'] || req.headers.authorization;
    if (!apiKey) return false;
    try {
        const session = await apiKeyProvider.verify(apiKey as string);
        if (!session) return false;
        req.session = session;
        return session;
    } catch (error) {
        return false;
    }
}

export async function isRefreshTokenValid<T>(req: FastifyRequest): Promise<false | T> {
    const refreshToken = req.headers['x-refresh-token'] as string;
    if (!refreshToken) return false;
    try {
        const session = await provider.verifyRefresh<T>(refreshToken);
        if (!session) return false;
        req.session = session;
        return session;
    } catch (error) {
        return false;
    }
}

export async function validateTokenPair<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null> {
    return await provider.validateTokens<T>(accessToken, refreshToken, validateFn);
}

export async function refreshAccessToken<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<string | null> {
    try {
        // First validate both tokens
        const isValid = await provider.validateTokens<T>(accessToken, refreshToken, validateFn);
        if (!isValid) {
            return null;
        }

        return await provider.signIn(isValid);
    } catch (error) {
        return null;
    }
}

