import { JWTPayload, jwtVerify, SignJWT } from 'jose'
import { PluginOptions, AuthMode } from './index.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { Type } from '@sinclair/typebox';
import { GuardFn, ResponseUnion, addSchema } from '@tsdiapi/server';
import { randomUUID } from 'crypto';

// Extend FastifyRequest interface
declare module 'fastify' {
    interface FastifyRequest {
        user?: UserData; // User data from authentication
    }

    interface Session {
        user?: UserData; // User data from session authentication
        jwt?: UserData;  // JWT token data
        isAuthenticated?: boolean; // Authentication flag
        destroy(callback?: (err?: Error) => void): void; // Method from @fastify/session
        regenerate(): Promise<void>; // Method from @fastify/session
    }
}

// User data types
export interface UserData {
    [key: string]: any;
}

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
export type TokenWithExpiry = {
    token: string;
    expiresAt: Date;
};
export type TokenPairWithExpiry = {
    accessToken: string;
    refreshToken: string;
    accessTokenExpiresAt: Date;
    refreshTokenExpiresAt: Date;
};

export interface AuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> {
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    signInWithExpiry<T extends Record<string, any>>(payload: T): Promise<TokenWithExpiry>;
    signInWithRefresh<T extends Record<string, any>>(payload: T): Promise<TokenPair>;
    signInWithRefreshAndExpiry<T extends Record<string, any>>(payload: T): Promise<TokenPairWithExpiry>;
    verify<T>(token: string): Promise<T | null>;
    verifyRefresh<T>(token: string): Promise<T | null>;
    validateTokens<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
    logout?(req: FastifyRequest, reply: FastifyReply): Promise<void>;
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
        const jti = randomUUID();
        return new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(jti)
            .sign(new TextEncoder().encode(this.config.secretKey));
    }

    async signInWithExpiry<T extends Record<string, any>>(payload: T): Promise<TokenWithExpiry> {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        const jti = randomUUID();
        const token = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(jti)
            .sign(new TextEncoder().encode(this.config.secretKey));

        return {
            token,
            expiresAt: new Date(exp * 1000)
        };
    }

    async signInWithRefresh<T extends Record<string, any>>(payload: T): Promise<TokenPair> {
        const iat = Math.floor(Date.now() / 1000);
        const accessExp = iat + this.config.expirationTime;
        const refreshExp = iat + this.config.refreshExpirationTime;

        // Generate unique JTI (JWT ID) to ensure token uniqueness
        const accessJti = randomUUID();
        const refreshJti = randomUUID();

        const accessToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(accessJti)
            .sign(new TextEncoder().encode(this.config.secretKey));

        const refreshToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(refreshJti)
            .sign(new TextEncoder().encode(this.config.refreshSecretKey));

        return {
            accessToken,
            refreshToken
        };
    }

    async signInWithRefreshAndExpiry<T extends Record<string, any>>(payload: T): Promise<TokenPairWithExpiry> {
        const iat = Math.floor(Date.now() / 1000);
        const accessExp = iat + this.config.expirationTime;
        const refreshExp = iat + this.config.refreshExpirationTime;

        // Generate unique JTI (JWT ID) to ensure token uniqueness
        const accessJti = randomUUID();
        const refreshJti = randomUUID();

        const accessToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(accessJti)
            .sign(new TextEncoder().encode(this.config.secretKey));

        const refreshToken = await new SignJWT({ ...(payload as JWTPayload) })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(refreshJti)
            .sign(new TextEncoder().encode(this.config.refreshSecretKey));

        return {
            accessToken,
            refreshToken,
            accessTokenExpiresAt: new Date(accessExp * 1000),
            refreshTokenExpiresAt: new Date(refreshExp * 1000)
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

    async logout(req: FastifyRequest, reply: FastifyReply): Promise<void> {
        // For JWT logout, we can't "delete" the token from the server
        // but we can clear the session if it exists
        if (req.session) {
            await destroySessionAsync(req.session);
        }

        // Clear req.user as well
        req.user = undefined;

        // In a real application, you could add token blacklist logic here
        // or other token invalidation mechanisms
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

// Session Provider
export class SessionProvider {
    config: PluginOptions | null = null;

    init(config: PluginOptions) {
        this.config = config;
    }

    async createUserSession<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<void> {
        if (!req.session) {
            throw new Error('Session is not available. Make sure @fastify/session is registered.');
        }

        // Regenerate session ID for security first
        await req.session.regenerate();

        // Now set the session data after regeneration
        req.session.user = userData;
        req.session.isAuthenticated = true;
    }

    async destroyUserSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
        if (!req.session) {
            return;
        }
        await destroySessionAsync(req.session);
    }

    async getUserFromSession<T extends UserData = UserData>(req: FastifyRequest): Promise<T | null> {
        if (!req.session || !req.session.isAuthenticated || !req.session.user) {
            return null;
        }

        return req.session.user as T;
    }

    async isSessionValid(req: FastifyRequest): Promise<boolean> {
        return !!(req.session && req.session.isAuthenticated && req.session.user);
    }

    // Гибридный метод: создает и JWT токены, и сессию
    async createHybridAuth<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<{
        tokens: TokenPairWithExpiry;
        session: boolean;
    }> {
        // Создаем JWT токены
        const tokens = await provider.signInWithRefreshAndExpiry(userData);

        // Создаем сессию
        await this.createUserSession(req, reply, userData);

        return {
            tokens,
            session: true
        };
    }
}

const sessionProvider: SessionProvider = new SessionProvider();

// Helper function to destroy session asynchronously
function destroySessionAsync(session: any): Promise<void> {
    return new Promise((resolve, reject) => {
        if (session.destroy) {
        session.destroy((err?: Error) => {
            if (err) {
                reject(err);
            } else {
                resolve();
                }
            });
        } else {
            resolve();
        }
    });
}

export { provider, apiKeyProvider, sessionProvider };

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

const forbiddenResponse = addSchema(
    Type.Object({
        error: Type.String(),
    }, {
        $id: 'ForbiddenResponse'
    })
);
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};

export function getAccessToken(req: FastifyRequest): string | undefined {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return undefined;
    }
    return authHeader.split(/\s+/)[1];
}

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
            // Store JWT session data
            if (req.session) {
                req.session.jwt = session;
                req.session.isAuthenticated = true;
            } else {
                req.user = session as UserData;
            }
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

export function useSession<T extends UserData = UserData>(req: FastifyRequest): T | undefined {
    // Try to get user from session first
    if (req.session?.user) {
        return req.session.user as T;
    }

    // Try to get JWT data from session
    if (req.session?.jwt) {
        return req.session.jwt as T;
    }

    // Fallback to req.user
    return req.user as T | undefined;
}

// Session Guard
export function SessionGuard(
    options?: JWTGuardOptions<any>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, reply: FastifyReply) => {
        try {
            if (!req.session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403 as const,
                    data: { error: 'Session support not initialized. Please install @fastify/session and @fastify/cookie' }
                } as ResponseUnion<ForbiddenResponses>;
            }

            const isSessionValid = await sessionProvider.isSessionValid(req);
            if (!isSessionValid) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403 as const,
                    data: { error: 'Invalid session' }
                } as ResponseUnion<ForbiddenResponses>;
            }

            const userData = await sessionProvider.getUserFromSession(req);
            if (!userData) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403 as const,
                    data: { error: 'User not found in session' }
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
                const result = await validateSession(userData);
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

            // Store user data in session properly
            if (req.session) {
                req.session.user = userData;
                req.session.isAuthenticated = true;
            } else {
                // Fallback: store in req.user if session is not available
                req.user = userData as UserData;
            }
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

            // Store JWT session data
            if (req.session) {
                req.session.jwt = session;
                req.session.isAuthenticated = true;
            } else {
                req.user = session as UserData;
            }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        } else {
            req.user = session as UserData;
        }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        } else {
            req.user = session as UserData;
        }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        } else {
            req.user = session as UserData;
        }
        return session;
    } catch (error) {
        return false;
    }
}

export async function validateTokenPair<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null> {
    return await provider.validateTokens<T>(accessToken, refreshToken, validateFn);
}

export async function refreshAccessToken<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<TokenPairWithExpiry | null> {
    try {
        // First validate both tokens
        const isValid = await provider.validateTokens<T>(accessToken, refreshToken, validateFn);
        if (!isValid) {
            return null;
        }

        // Extract payload from refresh token (not from validation result)
        const refreshPayload = await provider.verifyRefresh<T>(refreshToken);
        if (!refreshPayload) {
            return null;
        }

        // Generate new tokens using the refresh token payload
        return await provider.signInWithRefreshAndExpiry(refreshPayload);
    } catch (error) {
        return null;
    }
}

// Universal user functions
export async function useUser<T extends UserData = UserData>(req: FastifyRequest): Promise<T | null> {
    // First try to get user from session (JWT or session data)
    const sessionUser = useSession<T>(req);
    if (sessionUser) {
        return sessionUser;
    }

    // Then try to get user from JWT token
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(/\s+/)[1];
        const jwtUser = await provider.verify<T>(token);
        if (jwtUser) {
            return jwtUser;
        }
    }

    // Finally try to get user from session provider
    const sessionProviderUser = await sessionProvider.getUserFromSession<T>(req);
    if (sessionProviderUser) {
        return sessionProviderUser;
    }

    return null;
}

export async function createUserSession<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<void> {
    return await sessionProvider.createUserSession(req, reply, userData);
}

export async function destroyUserSession(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    return await sessionProvider.destroyUserSession(req, reply);
}

export async function isSessionValid(req: FastifyRequest): Promise<boolean> {
    return await sessionProvider.isSessionValid(req);
}

// Гибридная авторизация: создает и JWT токены, и сессию
export async function createHybridAuth<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<{
    tokens: TokenPairWithExpiry;
    session: boolean;
}> {
    return await sessionProvider.createHybridAuth(req, reply, userData);
}

// JWT logout function
export async function logout(req: FastifyRequest, reply: FastifyReply): Promise<void> {
    return await provider.logout(req, reply);
}

// Hybrid Authentication Guard
export type HybridAuthGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    mode?: AuthMode;
    fallbackMode?: 'jwt-to-session' | 'session-to-jwt';
    guardName?: keyof TGuards;
    validateSession?: ValidateSessionFunction<Record<string, any>>;
    errorMessage?: string;
    guardDescription?: string;
    optional?: boolean;
};

export function HybridAuthGuard<TGuards extends Record<string, ValidateSessionFunction<any>>>(
    options?: HybridAuthGuardOptions<TGuards>
): GuardFn<ForbiddenResponses, unknown> {
    return async (req: FastifyRequest, reply: FastifyReply) => {
        try {
            const mode = options?.mode || provider.config?.authMode || 'hybrid';
            let jwtUser: UserData | null = null;
            let sessionUser: UserData | null = null;
            let jwtValid = false;
            let sessionValid = false;

            // Try JWT authentication
            if (mode === 'jwt-only' || mode === 'hybrid' || mode === 'require-both') {
                const authHeader = req.headers.authorization;
                if (authHeader) {
                    const token = authHeader.split(/\s+/)[1];
                    jwtUser = await provider.verify(token);
                    jwtValid = !!jwtUser;
                }
            }

            // Try session authentication
            if (mode === 'session-only' || mode === 'hybrid' || mode === 'require-both') {
                sessionValid = await sessionProvider.isSessionValid(req);
                if (sessionValid) {
                    sessionUser = await sessionProvider.getUserFromSession(req);
                }
            }

            // Apply authentication mode logic
            switch (mode) {
                case 'jwt-only':
                    if (!jwtValid) {
                        if (options?.optional) return true;
                        return {
                            status: 403 as const,
                            data: { error: 'JWT authentication required' }
                        } as ResponseUnion<ForbiddenResponses>;
                    }
                    // Store JWT user data
                    if (req.session) {
                        req.session.jwt = jwtUser;
                        req.session.isAuthenticated = true;
                    } else {
                        req.user = jwtUser;
                    }
                    break;

                case 'session-only':
                    if (!sessionValid) {
                        if (options?.optional) return true;
                        return {
                            status: 403 as const,
                            data: { error: 'Session authentication required' }
                        } as ResponseUnion<ForbiddenResponses>;
                    }
                    // Store session user data
                    if (req.session) {
                        req.session.user = sessionUser;
                        req.session.isAuthenticated = true;
                    } else {
                        req.user = sessionUser;
                    }
                    break;

                case 'hybrid':
                    if (jwtValid) {
                        // Store JWT user data
                        if (req.session) {
                            req.session.jwt = jwtUser;
                            req.session.isAuthenticated = true;
                        } else {
                            req.user = jwtUser;
                        }
                        
                        // Если JWT валиден, но сессии нет или она невалидна - воссоздаем сессию
                        if (jwtValid && !sessionValid && req.session) {
                            try {
                                await sessionProvider.createUserSession(req, reply, jwtUser);
                            } catch (error) {
                                // Если не удалось создать сессию, продолжаем с JWT
                                console.warn('Failed to recreate session from JWT:', error);
                            }
                        }
                    } else if (sessionValid) {
                        // Store session user data
                        if (req.session) {
                            req.session.user = sessionUser;
                            req.session.isAuthenticated = true;
                        } else {
                            req.user = sessionUser;
                        }
                    } else {
                        if (options?.optional) return true;
                        return {
                            status: 403 as const,
                            data: { error: 'Authentication required (JWT or session)' }
                        } as ResponseUnion<ForbiddenResponses>;
                    }
                    break;

                case 'require-both':
                    if (!jwtValid || !sessionValid) {
                        if (options?.optional) return true;
                        return {
                            status: 403 as const,
                            data: { error: 'Both JWT and session authentication required' }
                        } as ResponseUnion<ForbiddenResponses>;
                    }
                    // Use JWT user as primary, session as secondary validation
                    // Store JWT user data
                    if (req.session) {
                        req.session.jwt = jwtUser;
                        req.session.isAuthenticated = true;
                    } else {
                        req.user = jwtUser;
                    }
                    break;

                default:
                    if (options?.optional) return true;
                    return {
                        status: 403 as const,
                        data: { error: 'Invalid authentication mode' }
                    } as ResponseUnion<ForbiddenResponses>;
            }

            // Apply validation if specified
            let validateSession: ValidateSessionFunction<any> | undefined = options?.validateSession;

            if (options?.guardName) {
                validateSession = provider.getGuard(options.guardName as string);
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
                const result = await validateSession(req.session);
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

