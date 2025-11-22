import { PluginOptions, AuthMode } from './index.js';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { GuardFn } from '@tsdiapi/server';
declare module 'fastify' {
    interface FastifyRequest {
        user?: UserData;
    }
    interface Session {
        user?: UserData;
        jwt?: UserData;
        isAuthenticated?: boolean;
        destroy(callback?: (err?: Error) => void): void;
        regenerate(): Promise<void>;
    }
}
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
export declare class JWTAuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> implements AuthProvider<TGuards> {
    config: PluginOptions<TGuards> | null;
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    signInWithExpiry<T extends Record<string, any>>(payload: T): Promise<TokenWithExpiry>;
    signInWithRefresh<T extends Record<string, any>>(payload: T): Promise<TokenPair>;
    signInWithRefreshAndExpiry<T extends Record<string, any>>(payload: T): Promise<TokenPairWithExpiry>;
    verify<T>(token: string): Promise<T>;
    verifyRefresh<T>(token: string): Promise<T>;
    validateTokens<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
    logout(req: FastifyRequest, reply: FastifyReply): Promise<void>;
}
declare const provider: JWTAuthProvider<Record<string, ValidateSessionFunction<any>>>;
export declare class ApiKeyProvider {
    constructor();
    config: PluginOptions | null;
    init(config: PluginOptions): void;
    get keys(): Record<string, true | "JWT" | import("./index.js").APIKeyEntry>;
    verify(key: string): Promise<unknown>;
}
declare const apiKeyProvider: ApiKeyProvider;
export declare class SessionProvider {
    config: PluginOptions | null;
    init(config: PluginOptions): void;
    createUserSession<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<void>;
    destroyUserSession(req: FastifyRequest, reply: FastifyReply): Promise<void>;
    getUserFromSession<T extends UserData = UserData>(req: FastifyRequest): Promise<T | null>;
    isSessionValid(req: FastifyRequest): Promise<boolean>;
    createHybridAuth<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<{
        tokens: TokenPairWithExpiry;
        session: boolean;
    }>;
}
declare const sessionProvider: SessionProvider;
export { provider, apiKeyProvider, sessionProvider };
export declare const JWTTokenAuthCheckHandler: (token: string) => Promise<unknown>;
declare const forbiddenResponse: import("@sinclair/typebox").TObject<{
    error: import("@sinclair/typebox").TString;
}> & {
    $id: string;
};
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};
export declare function getAccessToken(req: FastifyRequest): string | undefined;
export declare function JWTGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function useSession<T extends UserData = UserData>(req: FastifyRequest): T | undefined;
export declare function SessionGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function APIKeyGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function isBearerValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function isApiKeyValid(req: FastifyRequest): Promise<false | unknown>;
export declare function isRefreshTokenValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function validateTokenPair<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null>;
export declare function refreshAccessToken<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<TokenPairWithExpiry | null>;
export declare function useUser<T extends UserData = UserData>(req: FastifyRequest): Promise<T | null>;
export declare function createUserSession<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<void>;
export declare function destroyUserSession(req: FastifyRequest, reply: FastifyReply): Promise<void>;
export declare function isSessionValid(req: FastifyRequest): Promise<boolean>;
export declare function createHybridAuth<T extends UserData>(req: FastifyRequest, reply: FastifyReply, userData: T): Promise<{
    tokens: TokenPairWithExpiry;
    session: boolean;
}>;
export declare function logout(req: FastifyRequest, reply: FastifyReply): Promise<void>;
export type HybridAuthGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    mode?: AuthMode;
    fallbackMode?: 'jwt-to-session' | 'session-to-jwt';
    guardName?: keyof TGuards;
    validateSession?: ValidateSessionFunction<Record<string, any>>;
    errorMessage?: string;
    guardDescription?: string;
    optional?: boolean;
};
export declare function HybridAuthGuard<TGuards extends Record<string, ValidateSessionFunction<any>>>(options?: HybridAuthGuardOptions<TGuards>): GuardFn<ForbiddenResponses, unknown>;
//# sourceMappingURL=jwt-auth.d.ts.map