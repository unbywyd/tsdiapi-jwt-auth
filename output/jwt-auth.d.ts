import { PluginOptions } from './index.js';
import type { FastifyRequest } from 'fastify';
import { GuardFn } from '@tsdiapi/server';
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
export { provider, apiKeyProvider };
export declare const JWTTokenAuthCheckHandler: (token: string) => Promise<unknown>;
declare const forbiddenResponse: import("@sinclair/typebox").TObject<{
    error: import("@sinclair/typebox").TString;
}>;
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};
export declare function GetAccessToken(req: FastifyRequest): string | undefined;
export declare function JWTGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function useSession<T>(req: FastifyRequest): T | undefined;
export declare function APIKeyGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function isBearerValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function isApiKeyValid(req: FastifyRequest): Promise<false | unknown>;
export declare function isRefreshTokenValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function validateTokenPair<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<T | null>;
export declare function refreshAccessToken<T>(accessToken: string, refreshToken: string, validateFn?: ValidateTokenPairFunction<T>): Promise<TokenPairWithExpiry | null>;
//# sourceMappingURL=jwt-auth.d.ts.map