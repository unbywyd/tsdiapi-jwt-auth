import { APIKeyEntry, PluginOptions } from './index.js';
import type { FastifyRequest } from 'fastify';
import { GuardFn } from '@tsdiapi/server';
export type ValidateSessionFunction<T> = (session: T) => Promise<boolean | string> | (boolean | string);
export type JWTGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    guardName?: keyof TGuards;
    validateSession?: ValidateSessionFunction<Record<string, any>>;
    errorMessage?: string;
    guardDescription?: string;
};
export interface AuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> {
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    verify<T>(token: string): Promise<T | null>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
}
export declare class JWTAuthProvider<TGuards extends Record<string, ValidateSessionFunction<any>>> implements AuthProvider<TGuards> {
    config: PluginOptions<TGuards> | null;
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    verify<T>(token: string): Promise<T>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
}
declare const provider: JWTAuthProvider<Record<string, ValidateSessionFunction<any>>>;
export declare class ApiKeyProvider {
    constructor();
    config: PluginOptions | null;
    init(config: PluginOptions): void;
    get keys(): Record<string, true | "JWT" | APIKeyEntry>;
    verify(key: string): Promise<unknown>;
}
declare const apiKeyProvider: ApiKeyProvider;
export { provider, apiKeyProvider };
export declare const JWTTokenAuthCheckHandler: (token: string) => Promise<unknown>;
declare const forbiddenResponse: import("@sinclair/typebox").TObject<{
    error: import("@sinclair/typebox").TOptional<import("@sinclair/typebox").TString>;
}>;
type ForbiddenResponses = {
    403: typeof forbiddenResponse;
};
export declare function JWTGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function useSession<T>(req: FastifyRequest): T | undefined;
export declare function APIKeyGuard(options?: JWTGuardOptions<any>): GuardFn<ForbiddenResponses, unknown>;
export declare function isBearerValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function isApiKeyValid(req: FastifyRequest): Promise<false | unknown>;
//# sourceMappingURL=jwt-auth.d.ts.map