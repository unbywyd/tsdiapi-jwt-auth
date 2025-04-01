import { APIKeyEntry, PluginOptions } from './index.js';
import type { FastifyRequest } from 'fastify';
import { TSchema } from '@sinclair/typebox';
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
export declare function JWTGuard<TResponses extends Record<number, TSchema>>(options?: JWTGuardOptions<any>): GuardFn<TResponses, unknown>;
export declare function APIKeyGuard<TResponses extends Record<number, TSchema>>(options?: JWTGuardOptions<any>): GuardFn<TResponses, unknown>;
export declare function isBearerValid<T>(req: FastifyRequest): Promise<false | T>;
export declare function isApiKeyValid(req: FastifyRequest): Promise<false | unknown>;
//# sourceMappingURL=jwt-auth.d.ts.map