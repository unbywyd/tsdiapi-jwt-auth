import { PluginOptions } from '.';
export declare class jwtConfig<TGuards extends Record<string, ValidateSessionFunction<any>>> {
    config: PluginOptions<TGuards> | null;
    init(config: PluginOptions<TGuards>): void;
    signIn<T extends Record<string, any>>(payload: T): Promise<string>;
    verify<T>(token: string): Promise<T>;
    getGuard(name: keyof TGuards): ValidateSessionFunction<any> | undefined;
}
declare const jwt: jwtConfig<Record<string, ValidateSessionFunction<any>>>;
export { jwt };
export declare const JWTTokenAuthCheckHandler: (token: string) => Promise<unknown>;
export type ValidateSessionFunction<T> = (session: T) => Promise<boolean | string> | (boolean | string);
export type JWTGuardOptions<TGuards extends Record<string, ValidateSessionFunction<any>>> = {
    guardName?: keyof TGuards;
    validateSession?: ValidateSessionFunction<Record<string, any>>;
    errorMessage?: string;
    guardDescription?: string;
};
export declare function JWTGuard<TGuards extends Record<string, ValidateSessionFunction<any>>>(options?: JWTGuardOptions<TGuards>): (target: any, propertyKey?: string, descriptor?: PropertyDescriptor) => void;
export declare function CurrentSession(): (object: Object, method: string, index: number) => void;
//# sourceMappingURL=jwt-auth.d.ts.map