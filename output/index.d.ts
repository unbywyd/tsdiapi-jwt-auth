import { AppContext, AppPlugin } from "@tsdiapi/server";
import { ValidateSessionFunction } from "./jwt-auth.js";
export * from "./jwt-auth.js";
export type AuthMode = 'jwt-only' | 'session-only' | 'hybrid' | 'require-both';
export type SessionStore = 'memory' | 'redis' | 'mongodb' | 'custom';
export type SessionConfig = {
    store?: SessionStore;
    secret?: string;
    cookieName?: string;
    cookieOptions?: {
        secure?: boolean;
        httpOnly?: boolean;
        sameSite?: 'strict' | 'lax' | 'none';
        maxAge?: number;
        path?: string;
        domain?: string;
    };
    customStore?: any;
};
export type PluginOptions<TGuards extends Record<string, ValidateSessionFunction<any>> = {}> = {
    secretKey?: string;
    expirationTime?: number;
    refreshSecretKey?: string;
    refreshExpirationTime?: number;
    guards?: TGuards;
    apiKeys?: Record<string, APIKeyEntry | 'JWT' | true>;
    session?: SessionConfig;
    authMode?: AuthMode;
    fallbackMode?: 'jwt-to-session' | 'session-to-jwt';
};
export type APIKeyEntry = {
    description?: string;
    validate?: () => boolean | Promise<boolean>;
};
declare class App implements AppPlugin {
    name: string;
    config: PluginOptions;
    context: AppContext;
    constructor(config?: PluginOptions);
    onInit(ctx: AppContext): Promise<void>;
    beforeStart(ctx: AppContext): Promise<void>;
    private setupSessions;
}
export default function createPlugin(config?: PluginOptions): App;
export declare function useJWTAuthProvider(): import("./jwt-auth.js").JWTAuthProvider<Record<string, ValidateSessionFunction<any>>>;
export declare function useApiKeyProvider(): import("./jwt-auth.js").ApiKeyProvider;
export declare function useSessionProvider(): import("./jwt-auth.js").SessionProvider;
//# sourceMappingURL=index.d.ts.map