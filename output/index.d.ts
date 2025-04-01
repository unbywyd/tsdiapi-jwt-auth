import { AppContext, AppPlugin } from "@tsdiapi/server";
import { ValidateSessionFunction } from "./jwt-auth.js";
export * from "./jwt-auth.js";
export type PluginOptions<TGuards extends Record<string, ValidateSessionFunction<any>> = {}> = {
    secretKey?: string;
    expirationTime?: number;
    guards?: TGuards;
    apiKeys?: Record<string, APIKeyEntry | 'JWT' | true>;
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
}
export default function createPlugin(config?: PluginOptions): App;
export declare function useJWTAuthProvider(): import("./jwt-auth.js").JWTAuthProvider<Record<string, ValidateSessionFunction<any>>>;
export declare function useApiKeyProvider(): import("./jwt-auth.js").ApiKeyProvider;
//# sourceMappingURL=index.d.ts.map