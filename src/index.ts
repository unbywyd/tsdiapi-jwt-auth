import { AppContext, AppPlugin } from "@tsdiapi/server";
import { provider, ValidateSessionFunction, apiKeyProvider } from "./jwt-auth.js";
export * from "./jwt-auth.js";

// jwt params
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

const defaultConfig: PluginOptions = {
    secretKey: 'secret-key-for-jwt',
    expirationTime: 60 * 60 * 24 * 7 // 7 days
}

class App implements AppPlugin {
    name = 'tsdiapi-jwt-auth';
    config: PluginOptions;
    context: AppContext;
    constructor(config?: PluginOptions) {
        this.config = { ...config };
    }
    async onInit(ctx: AppContext) {
        this.context = ctx;
        const config = this.config;
        const appConfig = ctx.projectConfig;

        const secretKeyFromConfig = appConfig.get('JWT_SECRET_KEY', config.secretKey || defaultConfig.secretKey) as string;
        const expirationTime = appConfig.get('JWT_EXPIRATION_TIME', config.expirationTime || defaultConfig.expirationTime) as number;

        this.config.secretKey = secretKeyFromConfig;
        this.config.expirationTime = expirationTime;
        provider.init(this.config);
        apiKeyProvider.init(this.config);
    }
}

export default function createPlugin(config?: PluginOptions) {
    return new App(config);
}

export function useJWTAuthProvider() {
    if (!provider.config) {
        throw new Error('JWTAuthProvider is not initialized. Please initialize the provider first.');
    }
    return provider;
}
export function useApiKeyProvider() {
    if (!apiKeyProvider.config) {
        throw new Error('ApiKeyProvider is not initialized. Please initialize the provider first.');
    }
    return apiKeyProvider;
}