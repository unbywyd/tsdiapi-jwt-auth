import { provider, apiKeyProvider } from "./jwt-auth.js";
export * from "./jwt-auth.js";
const defaultConfig = {
    secretKey: 'secret-key-for-jwt',
    expirationTime: 60 * 60 * 24 * 7 // 7 days
};
class App {
    name = 'tsdiapi-jwt-auth';
    config;
    context;
    constructor(config) {
        this.config = { ...config };
    }
    async onInit(ctx) {
        this.context = ctx;
        const config = this.config;
        const appConfig = ctx.projectConfig;
        const secretKeyFromConfig = appConfig.get('JWT_SECRET_KEY', config.secretKey || defaultConfig.secretKey);
        const expirationTime = appConfig.get('JWT_EXPIRATION_TIME', config.expirationTime || defaultConfig.expirationTime);
        this.config.secretKey = secretKeyFromConfig;
        this.config.expirationTime = expirationTime;
        provider.init(this.config);
        apiKeyProvider.init(this.config);
    }
}
export default function createPlugin(config) {
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
//# sourceMappingURL=index.js.map