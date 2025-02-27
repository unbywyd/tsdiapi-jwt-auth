import "reflect-metadata";
import { AppContext, AppPlugin } from "@tsdiapi/server";
import { provider, ValidateSessionFunction } from "./jwt-auth";
export * from "./jwt-auth";

// jwt params
export type PluginOptions<TGuards extends Record<string, ValidateSessionFunction<any>> = {}> = {
    secretKey?: string;
    expirationTime?: number;
    guards?: TGuards;
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
        const appConfig = this.context.config.appConfig;

        if (!this.context?.config?.swaggerOptions['securitySchemes']) {
            this.context.config.swaggerOptions.securitySchemes = {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                }
            }
        } else {
            this.context.config.swaggerOptions.securitySchemes.bearerAuth = {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT",
            }
        }
        const secretKeyFromConfig = (appConfig.secretKey || appConfig['JWT_SECRET_KEY'] || config.secretKey);
        if (!secretKeyFromConfig) {
            this.context.logger.error('JWT secret key is not provided. Please provide a secret key in the config file or as an environment variable.');
        }

        const secretKey = appConfig.secretKey || appConfig['JWT_SECRET_KEY'] || config.secretKey || defaultConfig.secretKey;
        const expirationTime = appConfig.expirationTime || appConfig['JWT_EXPIRATION_TIME'] || config.expirationTime || defaultConfig.expirationTime;

        this.config.secretKey = secretKey;
        this.config.expirationTime = expirationTime;
        provider.init(this.config);
    }

}

export default function createPlugin(config?: PluginOptions) {
    return new App(config);
}

export function getJWTAuthProvider() {
    if (!provider.config) {
        throw new Error('JWTAuthProvider is not initialized. Please initialize the provider first.');
    }
    return provider;
}