"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = createPlugin;
exports.getJWTAuthProvider = getJWTAuthProvider;
require("reflect-metadata");
const jwt_auth_1 = require("./jwt-auth");
__exportStar(require("./jwt-auth"), exports);
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
        const appConfig = this.context.config.appConfig;
        if (!this.context?.config?.swaggerOptions['securitySchemes']) {
            this.context.config.swaggerOptions.securitySchemes = {
                bearerAuth: {
                    type: "http",
                    scheme: "bearer",
                    bearerFormat: "JWT",
                }
            };
        }
        else {
            this.context.config.swaggerOptions.securitySchemes.bearerAuth = {
                type: "http",
                scheme: "bearer",
                bearerFormat: "JWT",
            };
        }
        const secretKeyFromConfig = (appConfig.secretKey || appConfig['JWT_SECRET_KEY'] || config.secretKey);
        if (!secretKeyFromConfig) {
            this.context.logger.error('JWT secret key is not provided. Please provide a secret key in the config file or as an environment variable.');
        }
        const secretKey = appConfig.secretKey || appConfig['JWT_SECRET_KEY'] || config.secretKey || defaultConfig.secretKey;
        const expirationTime = appConfig.expirationTime || appConfig['JWT_EXPIRATION_TIME'] || config.expirationTime || defaultConfig.expirationTime;
        this.config.secretKey = secretKey;
        this.config.expirationTime = expirationTime;
        jwt_auth_1.provider.init(this.config);
    }
}
function createPlugin(config) {
    return new App(config);
}
function getJWTAuthProvider() {
    if (!jwt_auth_1.provider.config) {
        throw new Error('JWTAuthProvider is not initialized. Please initialize the provider first.');
    }
    return jwt_auth_1.provider;
}
//# sourceMappingURL=index.js.map