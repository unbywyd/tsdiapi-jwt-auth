"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VerifyJWT = exports.SignJWT = exports.JWTTokenAuthCheckHandler = exports.CurrentSession = exports.JWTGuard = exports.jwt = void 0;
exports.default = createPlugin;
require("reflect-metadata");
const jwt_auth_1 = require("./jwt-auth");
var jwt_auth_2 = require("./jwt-auth");
Object.defineProperty(exports, "jwt", { enumerable: true, get: function () { return jwt_auth_2.jwt; } });
Object.defineProperty(exports, "JWTGuard", { enumerable: true, get: function () { return jwt_auth_2.JWTGuard; } });
Object.defineProperty(exports, "CurrentSession", { enumerable: true, get: function () { return jwt_auth_2.CurrentSession; } });
Object.defineProperty(exports, "JWTTokenAuthCheckHandler", { enumerable: true, get: function () { return jwt_auth_2.JWTTokenAuthCheckHandler; } });
const SignJWT = jwt_auth_1.jwt.signIn;
exports.SignJWT = SignJWT;
const VerifyJWT = jwt_auth_1.jwt.verify;
exports.VerifyJWT = VerifyJWT;
const defaultConfig = {
    secretKey: 'secret',
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
        const secretKey = appConfig.secretKey || appConfig['JWT_SECRET_KEY'] || config.secretKey || defaultConfig.secretKey;
        const expirationTime = appConfig.expirationTime || appConfig['JWT_EXPIRATION_TIME'] || config.expirationTime || defaultConfig.expirationTime;
        this.config.secretKey = secretKey;
        this.config.expirationTime = expirationTime;
        jwt_auth_1.jwt.init(this.config);
    }
}
function createPlugin(config) {
    return new App(config);
}
//# sourceMappingURL=index.js.map