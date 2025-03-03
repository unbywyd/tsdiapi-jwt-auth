"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JWTTokenAuthCheckHandler = exports.provider = exports.JWTAuthProvider = void 0;
exports.JWTGuard = JWTGuard;
exports.isJWTValid = isJWTValid;
exports.CurrentSession = CurrentSession;
const routing_controllers_openapi_1 = require("routing-controllers-openapi");
const jose_1 = require("jose");
const routing_controllers_1 = require("routing-controllers");
class JWTAuthProvider {
    config;
    init(config) {
        this.config = config;
    }
    signIn(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        return new jose_1.SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
    }
    async verify(token) {
        try {
            const { payload } = await (0, jose_1.jwtVerify)(token, new TextEncoder().encode(this.config.secretKey));
            return payload;
        }
        catch (e) {
            console.error(e);
            return null;
        }
    }
    getGuard(name) {
        return this.config?.guards?.[name];
    }
}
exports.JWTAuthProvider = JWTAuthProvider;
const provider = new JWTAuthProvider();
exports.provider = provider;
const JWTTokenAuthCheckHandler = async (token) => {
    try {
        const session = await provider.verify(token);
        if (!session) {
            return new Error('Token is invalid!');
        }
        return session;
    }
    catch (_) {
        return new Error('Token is invalid!');
    }
};
exports.JWTTokenAuthCheckHandler = JWTTokenAuthCheckHandler;
function JWTGuard(options) {
    return function (target, propertyKey, descriptor) {
        (0, routing_controllers_1.UseBefore)(async (request, response, next) => {
            const authHeader = request.headers.authorization;
            if (!authHeader) {
                return response.status(403).send({ status: 403, message: 'Unauthorized!' });
            }
            const token = authHeader.split(/\s+/)[1];
            try {
                const session = await provider.verify(token);
                if (!session) {
                    return response.status(403).send({ status: 403, message: 'Invalid token!' });
                }
                let validateSession = options?.validateSession;
                // Если указано имя гуарда, ищем его в конфигурации
                if (options?.guardName) {
                    validateSession = provider.getGuard(options.guardName?.toString());
                    if (!validateSession) {
                        return response
                            .status(403)
                            .send({ status: 403, message: `Guard "${options.guardName?.toString()}" is not registered!` });
                    }
                }
                // Выполняем валидацию, если валидатор определён
                if (validateSession) {
                    const validationResult = await validateSession(session);
                    if (validationResult !== true) {
                        const errorMessage = typeof validationResult === 'string' ? validationResult : options?.errorMessage || 'Unauthorized!';
                        return response.status(403).send({ status: 403, message: errorMessage });
                    }
                }
                request.session = session; // Сохраняем сессию в запросе
                next();
            }
            catch {
                return response.status(403).send({ status: 403, message: 'Unauthorized!' });
            }
        })(target, propertyKey, descriptor);
        return (0, routing_controllers_openapi_1.OpenAPI)((operation) => {
            operation.security = [{ bearerAuth: [] }];
            if (options?.guardDescription) {
                operation.description = operation?.description
                    ? `${operation.description} ${options.guardDescription}`
                    : options.guardDescription;
            }
            return operation;
        })(target, propertyKey, descriptor);
    };
}
async function isJWTValid(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader)
        return false;
    const token = authHeader.split(/\s+/)[1];
    try {
        const session = await provider.verify(token);
        if (!session)
            return false;
        return session;
    }
    catch (error) {
        console.error('JWT validation error:', error);
        return false;
    }
}
function CurrentSession() {
    return (0, routing_controllers_1.createParamDecorator)({
        value: (action) => {
            return action.request?.session || null;
        },
    });
}
//# sourceMappingURL=jwt-auth.js.map