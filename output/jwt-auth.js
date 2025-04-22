import { jwtVerify, SignJWT } from 'jose';
import { Type } from '@sinclair/typebox';
export class JWTAuthProvider {
    config;
    init(config) {
        this.config = config;
    }
    signIn(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        return new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
    }
    async verify(token) {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.secretKey));
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
const provider = new JWTAuthProvider();
export class ApiKeyProvider {
    constructor() { }
    config = null;
    init(config) {
        this.config = config;
    }
    get keys() {
        return this.config?.apiKeys || {};
    }
    async verify(key) {
        const entry = this.keys[key];
        if (!(key in this.keys) || entry === 'JWT') {
            return provider.verify(key);
        }
        if (entry === true) {
            return true;
        }
        if (entry.validate) {
            return await entry.validate();
        }
        return true;
    }
}
const apiKeyProvider = new ApiKeyProvider();
export { provider, apiKeyProvider };
export const JWTTokenAuthCheckHandler = async (token) => {
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
const forbiddenResponse = Type.Object({
    error: Type.String(),
});
export function JWTGuard(options) {
    return async (req, reply) => {
        const authHeader = req.headers.authorization;
        if (!authHeader) {
            return {
                status: 403,
                data: { error: 'Authorization header is missing' }
            };
        }
        const token = authHeader.split(/\s+/)[1];
        const session = await provider.verify(token);
        if (!session) {
            return {
                status: 403,
                data: { error: 'Invalid token' }
            };
        }
        let validateSession = options?.validateSession;
        if (options?.guardName) {
            validateSession = provider.getGuard(options.guardName);
            if (!validateSession) {
                return {
                    status: 403,
                    data: { error: `Guard "${String(options.guardName)}" is not registered` }
                };
            }
        }
        if (validateSession) {
            const result = await validateSession(session);
            if (result !== true) {
                return {
                    status: 403,
                    data: {
                        error: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized'
                    }
                };
            }
        }
        req.session = session;
        return true;
    };
}
export function useSession(req) {
    return req.session;
}
export function APIKeyGuard(options) {
    return async (req, _reply) => {
        const apiKey = req.headers['x-api-key'] || req.headers.authorization;
        if (!apiKey) {
            return {
                status: 403,
                data: { error: 'X-API-Key header is missing' },
            };
        }
        const session = await apiKeyProvider.verify(apiKey);
        if (!session) {
            return {
                status: 403,
                data: { error: 'Invalid API key' },
            };
        }
        let validateSession = options?.validateSession;
        if (options?.guardName) {
            validateSession = provider.getGuard(options.guardName);
            if (!validateSession) {
                return {
                    status: 403,
                    data: { error: `Guard "${String(options.guardName)}" is not registered` },
                };
            }
        }
        if (validateSession) {
            const result = await validateSession(session);
            if (result !== true) {
                return {
                    status: 403,
                    data: {
                        error: typeof result === 'string' ? result : options?.errorMessage || 'Unauthorized',
                    },
                };
            }
        }
        req.session = session;
        return true;
    };
}
export async function isBearerValid(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader)
        return false;
    const token = authHeader.split(/\s+/)[1];
    try {
        const session = await provider.verify(token);
        if (!session)
            return false;
        req.session = session;
        return session;
    }
    catch (error) {
        console.error('JWT validation error:', error);
        return false;
    }
}
export async function isApiKeyValid(req) {
    const apiKey = req.headers['x-api-key'] || req.headers.authorization;
    if (!apiKey)
        return false;
    try {
        const session = await apiKeyProvider.verify(apiKey);
        if (!session)
            return false;
        req.session = session;
        return session;
    }
    catch (error) {
        console.error('API key validation error:', error);
        return false;
    }
}
//# sourceMappingURL=jwt-auth.js.map