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
    async signInWithExpiry(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        const token = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
        return {
            token,
            expiresAt: new Date(exp * 1000)
        };
    }
    async signInWithRefresh(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const accessExp = iat + this.config.expirationTime;
        const refreshExp = iat + this.config.refreshExpirationTime;
        const accessToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
        const refreshToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.refreshSecretKey));
        return {
            accessToken,
            refreshToken
        };
    }
    async signInWithRefreshAndExpiry(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const accessExp = iat + this.config.expirationTime;
        const refreshExp = iat + this.config.refreshExpirationTime;
        const accessToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.secretKey));
        const refreshToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .sign(new TextEncoder().encode(this.config.refreshSecretKey));
        return {
            accessToken,
            refreshToken,
            accessTokenExpiresAt: new Date(accessExp * 1000),
            refreshTokenExpiresAt: new Date(refreshExp * 1000)
        };
    }
    async verify(token) {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.secretKey));
            return payload;
        }
        catch (e) {
            return null;
        }
    }
    async verifyRefresh(token) {
        try {
            const { payload } = await jwtVerify(token, new TextEncoder().encode(this.config.refreshSecretKey));
            return payload;
        }
        catch (e) {
            return null;
        }
    }
    async validateTokens(accessToken, refreshToken, validateFn) {
        try {
            const accessPayload = await this.verify(accessToken);
            const refreshPayload = await this.verifyRefresh(refreshToken);
            if (!accessPayload || !refreshPayload) {
                return null;
            }
            // If custom validation function is provided, use it
            if (validateFn) {
                return await validateFn(accessPayload, refreshPayload);
            }
            // Default validation: check if both tokens belong to the same user
            // This assumes both tokens have the same structure and we can compare them
            // You can customize this logic based on your payload structure
            return JSON.stringify(accessPayload) === JSON.stringify(refreshPayload) ? refreshPayload : null;
        }
        catch (e) {
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
export function getAccessToken(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return undefined;
    }
    return authHeader.split(/\s+/)[1];
}
export function JWTGuard(options) {
    return async (req, reply) => {
        try {
            const authHeader = req.headers.authorization;
            if (!authHeader) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Authorization header is missing' }
                };
            }
            const token = authHeader.split(/\s+/)[1];
            const session = await provider.verify(token);
            if (!session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Invalid token' }
                };
            }
            let validateSession = options?.validateSession;
            if (options?.guardName) {
                validateSession = provider.getGuard(options.guardName);
                if (!validateSession) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403,
                        data: { error: `Guard "${String(options.guardName)}" is not registered` }
                    };
                }
            }
            if (validateSession) {
                const result = await validateSession(session);
                if (result !== true) {
                    if (options?.optional) {
                        return true;
                    }
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
        }
        catch (error) {
            if (options?.optional) {
                return true;
            }
            return {
                status: 403,
                data: { error: 'Unauthorized' }
            };
        }
    };
}
export function useSession(req) {
    return req.session;
}
export function APIKeyGuard(options) {
    return async (req, _reply) => {
        try {
            const apiKey = req.headers['x-api-key'] || req.headers.authorization;
            if (!apiKey) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'X-API-Key header is missing' },
                };
            }
            const session = await apiKeyProvider.verify(apiKey);
            if (!session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Invalid API key' },
                };
            }
            let validateSession = options?.validateSession;
            if (options?.guardName) {
                validateSession = provider.getGuard(options.guardName);
                if (!validateSession) {
                    if (options?.optional) {
                        return true;
                    }
                    return {
                        status: 403,
                        data: { error: `Guard "${String(options.guardName)}" is not registered` },
                    };
                }
            }
            if (validateSession) {
                const result = await validateSession(session);
                if (result !== true) {
                    if (options?.optional) {
                        return true;
                    }
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
        }
        catch (error) {
            if (options?.optional) {
                return true;
            }
            return {
                status: 403,
                data: { error: 'Unauthorized' }
            };
        }
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
        return false;
    }
}
export async function isRefreshTokenValid(req) {
    const refreshToken = req.headers['x-refresh-token'];
    if (!refreshToken)
        return false;
    try {
        const session = await provider.verifyRefresh(refreshToken);
        if (!session)
            return false;
        req.session = session;
        return session;
    }
    catch (error) {
        return false;
    }
}
export async function validateTokenPair(accessToken, refreshToken, validateFn) {
    return await provider.validateTokens(accessToken, refreshToken, validateFn);
}
export async function refreshAccessToken(accessToken, refreshToken, validateFn) {
    try {
        // First validate both tokens
        const isValid = await provider.validateTokens(accessToken, refreshToken, validateFn);
        if (!isValid) {
            return null;
        }
        // Extract payload from refresh token (not from validation result)
        const refreshPayload = await provider.verifyRefresh(refreshToken);
        if (!refreshPayload) {
            return null;
        }
        // Generate new tokens using the refresh token payload
        return await provider.signInWithRefreshAndExpiry(refreshPayload);
    }
    catch (error) {
        return null;
    }
}
//# sourceMappingURL=jwt-auth.js.map