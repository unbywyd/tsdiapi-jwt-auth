import { jwtVerify, SignJWT } from 'jose';
import { Type } from '@sinclair/typebox';
import { randomUUID } from 'crypto';
export class JWTAuthProvider {
    config;
    init(config) {
        this.config = config;
    }
    signIn(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        const jti = randomUUID();
        return new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(jti)
            .sign(new TextEncoder().encode(this.config.secretKey));
    }
    async signInWithExpiry(payload) {
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + this.config.expirationTime;
        const jti = randomUUID();
        const token = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(exp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(jti)
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
        // Generate unique JTI (JWT ID) to ensure token uniqueness
        const accessJti = randomUUID();
        const refreshJti = randomUUID();
        const accessToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(accessJti)
            .sign(new TextEncoder().encode(this.config.secretKey));
        const refreshToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(refreshJti)
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
        // Generate unique JTI (JWT ID) to ensure token uniqueness
        const accessJti = randomUUID();
        const refreshJti = randomUUID();
        const accessToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(accessExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(accessJti)
            .sign(new TextEncoder().encode(this.config.secretKey));
        const refreshToken = await new SignJWT({ ...payload })
            .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
            .setExpirationTime(refreshExp)
            .setIssuedAt(iat)
            .setNotBefore(iat)
            .setJti(refreshJti)
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
    async logout(req, reply) {
        // For JWT logout, we can't "delete" the token from the server
        // but we can clear the session if it exists
        if (req.session) {
            await destroySessionAsync(req.session);
        }
        // Clear req.user as well
        req.user = undefined;
        // In a real application, you could add token blacklist logic here
        // or other token invalidation mechanisms
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
// Session Provider
export class SessionProvider {
    config = null;
    init(config) {
        this.config = config;
    }
    async createUserSession(req, reply, userData) {
        if (!req.session) {
            throw new Error('Session is not available. Make sure @fastify/session is registered.');
        }
        req.session.user = userData;
        req.session.isAuthenticated = true;
        req.session.createdAt = new Date().toISOString();
        // Regenerate session ID for security
        await req.session.regenerate();
    }
    async destroyUserSession(req, reply) {
        if (!req.session) {
            return;
        }
        await destroySessionAsync(req.session);
    }
    async getUserFromSession(req) {
        if (!req.session || !req.session.isAuthenticated || !req.session.user) {
            return null;
        }
        return req.session.user;
    }
    async isSessionValid(req) {
        return !!(req.session && req.session.isAuthenticated && req.session.user);
    }
    // Гибридный метод: создает и JWT токены, и сессию
    async createHybridAuth(req, reply, userData) {
        // Создаем JWT токены
        const tokens = await provider.signInWithRefreshAndExpiry(userData);
        // Создаем сессию
        await this.createUserSession(req, reply, userData);
        return {
            tokens,
            session: true
        };
    }
}
const sessionProvider = new SessionProvider();
// Helper function to destroy session asynchronously
function destroySessionAsync(session) {
    return new Promise((resolve, reject) => {
        if (session.destroy) {
            session.destroy((err) => {
                if (err) {
                    reject(err);
                }
                else {
                    resolve();
                }
            });
        }
        else {
            resolve();
        }
    });
}
export { provider, apiKeyProvider, sessionProvider };
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
            // Store JWT session data
            if (req.session) {
                req.session.jwt = session;
                req.session.isAuthenticated = true;
            }
            else {
                req.user = session;
            }
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
    // Try to get user from session first
    if (req.session?.user) {
        return req.session.user;
    }
    // Try to get JWT data from session
    if (req.session?.jwt) {
        return req.session.jwt;
    }
    // Fallback to req.user
    return req.user;
}
// Session Guard
export function SessionGuard(options) {
    return async (req, reply) => {
        try {
            if (!req.session) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Session support not initialized. Please install @fastify/session and @fastify/cookie' }
                };
            }
            const isSessionValid = await sessionProvider.isSessionValid(req);
            if (!isSessionValid) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'Invalid session' }
                };
            }
            const userData = await sessionProvider.getUserFromSession(req);
            if (!userData) {
                if (options?.optional) {
                    return true;
                }
                return {
                    status: 403,
                    data: { error: 'User not found in session' }
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
                const result = await validateSession(userData);
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
            // Store user data in session properly
            if (req.session) {
                req.session.user = userData;
                req.session.isAuthenticated = true;
            }
            else {
                // Fallback: store in req.user if session is not available
                req.user = userData;
            }
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
            // Store JWT session data
            if (req.session) {
                req.session.jwt = session;
                req.session.isAuthenticated = true;
            }
            else {
                req.user = session;
            }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        }
        else {
            req.user = session;
        }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        }
        else {
            req.user = session;
        }
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
        // Store session data
        if (req.session) {
            req.session.jwt = session;
            req.session.isAuthenticated = true;
        }
        else {
            req.user = session;
        }
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
// Universal user functions
export async function useUser(req) {
    // First try to get user from session (JWT or session data)
    const sessionUser = useSession(req);
    if (sessionUser) {
        return sessionUser;
    }
    // Then try to get user from JWT token
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader.split(/\s+/)[1];
        const jwtUser = await provider.verify(token);
        if (jwtUser) {
            return jwtUser;
        }
    }
    // Finally try to get user from session provider
    const sessionProviderUser = await sessionProvider.getUserFromSession(req);
    if (sessionProviderUser) {
        return sessionProviderUser;
    }
    return null;
}
export async function createUserSession(req, reply, userData) {
    return await sessionProvider.createUserSession(req, reply, userData);
}
export async function destroyUserSession(req, reply) {
    return await sessionProvider.destroyUserSession(req, reply);
}
export async function isSessionValid(req) {
    return await sessionProvider.isSessionValid(req);
}
// Гибридная авторизация: создает и JWT токены, и сессию
export async function createHybridAuth(req, reply, userData) {
    return await sessionProvider.createHybridAuth(req, reply, userData);
}
// JWT logout function
export async function logout(req, reply) {
    return await provider.logout(req, reply);
}
export function HybridAuthGuard(options) {
    return async (req, reply) => {
        try {
            const mode = options?.mode || provider.config?.authMode || 'jwt-only';
            const fallbackMode = options?.fallbackMode || provider.config?.fallbackMode || 'jwt-to-session';
            let jwtUser = null;
            let sessionUser = null;
            let jwtValid = false;
            let sessionValid = false;
            // Try JWT authentication
            if (mode === 'jwt-only' || mode === 'hybrid' || mode === 'require-both') {
                const authHeader = req.headers.authorization;
                if (authHeader) {
                    const token = authHeader.split(/\s+/)[1];
                    jwtUser = await provider.verify(token);
                    jwtValid = !!jwtUser;
                }
            }
            // Try session authentication
            if (mode === 'session-only' || mode === 'hybrid' || mode === 'require-both') {
                sessionValid = await sessionProvider.isSessionValid(req);
                if (sessionValid) {
                    sessionUser = await sessionProvider.getUserFromSession(req);
                }
            }
            // Apply authentication mode logic
            switch (mode) {
                case 'jwt-only':
                    if (!jwtValid) {
                        if (options?.optional)
                            return true;
                        return {
                            status: 403,
                            data: { error: 'JWT authentication required' }
                        };
                    }
                    // Store JWT user data
                    if (req.session) {
                        req.session.jwt = jwtUser;
                        req.session.isAuthenticated = true;
                    }
                    else {
                        req.user = jwtUser;
                    }
                    break;
                case 'session-only':
                    if (!sessionValid) {
                        if (options?.optional)
                            return true;
                        return {
                            status: 403,
                            data: { error: 'Session authentication required' }
                        };
                    }
                    // Store session user data
                    if (req.session) {
                        req.session.user = sessionUser;
                        req.session.isAuthenticated = true;
                    }
                    else {
                        req.user = sessionUser;
                    }
                    break;
                case 'hybrid':
                    if (jwtValid) {
                        // Store JWT user data
                        if (req.session) {
                            req.session.jwt = jwtUser;
                            req.session.isAuthenticated = true;
                        }
                        else {
                            req.user = jwtUser;
                        }
                    }
                    else if (sessionValid) {
                        // Store session user data
                        if (req.session) {
                            req.session.user = sessionUser;
                            req.session.isAuthenticated = true;
                        }
                        else {
                            req.user = sessionUser;
                        }
                    }
                    else {
                        if (options?.optional)
                            return true;
                        return {
                            status: 403,
                            data: { error: 'Authentication required (JWT or session)' }
                        };
                    }
                    break;
                case 'require-both':
                    if (!jwtValid || !sessionValid) {
                        if (options?.optional)
                            return true;
                        return {
                            status: 403,
                            data: { error: 'Both JWT and session authentication required' }
                        };
                    }
                    // Use JWT user as primary, session as secondary validation
                    // Store JWT user data
                    if (req.session) {
                        req.session.jwt = jwtUser;
                        req.session.isAuthenticated = true;
                    }
                    else {
                        req.user = jwtUser;
                    }
                    break;
                default:
                    if (options?.optional)
                        return true;
                    return {
                        status: 403,
                        data: { error: 'Invalid authentication mode' }
                    };
            }
            // Apply validation if specified
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
                const result = await validateSession(req.session);
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
//# sourceMappingURL=jwt-auth.js.map