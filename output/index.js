import { provider, apiKeyProvider, sessionProvider } from "./jwt-auth.js";
export * from "./jwt-auth.js";
const defaultConfig = {
    secretKey: 'secret-key-for-jwt',
    expirationTime: 60 * 60 * 24 * 7, // 7 days
    refreshSecretKey: 'refresh-secret-key-for-jwt',
    refreshExpirationTime: 60 * 60 * 24 * 30, // 30 days
    authMode: 'jwt-only',
    session: {
        store: 'memory',
        secret: 'session-secret-key',
        cookieName: 'sessionId',
        cookieOptions: {
            secure: false, // Set to true in production with HTTPS
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days in milliseconds
            path: '/'
        }
    }
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
        const refreshSecretKeyFromConfig = appConfig.get('JWT_REFRESH_SECRET_KEY', config.refreshSecretKey || defaultConfig.refreshSecretKey);
        const refreshExpirationTime = appConfig.get('JWT_REFRESH_EXPIRATION_TIME', config.refreshExpirationTime || defaultConfig.refreshExpirationTime);
        // Session configuration
        const sessionSecret = appConfig.get('SESSION_SECRET', config.session?.secret || defaultConfig.session?.secret);
        const authMode = appConfig.get('AUTH_MODE', config.authMode || defaultConfig.authMode);
        this.config.secretKey = secretKeyFromConfig;
        this.config.expirationTime = expirationTime;
        this.config.refreshSecretKey = refreshSecretKeyFromConfig;
        this.config.refreshExpirationTime = refreshExpirationTime;
        this.config.authMode = authMode;
        // Merge session config with defaults
        this.config.session = {
            ...defaultConfig.session,
            ...config.session,
            secret: sessionSecret
        };
        provider.init(this.config);
        apiKeyProvider.init(this.config);
        sessionProvider.init(this.config);
    }
    async beforeStart(ctx) {
        // Initialize session support if enabled and properly configured
        if (this.config.session && this.config.session.secret) {
            await this.setupSessions(ctx);
        }
    }
    async setupSessions(ctx) {
        const { session } = this.config;
        try {
            // Check if required dependencies are available
            let cookiePlugin, sessionPlugin;
            try {
                cookiePlugin = await import('@fastify/cookie');
                sessionPlugin = await import('@fastify/session');
            }
            catch (error) {
                throw new Error('Session dependencies not found. Please install @fastify/cookie and @fastify/session:\n' +
                    'npm install @fastify/cookie @fastify/session');
            }
            // Register @fastify/cookie
            await ctx.fastify.register(cookiePlugin.default, {
                secret: session.secret
            });
            // Register @fastify/session
            await ctx.fastify.register(sessionPlugin.default, {
                secret: session.secret,
                cookieName: session.cookieName,
                cookie: session.cookieOptions
            });
            console.log('✅ Session support initialized successfully');
        }
        catch (error) {
            console.error('❌ Failed to initialize session support:', error.message);
            throw error;
        }
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
export function useSessionProvider() {
    if (!sessionProvider.config) {
        throw new Error('SessionProvider is not initialized. Please initialize the provider first.');
    }
    return sessionProvider;
}
//# sourceMappingURL=index.js.map