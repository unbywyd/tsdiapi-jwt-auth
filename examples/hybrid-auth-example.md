import { FastifyInstance } from 'fastify';
import { createPlugin, JWTGuard, SessionGuard, HybridAuthGuard, useUser, createUserSession, destroyUserSession } from '@tsdiapi/jwt-auth';

// Example user type
interface User {
    id: string;
    email: string;
    role: 'admin' | 'user';
}

// Initialize the plugin with hybrid authentication
const authPlugin = createPlugin({
    authMode: 'hybrid', // Enable hybrid authentication
    session: {
        store: 'memory',
        secret: 'your-session-secret',
        cookieName: 'sessionId',
        cookieOptions: {
            secure: false, // Set to true in production
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7 * 1000, // 7 days
            path: '/'
        }
    },
    guards: {
        admin: (user: User) => user.role === 'admin',
        user: (user: User) => user.role === 'user' || user.role === 'admin'
    }
});

// Example route handlers
export async function setupAuthRoutes(fastify: FastifyInstance) {
    // Register the auth plugin
    await fastify.register(authPlugin);

    // Register session support
    await fastify.register(require('@fastify/cookie'));
    await fastify.register(require('@fastify/session'), {
        secret: 'your-session-secret',
        cookie: {
            secure: false,
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7 * 1000
        }
    });

    // Login endpoint - creates both JWT and session
    fastify.post('/login', async (request, reply) => {
        const { email, password } = request.body as { email: string; password: string };
        
        // Your authentication logic here
        const user: User = {
            id: '1',
            email,
            role: 'user'
        };

        // Create JWT token
        const jwtProvider = authPlugin.useJWTAuthProvider();
        const token = await jwtProvider.signIn(user);

        // Create session
        await createUserSession(request, reply, user);

        return {
            token,
            user,
            message: 'Login successful'
        };
    });

    // Logout endpoint
    fastify.post('/logout', async (request, reply) => {
        await destroyUserSession(request, reply);
        return { message: 'Logout successful' };
    });

    // JWT-only protected route
    fastify.get('/jwt-only', {
        preHandler: JWTGuard()
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { message: 'JWT-only route', user };
    });

    // Session-only protected route
    fastify.get('/session-only', {
        preHandler: SessionGuard()
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { message: 'Session-only route', user };
    });

    // Hybrid protected route (accepts both JWT and session)
    fastify.get('/hybrid', {
        preHandler: HybridAuthGuard()
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { message: 'Hybrid route', user };
    });

    // Admin-only route with hybrid auth
    fastify.get('/admin', {
        preHandler: HybridAuthGuard({
            guardName: 'admin'
        })
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { message: 'Admin route', user };
    });

    // Route that requires both JWT and session
    fastify.get('/secure', {
        preHandler: HybridAuthGuard({
            mode: 'require-both'
        })
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { message: 'Secure route (both JWT and session required)', user };
    });

    // Optional authentication route
    fastify.get('/optional', {
        preHandler: HybridAuthGuard({
            optional: true
        })
    }, async (request, reply) => {
        const user = await useUser<User>(request);
        return { 
            message: 'Optional auth route', 
            user,
            authenticated: !!user
        };
    });
}
