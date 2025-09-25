# Hybrid Authentication Example

This example demonstrates the new hybrid authentication capabilities of `@tsdiapi/jwt-auth`.

## Features

- **JWT-only authentication**: Traditional Bearer token authentication
- **Session-only authentication**: HTTP session-based authentication
- **Hybrid authentication**: Accepts both JWT and session authentication
- **Require both**: Requires both JWT and session authentication
- **Optional authentication**: Routes that work with or without authentication

## Setup

1. Install dependencies:
```bash
npm install @tsdiapi/jwt-auth @fastify/session @fastify/cookie
```

2. Register the plugin with your Fastify instance:
```typescript
import { createPlugin } from '@tsdiapi/jwt-auth';

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
    }
});
```

3. Register session support:
```typescript
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
```

## Authentication Modes

### JWT-only Mode
```typescript
fastify.get('/jwt-only', {
    preHandler: JWTGuard()
}, handler);
```

### Session-only Mode
```typescript
fastify.get('/session-only', {
    preHandler: SessionGuard()
}, handler);
```

### Hybrid Mode (Default)
```typescript
fastify.get('/hybrid', {
    preHandler: HybridAuthGuard()
}, handler);
```

### Require Both Mode
```typescript
fastify.get('/secure', {
    preHandler: HybridAuthGuard({
        mode: 'require-both'
    })
}, handler);
```

### Optional Authentication
```typescript
fastify.get('/optional', {
    preHandler: HybridAuthGuard({
        optional: true
    })
}, handler);
```

## Utility Functions

### Get User Data
```typescript
import { useUser } from '@tsdiapi/jwt-auth';

const user = await useUser<User>(request);
```

### Create User Session
```typescript
import { createUserSession } from '@tsdiapi/jwt-auth';

await createUserSession(request, reply, userData);
```

### Destroy User Session
```typescript
import { destroyUserSession } from '@tsdiapi/jwt-auth';

await destroyUserSession(request, reply);
```

### Check Session Validity
```typescript
import { isSessionValid } from '@tsdiapi/jwt-auth';

const isValid = await isSessionValid(request);
```

## Configuration Options

```typescript
const authPlugin = createPlugin({
    // Authentication mode
    authMode: 'hybrid', // 'jwt-only' | 'session-only' | 'hybrid' | 'require-both'
    
    // Session configuration
    session: {
        store: 'memory', // 'memory' | 'redis' | 'mongodb' | 'custom'
        secret: 'your-session-secret',
        cookieName: 'sessionId',
        cookieOptions: {
            secure: false,
            httpOnly: true,
            sameSite: 'lax',
            maxAge: 60 * 60 * 24 * 7 * 1000,
            path: '/',
            domain: undefined
        },
        customStore: undefined // For custom session stores
    },
    
    // Fallback mode for hybrid authentication
    fallbackMode: 'jwt-to-session', // 'jwt-to-session' | 'session-to-jwt'
    
    // Guards for role-based access control
    guards: {
        admin: (user) => user.role === 'admin',
        user: (user) => user.role === 'user' || user.role === 'admin'
    }
});
```

## Environment Variables

You can configure the plugin using environment variables:

```bash
# JWT Configuration
JWT_SECRET_KEY=your-jwt-secret
JWT_EXPIRATION_TIME=604800  # 7 days in seconds
JWT_REFRESH_SECRET_KEY=your-refresh-secret
JWT_REFRESH_EXPIRATION_TIME=2592000  # 30 days in seconds

# Session Configuration
SESSION_SECRET=your-session-secret

# Authentication Mode
AUTH_MODE=hybrid
```

## Usage Examples

### Login with Both JWT and Session
```typescript
fastify.post('/login', async (request, reply) => {
    const { email, password } = request.body;
    
    // Authenticate user
    const user = await authenticateUser(email, password);
    
    // Create JWT token
    const jwtProvider = authPlugin.useJWTAuthProvider();
    const token = await jwtProvider.signIn(user);
    
    // Create session
    await createUserSession(request, reply, user);
    
    return { token, user };
});
```

### Protected Route with Role-based Access
```typescript
fastify.get('/admin/users', {
    preHandler: HybridAuthGuard({
        guardName: 'admin'
    })
}, async (request, reply) => {
    const user = await useUser<User>(request);
    // Handle admin-only logic
    return { users: await getUsers() };
});
```

This hybrid authentication system provides maximum flexibility for different authentication scenarios while maintaining security and ease of use.
