# @tsdiapi/jwt-auth

[![npm version](https://badge.fury.io/js/%40tsdiapi%2Fjwt-auth.svg)](https://badge.fury.io/js/%40tsdiapi%2Fjwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TSDIAPI-JWT-Auth** is a plugin for the `TSDIAPI-Server` framework that simplifies JWT-based authentication and authorization. It includes utilities for token creation, session validation, and custom guards to secure API endpoints effectively.

## Features

- **Token Management**: Generate and verify JWT tokens with customizable payloads and expiration times.
- **Session Protection**: Use built-in or custom session validation logic for secure API access.
- **Custom Guards**: Easily register and reference multiple guards to support various security requirements.
- **Environment Integration**: Supports configuration through `.env` files to streamline deployment.
- **Optional Guards**: Load session without blocking requests when authentication fails.

## Installation

```bash
npm install @tsdiapi/jwt-auth
```

Or use the CLI to add the plugin:

```bash
tsdiapi plugins add jwt-auth
```

## Usage

### Register the Plugin

Import and register the plugin in your TSDIAPI application:

```typescript
import createPlugin from "@tsdiapi/jwt-auth";
import { createApp } from "@tsdiapi/server";

createApp({
  plugins: [
    createPlugin({
      secretKey: "your-secret-key", // Use JWT_SECRET_KEY in .env as an alternative
      expirationTime: 60 * 60 * 24 * 7, // Token valid for 7 days, override with JWT_EXPIRATION_TIME in .env
      refreshSecretKey: "your-refresh-secret-key", // Use JWT_REFRESH_SECRET_KEY in .env as an alternative
      refreshExpirationTime: 60 * 60 * 24 * 30, // Refresh token valid for 30 days, override with JWT_REFRESH_EXPIRATION_TIME in .env
      guards: {
        admin: (session) => session.role === 'admin',
        user: (session) => session.role === 'user'
      },
      apiKeys: {
        'api-key-1': true,
        'api-key-2': {
          description: 'Admin API key',
          validate: () => true
        }
      },

    }),
  ],
});
```

### Environment Configuration

Define environment variables in your `.env` file to avoid hardcoding sensitive data:

```env
JWT_SECRET_KEY=your-secret-key
JWT_EXPIRATION_TIME=604800
JWT_REFRESH_SECRET_KEY=your-refresh-secret-key
JWT_REFRESH_EXPIRATION_TIME=2592000
```

## Protecting Endpoints

**Important Rules for Route Definition:**
1. Every route using guards **MUST** define a 403 response code with the following schema:
   ```typescript
   .code(403, Type.Object({
       error: Type.String(),
   }))
   ```
2. Response codes (`code()`) must be defined immediately after the HTTP method (get, post, etc.)
3. Authentication (`auth()`) and guards (`guard()`) should be defined after response codes
4. The handler should be defined last

### Required Guards

These guards will block requests if authentication fails:

#### Applying the `JWTGuard`

Secure API endpoints using `JWTGuard`. You can use it in two ways:

1. For standard bearer token validation:
```typescript
useRoute()
  .get('/protected/endpoint')
  .code(200, Type.Object({
      message: Type.String(),
  }))
  .code(403, Type.Object({
      error: Type.String(),
  }))
  .auth('bearer')
  .guard(JWTGuard())
  .handler(async (req) => {
    return {
      status: 200,
      data: { message: 'Access granted' }
    }
  })
  .build();
```

2. For custom guard validation:
```typescript
useRoute()
  .get('/admin/dashboard')
  .code(200, Type.Object({
      message: Type.String(),
  }))
  .code(403, Type.Object({
      error: Type.String(),
  }))
  .auth('bearer')
  .guard(JWTGuard({ guardName: 'adminOnly' }))
  .handler(async (req) => {
    return {
      status: 200,
      data: { message: 'Welcome to admin dashboard' }
    }
  })
  .build();
```

#### Applying the `APIKeyGuard`

```typescript
useRoute()
  .get('/api/protected')
  .code(200, Type.Object({
      message: Type.String(),
  }))
  .code(403, Type.Object({
      error: Type.String(),
  }))
  .guard(APIKeyGuard())
  .handler(async (req) => {
    return {
      status: 200,
      data: { message: 'API access granted' }
    }
  })
  .build();
```

### Optional Guards

These guards load session if authentication is valid, but don't block requests if it fails. Use the `optional: true` option:

#### Applying the `JWTGuard` in Optional Mode

```typescript
useRoute()
  .get('/optional-auth')
  .code(200, Type.Object({
      message: Type.String(),
      isAuthenticated: Type.Optional(Type.Boolean()),
      user: Type.Optional(Type.Object({
          userId: Type.String(),
          role: Type.String()
      }))
  }))
  .guard(JWTGuard({ optional: true }))
  .handler(async (req) => {
    const session = useSession(req);
    if (session) {
      return {
        status: 200,
        data: { 
          message: 'Authenticated user', 
          user: session,
          isAuthenticated: true 
        }
      };
    } else {
      return {
        status: 200,
        data: { 
          message: 'Guest user',
          isAuthenticated: false 
        }
      };
    }
  })
  .build();
```

#### Applying the `APIKeyGuard` in Optional Mode

```typescript
useRoute()
  .get('/api/optional')
  .code(200, Type.Object({
      message: Type.String(),
      isApiAuthenticated: Type.Optional(Type.Boolean()),
      key: Type.Optional(Type.Any())
  }))
  .guard(APIKeyGuard({ optional: true }))
  .handler(async (req) => {
    const session = useSession(req);
    if (session) {
      return {
        status: 200,
        data: { 
          message: 'Authenticated API call', 
          key: session,
          isApiAuthenticated: true 
        }
      };
    } else {
      return {
        status: 200,
        data: { 
          message: 'Unauthenticated API call',
          isApiAuthenticated: false 
        }
      };
    }
  })
  .build();
```

#### Optional Guard with Custom Validation

```typescript
useRoute()
  .get('/premium-content')
  .code(200, Type.Object({
      message: Type.String(),
      accessLevel: Type.String()
  }))
  .guard(JWTGuard({ 
    optional: true,
    validateSession: (session) => session.subscription === 'premium',
    guardDescription: 'Optional premium validation'
  }))
  .handler(async (req) => {
    const session = useSession(req);
    if (session && session.subscription === 'premium') {
      return {
        status: 200,
        data: { 
          message: 'Premium content', 
          accessLevel: 'premium' 
        }
      };
    } else if (session) {
      return {
        status: 200,
        data: { 
          message: 'Basic content', 
          accessLevel: 'basic' 
        }
      };
    } else {
      return {
        status: 200,
        data: { 
          message: 'Guest content',
          accessLevel: 'guest' 
        }
      };
    }
  })
  .build();
```

### Registering Custom Guards

You can register custom guards during plugin initialization. These guards can later be referenced by name:

```typescript
createApp({
  plugins: [
    createPlugin({
      secretKey: "your-secret-key",
      guards: {
        adminOnly: async (session) => {
          if (session.role !== "admin") {
            return "Only administrators are allowed!";
          }
          return true;
        },
      },
    }),
  ],
});
```

To use the custom guard in your routes:

```typescript
import { JWTGuard } from "@tsdiapi/jwt-auth";

useRoute()
  .get('/admin/dashboard')
  .code(200, Type.Object({
      message: Type.String(),
  }))
  .code(403, Type.Object({
      error: Type.String(),
  }))
  .auth('bearer')
  .guard(JWTGuard({ guardName: 'adminOnly' }))
  .handler(async (req) => {
    return {
      status: 200,
      data: { message: 'Welcome to admin dashboard' }
    }
  })
  .build();
```

**Important Notes:**
1. The `guardName` in `JWTGuard` must match exactly with one of the guards registered in the plugin initialization
2. Your route must support 403 status code to handle unauthorized access cases
3. The guard will return the error message defined in the guard function when validation fails

### Accessing User Session Data

After successful authentication, you can access the user's session data through `req.session`. The session contains the decoded JWT payload:

```typescript
import { JWTGuard, useSession } from "@tsdiapi/jwt-auth";

useRoute()
  .get('/user/profile')
  .code(200, Type.Object({
      userId: Type.String(),
      role: Type.String(),
  }))
  .code(403, Type.Object({
      error: Type.String(),
  }))
  .auth('bearer')
  .guard(JWTGuard())
  .handler(async (req) => {
    // Type-safe session access
    const session = useSession<{
      userId: string;
      role: string;
    }>(req);
    
    return {
      status: 200,
      data: { userId: session.userId, role: session.role }
    }
  })
  .build();
```

For better type safety, you can define your session type once and reuse it:

```typescript
type UserSession = {
  userId: string;
  role: string;
  permissions: string[];
};

// In your route handler
const session = useSession<UserSession>(req);
```

The session object contains all the data that was included in the JWT token when it was created. For example, if you signed in with:
```typescript
const token = await authProvider.signIn({
  userId: "123",
  role: "admin",
  permissions: ["read", "write"]
});
```

Then in your route handler, you can access all these fields with type safety:
```typescript
const session = useSession<UserSession>(req);
const { userId, role, permissions } = session;
```

---

## Using the JWT Auth Provider

The `JWTAuthProvider` is the core service for handling JWT-based authentication in your TSDIAPI application. It provides methods for signing in users, verifying tokens, and managing guards for session validation.

### Importing the Provider

To access the provider, import the `useJWTAuthProvider` function:

```typescript
import { useJWTAuthProvider } from "@tsdiapi/jwt-auth";
```

Make sure the plugin is registered before calling this function, otherwise, an error will be thrown.

---

### `signIn(payload: Record<string, any>): Promise<string>`

Generates a JWT token for the given user payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const token = await authProvider.signIn({
  userId: "123",
  role: "admin",
});
console.log("Generated Token:", token);
```

### `signInWithExpiry(payload: Record<string, any>): Promise<TokenWithExpiry>`

Generates a JWT token with expiration date for the given user payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const result = await authProvider.signInWithExpiry({
  userId: "123",
  role: "admin",
});
console.log("Generated Token:", result.token);
console.log("Expires At:", result.expiresAt);
```

### `signInWithRefresh(payload: Record<string, any>): Promise<TokenPair>`

Generates both access and refresh tokens for the given user payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const tokens = await authProvider.signInWithRefresh({
  userId: "123",
  role: "admin",
});
console.log("Access Token:", tokens.accessToken);
console.log("Refresh Token:", tokens.refreshToken);
```

### `signInWithRefreshAndExpiry(payload: Record<string, any>): Promise<TokenPairWithExpiry>`

Generates both access and refresh tokens with expiration dates for the given user payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const tokens = await authProvider.signInWithRefreshAndExpiry({
  userId: "123",
  role: "admin",
});
console.log("Access Token:", tokens.accessToken);
console.log("Access Token Expires At:", tokens.accessTokenExpiresAt);
console.log("Refresh Token:", tokens.refreshToken);
console.log("Refresh Token Expires At:", tokens.refreshTokenExpiresAt);
```

### `verify<T>(token: string): Promise<T | null>`

Verifies a JWT token and returns the decoded session payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const session = await authProvider.verify<{ userId: string; role: string }>(token);
if (session) {
  console.log("Authenticated User:", session.userId);
} else {
  console.log("Invalid token");
}
```

### `verifyRefresh<T>(token: string): Promise<T | null>`

Verifies a refresh token and returns the decoded session payload.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

const session = await authProvider.verifyRefresh<{ userId: string; role: string }>(refreshToken);
if (session) {
  console.log("Valid Refresh Token for User:", session.userId);
} else {
  console.log("Invalid refresh token");
}
```

### `validateTokens<T>(accessToken: string, refreshToken: string, validateFn?: (accessPayload: any, refreshPayload: any) => boolean | Promise<boolean>): Promise<boolean>`

Validates if both access and refresh tokens are valid and belong to the same user. Optionally accepts a custom validation function.

#### Example:
```typescript
const authProvider = useJWTAuthProvider();

// Basic validation (compares payloads)
const isValid = await authProvider.validateTokens(accessToken, refreshToken);
if (isValid) {
  console.log("Both tokens are valid and belong to the same user");
} else {
  console.log("Tokens are invalid or don't match");
}

// Custom validation
const isValidCustom = await authProvider.validateTokens(
  accessToken, 
  refreshToken,
  (accessPayload, refreshPayload) => {
    return accessPayload.userId === refreshPayload.userId && 
           accessPayload.status === 'active';
  }
);
```

---

## Configuration

### Environment Variables

- `JWT_SECRET_KEY` - Secret key for JWT signing (default: 'secret-key-for-jwt')
- `JWT_EXPIRATION_TIME` - Token expiration time in seconds (default: 604800 - 7 days)
- `JWT_REFRESH_SECRET_KEY` - Secret key for JWT refresh token signing (default: 'refresh-secret-key-for-jwt')
- `JWT_REFRESH_EXPIRATION_TIME` - Refresh token expiration time in seconds (default: 2592000 - 30 days)

### Plugin Options

| Option                | Type                                      | Description                                    |
| --------------------- | ----------------------------------------- | ---------------------------------------------- |
| `secretKey`           | `string`                                  | Secret key for signing JWT tokens.             |
| `expirationTime`      | `number`                                  | Token expiration time in seconds.              |
| `refreshSecretKey`    | `string`                                  | Secret key for signing refresh tokens.         |
| `refreshExpirationTime` | `number`                               | Refresh token expiration time in seconds.      |
| `guards`              | `Record<string, ValidateSessionFunction>` | Custom guards for validating sessions.         |
| `apiKeys`             | `Record<string, APIKeyEntry \| 'JWT' \| true>` | API keys configuration.                        |


---

## API Reference

### Guards

- `JWTGuard(options?)` - JWT authentication (use `optional: true` for optional mode)
- `APIKeyGuard(options?)` - API key authentication (use `optional: true` for optional mode)

### Helper Functions

- `useSession<T>(req)` - Get current session
- `useJWTAuthProvider()` - Get JWT provider instance
- `useApiKeyProvider()` - Get API key provider instance
- `isBearerValid<T>(req)` - Check if Bearer token is valid
- `isApiKeyValid(req)` - Check if API key is valid
- `isRefreshTokenValid<T>(req)` - Check if refresh token is valid
- `validateTokenPair<T>(accessToken, refreshToken, validateFn?)` - Validate if both tokens are valid and belong to the same user
- `refreshAccessToken<T>(accessToken, refreshToken, validateFn?)` - Generate new access and refresh tokens with expiry dates from refresh token with validation

### Types

- `ValidateSessionFunction<T>` - Session validation function type
- `JWTGuardOptions<TGuards>` - Guard configuration options
- `PluginOptions<TGuards>` - Plugin configuration options
- `TokenPair` - Object containing access and refresh tokens
- `TokenWithExpiry` - Object containing token and expiration date
- `TokenPairWithExpiry` - Object containing access and refresh tokens with expiration dates

---

## Refresh Token Usage Examples

### Basic Refresh Token Flow

```typescript
import { useJWTAuthProvider, validateTokenPair, refreshAccessToken } from "@tsdiapi/jwt-auth";

// 1. Sign in with refresh token and expiry dates
const authProvider = useJWTAuthProvider();
const tokens = await authProvider.signInWithRefreshAndExpiry({
  userId: "123",
  role: "user",
  email: "user@example.com"
});

console.log("Access Token:", tokens.accessToken);
console.log("Access Token Expires At:", tokens.accessTokenExpiresAt);
console.log("Refresh Token:", tokens.refreshToken);
console.log("Refresh Token Expires At:", tokens.refreshTokenExpiresAt);

// 2. Validate token pair
const isValid = await validateTokenPair(tokens.accessToken, tokens.refreshToken);
if (isValid) {
  console.log("Tokens are valid and belong to the same user");
}

// 3. Validate with custom logic
const isValidCustom = await validateTokenPair(
  tokens.accessToken, 
  tokens.refreshToken,
  (accessPayload, refreshPayload) => {
    return accessPayload.userId === refreshPayload.userId && 
           accessPayload.role === refreshPayload.role;
  }
);

// 4. Refresh tokens when they expire
const newTokens = await refreshAccessToken(tokens.accessToken, tokens.refreshToken);
if (newTokens) {
  console.log("New access token:", newTokens.accessToken);
  console.log("New access token expires at:", newTokens.accessTokenExpiresAt);
  console.log("New refresh token:", newTokens.refreshToken);
  console.log("New refresh token expires at:", newTokens.refreshTokenExpiresAt);
}

// 5. Refresh with custom validation
const newTokensCustom = await refreshAccessToken(
  tokens.accessToken, 
  tokens.refreshToken,
  (accessPayload, refreshPayload) => {
    return accessPayload.userId === refreshPayload.userId && 
           accessPayload.status === 'active';
  }
);
```

### Custom Token Validation

```typescript
import { validateTokenPair } from "@tsdiapi/jwt-auth";

// Custom validation function
const customValidation = (accessPayload, refreshPayload) => {
  // Custom validation logic
  if (accessPayload.userId !== refreshPayload.userId) {
    return false;
  }
  
  // Check if user is still active
  if (accessPayload.status === 'inactive') {
    return false;
  }
  
  // Check if tokens were issued for the same session
  if (accessPayload.sessionId !== refreshPayload.sessionId) {
    return false;
  }
  
  return true;
};

// Use in your application
const isValid = await validateTokenPair(accessToken, refreshToken, customValidation);
```

### Refresh Token Endpoint Example

```typescript
import { useRoute } from "@tsdiapi/server";
import { Type } from "@sinclair/typebox";
import { refreshAccessToken, isRefreshTokenValid } from "@tsdiapi/jwt-auth";

useRoute()
  .post('/auth/refresh')
  .code(200, Type.Object({
    accessToken: Type.String(),
    refreshToken: Type.String(),
    accessTokenExpiresAt: Type.String(),
    refreshTokenExpiresAt: Type.String(),
  }))
  .code(403, Type.Object({
    error: Type.String(),
  }))
  .handler(async (req) => {
    const accessToken = req.headers.authorization?.split(/\s+/)[1] as string;
    const refreshToken = req.headers['x-refresh-token'] as string;
    
    if (!accessToken || !refreshToken) {
      return {
        status: 403,
        data: { error: 'Both access and refresh tokens are required' }
      };
    }
    
    // Custom validation function
    const customValidation = (accessPayload, refreshPayload) => {
      return accessPayload.userId === refreshPayload.userId && 
             accessPayload.status === 'active';
    };
    
    const newTokens = await refreshAccessToken(accessToken, refreshToken, customValidation);
    
    if (!newTokens) {
      return {
        status: 403,
        data: { error: 'Invalid tokens or validation failed' }
      };
    }
    
    return {
      status: 200,
      data: { 
        accessToken: newTokens.accessToken,
        refreshToken: newTokens.refreshToken,
        accessTokenExpiresAt: newTokens.accessTokenExpiresAt.toISOString(),
        refreshTokenExpiresAt: newTokens.refreshTokenExpiresAt.toISOString()
      }
    };
  })
  .build();
```

### Token Pair Validation Endpoint

```typescript
import { useRoute } from "@tsdiapi/server";
import { Type } from "@sinclair/typebox";
import { validateTokenPair } from "@tsdiapi/jwt-auth";

useRoute()
  .post('/auth/validate-tokens')
  .code(200, Type.Object({
    isValid: Type.Boolean(),
  }))
  .code(400, Type.Object({
    error: Type.String(),
  }))
  .handler(async (req) => {
    const { accessToken, refreshToken } = req.body;
    
    if (!accessToken || !refreshToken) {
      return {
        status: 400,
        data: { error: 'Both access and refresh tokens are required' }
      };
    }
    
    const isValid = await validateTokenPair(accessToken, refreshToken);
    
    return {
      status: 200,
      data: { isValid }
    };
  })
  .build();
```

---

## License

This plugin is open-source and available under the [MIT License](LICENSE).