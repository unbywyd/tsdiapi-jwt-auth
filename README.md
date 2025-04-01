# @tsdiapi/jwt-auth

[![npm version](https://badge.fury.io/js/%40tsdiapi%2Fjwt-auth.svg)](https://badge.fury.io/js/%40tsdiapi%2Fjwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**TSDIAPI-JWT-Auth** is a plugin for the `TSDIAPI-Server` framework that simplifies JWT-based authentication and authorization. It includes utilities for token creation, session validation, and custom guards to secure API endpoints effectively.

---

## Features

- **Token Management**: Generate and verify JWT tokens with customizable payloads and expiration times.
- **Session Protection**: Use built-in or custom session validation logic for secure API access.
- **Custom Guards**: Easily register and reference multiple guards to support various security requirements.
- **Environment Integration**: Supports configuration through `.env` files to streamline deployment.

---

## Installation

```bash
npm install @tsdiapi/jwt-auth
```

Or use the CLI to add the plugin:

```bash
tsdiapi plugins add jwt-auth
```

---

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
    }),
  ],
});
```

### Environment Configuration

Define environment variables in your `.env` file to avoid hardcoding sensitive data:

```env
JWT_SECRET_KEY=your-secret-key
JWT_EXPIRATION_TIME=604800
```

---

## Protecting Endpoints

### Applying the `JWTGuard`

Secure API endpoints using `JWTGuard`. You can also add custom session validation logic:

```typescript

useRoute()
  .get('/external/report')
  .auth('apiKey')
  .guard(APIKeyGuard({ guardName: 'reportService' }))
  .code(200, Type.Object({
      from: Type.String(),
      key: Type.String(),
  }))
  .handler(async (req) => {
    return {
      status: 200,
      data: { from: 'APIKey session', key: req.session.apiKey }
    }
  })
  .build();
```
---

## Registering Custom Guards

You can register custom guards during plugin initialization. These guards can later be referenced by name:

```typescript
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
});
```

To use the custom guard:

```typescript
import { JWTGuard } from "@tsdiapi/jwt-auth";

useRoute()
  .get('/external/report')
  .auth('apiKey')
  .guard(APIKeyGuard({ guardName: 'reportService' }))
  .code(200, Type.Object({
      from: Type.String(),
      key: Type.String(),
  }))
  .handler(async (req) => {
    return {
      status: 200,
      data: { from: 'APIKey session', key: req.session.apiKey }
    }
  })
  .build();
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

---

## API Reference

### Plugin Options

| Option           | Type                                      | Description                            |
| ---------------- | ----------------------------------------- | -------------------------------------- |
| `secretKey`      | `string`                                  | Secret key for signing JWT tokens.     |
| `expirationTime` | `number`                                  | Token expiration time in seconds.      |
| `guards`         | `Record<string, ValidateSessionFunction>` | Custom guards for validating sessions. |

---

## License

This plugin is open-source and available under the [MIT License](LICENSE).
