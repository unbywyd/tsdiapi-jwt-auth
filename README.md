# TSDIAPI-JWT-Auth

**TSDIAPI-JWT-Auth** is a plugin for the `TSDIAPI-Server` framework that simplifies JWT-based authentication and authorization. It includes utilities for token creation, session validation, and declarative guards to secure API endpoints effectively.

---

## Features

- **Token Management**: Generate and verify JWT tokens with customizable payloads and expiration times.
- **Session Protection**: Use built-in or custom session validation logic for secure API access.
- **Declarative Guards**: Apply the `@JWTGuard` decorator to protect endpoints with optional validation handlers.
- **Custom Guards**: Easily register and reference multiple guards to support various security requirements.
- **Environment Integration**: Supports configuration through `.env` files to streamline deployment.

---

## Installation

```bash
npm install @tsdiapi/jwt-auth
```

---

## Usage

### Register the Plugin

Import and register the plugin in your TSDIAPI application:

```typescript
import createPlugin from '@tsdiapi/jwt-auth';
import { createApp } from '@tsdiapi/server';

createApp({
  plugins: [
    createPlugin({
      secretKey: 'your-secret-key', // Use JWT_SECRET_KEY in .env as an alternative
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

### Applying the `@JWTGuard` Decorator

Secure API endpoints using `@JWTGuard`. You can also add custom session validation logic:

```typescript
import { JWTGuard } from '@tsdiapi/jwt-auth';
import { Controller, Get } from 'routing-controllers';

@Controller('/profile')
export class ProfileController {
  @Get('/')
  @JWTGuard({
    validateSession: async (session) => {
      if (!session.userId) {
        return 'User not authenticated!';
      }
      return true;
    },
  })
  getProfile() {
    return { message: 'This is a protected route!' };
  }
}
```

---

### Accessing the Current Session

Use the `@CurrentSession` decorator to retrieve the authenticated session inside your controller methods:

```typescript
import { CurrentSession } from '@tsdiapi/jwt-auth';
import { Controller, Get } from 'routing-controllers';

@Controller('/session')
export class SessionController {
  @Get('/')
  getSession(@CurrentSession() session: any) {
    return { session };
  }
}
```

---

## Registering Custom Guards

You can register custom guards during plugin initialization. These guards can later be referenced by name:

```typescript
createPlugin({
  secretKey: 'your-secret-key',
  guards: {
    adminOnly: async (session) => {
      if (session.role !== 'admin') {
        return 'Only administrators are allowed!';
      }
      return true;
    },
  },
});
```

To use the custom guard:

```typescript
import { JWTGuard } from '@tsdiapi/jwt-auth';
import { Controller, Get } from 'routing-controllers';

@Controller('/admin')
export class AdminController {
  @Get('/dashboard')
  @JWTGuard({ validateSession: 'adminOnly' })
  getDashboard() {
    return { message: 'Welcome to the admin dashboard!' };
  }
}
```

---

## API Reference

### Plugin Options

| Option            | Type                                      | Description                                  |
|-------------------|-------------------------------------------|----------------------------------------------|
| `secretKey`       | `string`                                  | Secret key for signing JWT tokens.            |
| `expirationTime`  | `number`                                  | Token expiration time in seconds.             |
| `guards`          | `Record<string, ValidateSessionFunction>` | Custom guards for validating sessions.        |

---

## License

This plugin is open-source and available under the [MIT License](LICENSE).