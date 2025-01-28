# TSDIAPI-JWT-Auth

**TSDIAPI-JWT-Auth** is a plugin for `TSDIAPI-Server` that simplifies JWT-based authentication and authorization. It provides utilities for token generation, session validation, and declarative guards for securing API endpoints.

---

## Features

- **Token Generation:** Easily generate secure JWTs with custom payloads.
- **Session Validation:** Verify and decode JWT tokens with optional custom validation logic.
- **Guards:** Secure endpoints with `@JWTGuard`, supporting custom validation functions.
- **Extendable:** Add and manage multiple guards for flexible security configurations.

---

## Installation

```bash
npm install tsdiapi-jwt-auth
```

---

## Usage

### Register the Plugin

In your `TSDIAPI-Server` application, import and register the plugin:

```typescript
import createPlugin from 'tsdiapi-jwt-auth';
import { createApp } from 'tsdiapi-server';

createApp({
  plugins: [
    createPlugin({
      secretKey: 'your-secret-key', // or JWT_SECRET_KEY from .env
      expirationTime: 60 * 60 * 24 * 7, // or JWT_EXPIRATION_TIME from .env
    }),
  ],
});
```

### Environment-Based Configuration

Instead of passing the plugin configuration directly, you can set the following keys in your `.env` file:

```env
JWT_SECRET_KEY=your-secret-key
JWT_EXPIRATION_TIME=604800
```

The plugin will automatically use these values if available.

---

## Protecting Endpoints

### Using the `@JWTGuard` Decorator

Secure your API endpoints by applying the `@JWTGuard` decorator. You can also provide custom validation logic for sessions:

```typescript
import { JWTGuard } from 'tsdiapi-jwt-auth';
import { Controller, Get } from 'routing-controllers';

@Controller('/users')
export class UserController {
  @Get('/profile')
  @JWTGuard({
    validateSession: async (session) => {
      // Custom validation logic
      if (!session.userId) {
        return 'User ID is missing!';
      }
      return true;
    },
  })
  getUserProfile() {
    return { message: 'This is a protected route!' };
  }
}
```

---

## Accessing the Current Session

Use the `@CurrentSession()` decorator to access the current session in your controller methods:

```typescript
import { CurrentSession } from 'tsdiapi-jwt-auth';
import { Controller, Get } from 'routing-controllers';

@Controller('/users')
export class UserController {
  @Get('/session')
  getSession(@CurrentSession() session: any) {
    return { session };
  }
}
```

---

## Adding Custom Guards

You can register multiple custom guards during plugin initialization and reference them by name in your API:

```typescript
createPlugin({
  secretKey: 'your-secret-key',
  guards: {
    adminOnly: async (session) => {
      if (session.role !== 'admin') {
        return 'Only admins are allowed!';
      }
      return true;
    },
  },
});
```

Then use the guard in your controllers:

```typescript
@Controller('/admin')
export class AdminController {
  @Get('/dashboard')
  @JWTGuard({ validateSession: 'adminOnly' })
  getAdminDashboard() {
    return { message: 'Welcome to the admin dashboard!' };
  }
}
```

---

## API

### Plugin Configuration

```typescript
export type PluginOptions = {
  secretKey?: string; // The secret key for signing JWT tokens.
  expirationTime?: number; // Token expiration time in seconds.
  guards?: Record<string, ValidateSessionFunction<Record<string, any>>>; // Custom guards for validating sessions.
};
```

---

## License

MIT License
