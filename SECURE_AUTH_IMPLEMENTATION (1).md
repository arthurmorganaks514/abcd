# Secure Authentication Implementation Plan

## Table of Contents

1. [Overview](#overview)
2. [Current Security Issues](#current-security-issues)
3. [Solution Architecture](#solution-architecture)
4. [Implementation Steps](#implementation-steps)
5. [Security Flow Diagrams](#security-flow-diagrams)
6. [Environment Configuration](#environment-configuration)
7. [DynamoDB Schema](#dynamodb-schema)
8. [Attack Prevention Matrix](#attack-prevention-matrix)

---

## Overview

This document outlines the implementation of **HttpOnly Cookies + CSRF Protection + Refresh Token Rotation** to prevent JWT token theft and replay attacks.

### What We're Implementing

| Feature | Description |
|---------|-------------|
| **HttpOnly Cookies** | JWT stored in cookies inaccessible via JavaScript |
| **CSRF Protection** | Token-based CSRF validation for state-changing requests |
| **Refresh Token Rotation** | Short-lived access tokens with automatic refresh |
| **Environment-Based Config** | Supports both development (localhost) and production (HTTPS) |

### Token Lifetimes

| Token | Lifetime | Storage |
|-------|----------|---------|
| Access Token | 15 minutes | HttpOnly Cookie |
| Refresh Token | 7 days | HttpOnly Cookie + DynamoDB |
| CSRF Token | Session | sessionStorage (frontend) |

---

## Current Security Issues

### Current Implementation Analysis

```
┌─────────────────────────────────────────────────────────────┐
│                    CURRENT (INSECURE)                       │
├─────────────────────────────────────────────────────────────┤
│  Backend:                                                   │
│    - JWT with {email, role} payload                         │
│    - 24-hour expiry                                         │
│    - Sent in response body                                  │
│                                                             │
│  Frontend:                                                  │
│    - Token stored in localStorage                           │
│    - Sent via Authorization: Bearer header                  │
│    - No device validation                                   │
└─────────────────────────────────────────────────────────────┘
```

### Vulnerabilities

| Vulnerability | Risk Level | Description |
|---------------|------------|-------------|
| XSS Token Theft | **Critical** | localStorage accessible via JavaScript |
| Token Replay | **High** | Stolen token works from any browser |
| Long Token Life | **Medium** | 24-hour exposure window |
| No Revocation | **Medium** | Cannot invalidate stolen tokens |

---

## Solution Architecture

### Secure Flow Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         LOGIN FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│  1. User submits credentials                                    │
│  2. Backend validates → generates:                              │
│     • Access Token (15 min, HttpOnly cookie)                    │
│     • Refresh Token (7 days, HttpOnly cookie, stored in DB)     │
│     • CSRF Token (in response body)                             │
│  3. Frontend stores CSRF token in sessionStorage                │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                       REQUEST FLOW                              │
├─────────────────────────────────────────────────────────────────┤
│  1. Request automatically includes cookies                      │
│  2. Frontend adds CSRF token to header (X-CSRF-Token)           │
│  3. Backend validates:                                          │
│     • Access Token signature & expiry                           │
│     • CSRF token matches                                        │
│  4. If access token expired → use /refresh endpoint             │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      REFRESH FLOW                               │
├─────────────────────────────────────────────────────────────────┤
│  1. Frontend detects 401 → calls /refresh                       │
│  2. Backend validates refresh token from cookie                 │
│  3. Checks refresh token exists in DB (not revoked)             │
│  4. Issues new access token + new refresh token (rotation)      │
│  5. Old refresh token is invalidated                            │
└─────────────────────────────────────────────────────────────────┘
```

### Component Interaction

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Frontend   │     │   Backend    │     │   DynamoDB   │
│   (React)    │     │  (Express)   │     │              │
├──────────────┤     ├──────────────┤     ├──────────────┤
│              │     │              │     │              │
│  Login.jsx ──┼────►│ auth.js ─────┼────►│ User.js      │
│              │     │              │     │              │
│  api.js ─────┼────►│ auth.js ─────┼────►│ RefreshToken │
│  (intercept) │     │ (middleware) │     │   records    │
│              │     │              │     │              │
│  useAuth.js ◄┼─────│  cookies     │     │              │
│              │     │              │     │              │
└──────────────┘     └──────────────┘     └──────────────┘
```

---

## Implementation Steps

### Step 1: Install Dependencies

```bash
cd babai-campaign-app-backend
npm install cookie-parser
```

### Step 2: Create Cookie Configuration

**File:** `backend/config/cookieConfig.js`

```javascript
const isProduction = process.env.NODE_ENV === 'production';

export const cookieConfig = {
  access: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/',
    maxAge: 15 * 60 * 1000,  // 15 minutes
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined
  },
  refresh: {
    httpOnly: true,
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/api/auth',  // Only sent to auth endpoints
    maxAge: 7 * 24 * 60 * 60 * 1000,  // 7 days
    domain: isProduction ? process.env.COOKIE_DOMAIN : undefined
  }
};

export const csrfConfig = {
  cookie: {
    httpOnly: false,  // Frontend needs to read this
    secure: isProduction,
    sameSite: isProduction ? 'strict' : 'lax',
    path: '/',
    maxAge: 15 * 60 * 1000  // Match access token
  }
};
```

### Step 3: Update app.js

**File:** `backend/app.js`

```javascript
import cookieParser from 'cookie-parser';
// ... existing imports

const app = express();

// Add cookie parser (BEFORE routes)
app.use(cookieParser(process.env.COOKIE_SECRET));

// Update CORS to allow CSRF header
app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true);
    if (NODE_ENV === 'development') return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,  // Already set
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token']  // Add X-CSRF-Token
}));

// ... rest of existing code
```

### Step 4: Update User Model

**File:** `backend/models/User.js`

Add these methods to the User class:

```javascript
import crypto from 'crypto';

// Add to User class:

static hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

static async saveRefreshToken(email, token, deviceInfo = 'Unknown') {
  const tokenHash = this.hashToken(token);
  const timestamp = this.timestamp;
  const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();

  const refreshTokenItem = db.User(email, `REFRESH#${tokenHash.substring(0, 8)}`);
  Object.assign(refreshTokenItem, {
    tokenHash,
    deviceInfo: deviceInfo.substring(0, 100),  // Limit length
    createdAt: timestamp,
    expiresAt
  });

  await refreshTokenItem.save();
  return tokenHash;
}

static async validateRefreshToken(email, token) {
  const tokenHash = this.hashToken(token);
  const prefix = tokenHash.substring(0, 8);

  try {
    const record = await this.userPartition(email).get(`REFRESH#${prefix}`);
    if (!record) return false;

    const data = record.getData();

    // Check if expired
    if (new Date(data.expiresAt) < new Date()) {
      await this.deleteRefreshToken(email, token);
      return false;
    }

    // Verify hash matches
    return data.tokenHash === tokenHash;
  } catch (error) {
    return false;
  }
}

static async deleteRefreshToken(email, token) {
  const tokenHash = this.hashToken(token);
  const prefix = tokenHash.substring(0, 8);

  try {
    await this.userPartition(email).delete(`REFRESH#${prefix}`);
  } catch (error) {
    // Token may already be deleted
  }
}

static async deleteAllRefreshTokens(email) {
  try {
    const partition = this.userPartition(email);
    const allItems = await partition.getAll();

    const refreshTokens = allItems.filter(item =>
      item.getData().PK?.startsWith('REFRESH#')
    );

    await Promise.all(
      refreshTokens.map(token => token.delete())
    );
  } catch (error) {
    // Handle gracefully
  }
}
```

### Step 5: Update Auth Middleware

**File:** `backend/middleware/auth.js`

```javascript
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const authenticateToken = (req, res, next) => {
  // Read token from cookie instead of Authorization header
  const token = req.cookies?.accessToken;

  if (!token) {
    return res.status(401).json({
      success: false,
      error: 'Access token required'
    });
  }

  const secret = process.env.JWT_SECRET;
  if (!secret) {
    console.error('JWT_SECRET is not configured');
    return res.status(500).json({
      success: false,
      error: 'Server configuration error'
    });
  }

  jwt.verify(token, secret, (err, user) => {
    if (err) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired token'
      });
    }
    req.user = user;
    next();
  });
};

const csrfProtection = (req, res, next) => {
  // Skip for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
    return next();
  }

  const csrfToken = req.headers['x-csrf-token'];
  const csrfCookie = req.cookies?.csrfToken;

  if (!csrfToken || !csrfCookie) {
    return res.status(403).json({
      success: false,
      error: 'CSRF token missing'
    });
  }

  // Use timing-safe comparison
  const isValid = crypto.timingSafeEqual(
    Buffer.from(csrfToken),
    Buffer.from(csrfCookie)
  );

  if (!isValid) {
    return res.status(403).json({
      success: false,
      error: 'Invalid CSRF token'
    });
  }

  next();
};

const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required'
      });
    }

    if (!req.user.role) {
      return res.status(403).json({
        success: false,
        error: 'User role not defined'
      });
    }

    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        error: `Access denied. Required role: ${allowedRoles.join(' or ')}`
      });
    }

    next();
  };
};

export { authenticateToken, csrfProtection, authorizeRoles };
```

### Step 6: Update Auth Routes

**File:** `backend/routes/auth.js`

```javascript
import express from 'express';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import User from '../models/User.js';
import { authLimiter } from '../middleware/dynamoRateLimiter.js';
import { authenticateToken, csrfProtection } from '../middleware/auth.js';
import { validateInput } from '../middleware/inputValidator.js';
import { logger } from '../utils/asyncLogger.js';
import { cookieConfig } from '../config/cookieConfig.js';

const router = express.Router();

// Helper: Generate CSRF token
function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Helper: Generate token pair
function generateTokens(user) {
  const accessToken = jwt.sign(
    { email: user.email, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY || '15m' }
  );

  const refreshToken = crypto.randomBytes(64).toString('hex');

  return { accessToken, refreshToken };
}

// Helper: Set cookies
function setTokenCookies(res, accessToken, refreshToken, csrfToken) {
  res.cookie('accessToken', accessToken, cookieConfig.access);
  res.cookie('refreshToken', refreshToken, cookieConfig.refresh);
  res.cookie('csrfToken', csrfToken, {
    ...cookieConfig.access,
    httpOnly: false  // Frontend needs to read this
  });
}

// Helper: Clear cookies
function clearTokenCookies(res) {
  const isProduction = process.env.NODE_ENV === 'production';
  const domain = isProduction ? process.env.COOKIE_DOMAIN : undefined;

  res.clearCookie('accessToken', { path: '/', domain });
  res.clearCookie('refreshToken', { path: '/api/auth', domain });
  res.clearCookie('csrfToken', { path: '/', domain });
}

// ==================== LOGIN ====================
router.post('/login', authLimiter, validateInput('login'), async (req, res, next) => {
  try {
    const { email, password } = req.body;
    logger.info('Login attempt', { email });

    const user = await User.findByEmail(email);
    if (!user) {
      logger.warn('Login failed - user not found', { email });
      return res.status(401).json({
        success: false,
        error: 'Login failed - user not found'
      });
    }

    if (!user.isActive) {
      logger.warn('Login failed - inactive account', { email });
      return res.status(403).json({
        success: false,
        error: 'Account is inactive. Please contact support.'
      });
    }

    const isValidPassword = await User.validatePassword(password, user.password);
    if (!isValidPassword) {
      logger.warn('Login failed - invalid password', { email });
      return res.status(401).json({
        success: false,
        error: 'Login failed - Invalid password'
      });
    }

    // Generate tokens
    const { accessToken, refreshToken } = generateTokens(user);
    const csrfToken = generateCsrfToken();

    // Store refresh token in DB
    const deviceInfo = req.headers['user-agent'] || 'Unknown';
    await User.saveRefreshToken(user.email, refreshToken, deviceInfo);

    // Update last login
    await User.updateLastLogin(user.email).catch(err =>
      logger.error('Failed to update last login', { error: err.message })
    );

    // Set cookies
    setTokenCookies(res, accessToken, refreshToken, csrfToken);

    logger.info('Login successful', { email: user.email });

    // Return CSRF token and user info (NOT the JWT)
    res.json({
      success: true,
      message: 'Login successful',
      data: {
        user: {
          email: user.email,
          name: user.name,
          role: user.role
        },
        csrfToken
      }
    });

  } catch (error) {
    next(error);
  }
});

// ==================== REFRESH ====================
router.post('/refresh', async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token required'
      });
    }

    // Decode refresh token to get user email (without verification)
    // We need to find which user this token belongs to
    // Alternative: Store user email in a separate cookie or decode from token

    // For now, we'll verify the token exists in DB for any user
    // This requires a different approach - let's decode the access token if available
    const accessToken = req.cookies?.accessToken;

    let userEmail;
    if (accessToken) {
      try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET, { ignoreExpiration: true });
        userEmail = decoded.email;
      } catch {
        // Access token invalid, try to extract from refresh token flow
      }
    }

    if (!userEmail) {
      // If no access token, we need another way to identify user
      // Option: Add a non-httpOnly cookie with user identifier
      return res.status(401).json({
        success: false,
        error: 'Unable to identify user. Please login again.'
      });
    }

    // Validate refresh token in DB
    const isValid = await User.validateRefreshToken(userEmail, refreshToken);
    if (!isValid) {
      clearTokenCookies(res);
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token. Please login again.'
      });
    }

    // Get user data
    const user = await User.findByEmail(userEmail);
    if (!user || !user.isActive) {
      clearTokenCookies(res);
      return res.status(401).json({
        success: false,
        error: 'User not found or inactive'
      });
    }

    // Delete old refresh token (rotation)
    await User.deleteRefreshToken(userEmail, refreshToken);

    // Generate new tokens
    const tokens = generateTokens(user);
    const csrfToken = generateCsrfToken();

    // Store new refresh token
    const deviceInfo = req.headers['user-agent'] || 'Unknown';
    await User.saveRefreshToken(user.email, tokens.refreshToken, deviceInfo);

    // Set new cookies
    setTokenCookies(res, tokens.accessToken, tokens.refreshToken, csrfToken);

    logger.info('Token refreshed', { email: user.email });

    res.json({
      success: true,
      data: { csrfToken }
    });

  } catch (error) {
    next(error);
  }
});

// ==================== LOGOUT ====================
router.post('/logout', authenticateToken, async (req, res, next) => {
  try {
    const refreshToken = req.cookies?.refreshToken;

    if (refreshToken) {
      await User.deleteRefreshToken(req.user.email, refreshToken);
    }

    clearTokenCookies(res);

    logger.info('User logged out', { email: req.user.email });

    res.json({
      success: true,
      message: 'Logged out successfully'
    });

  } catch (error) {
    next(error);
  }
});

// ==================== GET CURRENT USER ====================
router.get('/me', authenticateToken, async (req, res, next) => {
  try {
    const user = await User.findByEmail(req.user.email);

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const { password, ...safeUser } = user;

    res.json({
      success: true,
      data: { user: safeUser }
    });

  } catch (error) {
    next(error);
  }
});

// ==================== CHANGE PASSWORD ====================
router.post('/change-password', authenticateToken, csrfProtection, async (req, res, next) => {
  try {
    const { currentPassword, newPassword } = req.body;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({
        success: false,
        error: 'Current password and new password are required'
      });
    }

    if (newPassword.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'New password must be at least 8 characters long'
      });
    }

    const user = await User.findByEmail(req.user.email);
    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    const isValidPassword = await User.validatePassword(currentPassword, user.password);
    if (!isValidPassword) {
      logger.warn('Password change failed - invalid current password', { email: user.email });
      return res.status(400).json({
        success: false,
        error: 'Current password is incorrect'
      });
    }

    await User.changePassword(user.email, newPassword);

    // Invalidate all refresh tokens after password change
    await User.deleteAllRefreshTokens(user.email);

    logger.info('Password changed successfully', { email: user.email });

    res.json({
      success: true,
      message: 'Password changed successfully. Please login again.'
    });

  } catch (error) {
    next(error);
  }
});

export default router;
```

### Step 7: Update Environment Variables

**File:** `backend/.env`

```env
# Existing variables
JWT_SECRET=your-jwt-secret
NODE_ENV=development

# New variables for secure auth
COOKIE_SECRET=your-cookie-secret-min-32-chars
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false

# Token expiry (optional - defaults shown)
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

### Step 8: Update Frontend API

**File:** `frontend/src/utils/api.js`

```javascript
import axios from "axios";

export const API_URL =
  import.meta.env.VITE_API_URL || "http://localhost:3001/api";

const api = axios.create({
  baseURL: API_URL,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true,  // IMPORTANT: Send cookies with requests
});

// CSRF Token interceptor (replaces Authorization header)
api.interceptors.request.use((config) => {
  const csrfToken = sessionStorage.getItem("csrfToken");
  if (csrfToken) {
    config.headers["X-CSRF-Token"] = csrfToken;
  }
  return config;
});

// Token refresh interceptor
let isRefreshing = false;
let failedQueue = [];

const processQueue = (error, token = null) => {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(token);
    }
  });
  failedQueue = [];
};

api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // Skip refresh for login and refresh requests
    if (
      originalRequest.url?.includes("/auth/login") ||
      originalRequest.url?.includes("/auth/refresh")
    ) {
      return Promise.reject(error);
    }

    // If 401 and not already retrying
    if (error.response?.status === 401 && !originalRequest._retry) {
      if (isRefreshing) {
        // Queue the request while refreshing
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then((token) => {
          originalRequest.headers["X-CSRF-Token"] = token;
          return api(originalRequest);
        });
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        const { data } = await api.post("/auth/refresh");
        const newCsrfToken = data.data.csrfToken;
        sessionStorage.setItem("csrfToken", newCsrfToken);

        processQueue(null, newCsrfToken);

        originalRequest.headers["X-CSRF-Token"] = newCsrfToken;
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError, null);

        // Refresh failed - redirect to login
        sessionStorage.removeItem("csrfToken");
        window.location.href = "/";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export const auth = {
  login: (credentials) => api.post("/auth/login", credentials),
  logout: () => api.post("/auth/logout"),
  getMe: () => api.get("/auth/me"),
  changePassword: (data) => api.post("/auth/change-password", data),
};

// ... rest of existing exports remain the same
export default api;
```

### Step 9: Update Auth Hook

**File:** `frontend/src/hooks/useAuth.js`

```javascript
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { auth } from '../utils/api';

export const useAuth = () => {
  const queryClient = useQueryClient();
  const csrfToken = sessionStorage.getItem('csrfToken');

  const {
    data: user,
    isLoading,
    isError
  } = useQuery({
    queryKey: ['authUser'],
    queryFn: async () => {
      const res = await auth.getMe();
      return res.data.data.user;
    },
    enabled: !!csrfToken,  // Only fetch if CSRF token exists
    retry: 1,
    staleTime: 1000 * 60 * 5,
  });

  const login = (csrfToken) => {
    sessionStorage.setItem('csrfToken', csrfToken);
    queryClient.invalidateQueries(['authUser']);
  };

  const logout = async () => {
    try {
      await auth.logout();
    } catch (error) {
      // Logout API failed, but we still clear local state
      console.error('Logout API failed:', error);
    } finally {
      sessionStorage.removeItem('csrfToken');
      queryClient.setQueryData(['authUser'], null);
      window.location.href = '/';
    }
  };

  return {
    isAuthenticated: !!user,
    loading: isLoading,
    user,
    login,
    logout
  };
};
```

### Step 10: Update Login Page

**File:** `frontend/src/pages/Login.jsx`

```javascript
import { useState } from "react";
import { useAuth } from "../hooks/useAuth";
import { auth } from "../utils/api";
import toast from "react-hot-toast";

const Login = () => {
  const [credentials, setCredentials] = useState({ email: "", password: "" });
  const [loading, setLoading] = useState(false);
  const { login } = useAuth();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const response = await auth.login(credentials);
      // Store CSRF token (NOT the JWT - that's in HttpOnly cookie)
      login(response.data.data.csrfToken);
      window.location.href = "/";
    } catch (err) {
      toast.error(err.response?.data?.error || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="max-w-md w-full space-y-8">
        <div>
          <h2 className="mt-6 text-center text-3xl font-extrabold text-gray-900">
            Admin Login
          </h2>
        </div>
        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div>
            <input
              type="email"
              required
              className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Email address"
              value={credentials.email}
              onChange={(e) =>
                setCredentials({ ...credentials, email: e.target.value })
              }
            />
          </div>
          <div>
            <input
              type="password"
              required
              className="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 placeholder-gray-500 text-gray-900 focus:outline-none focus:ring-blue-500 focus:border-blue-500"
              placeholder="Password"
              value={credentials.password}
              onChange={(e) =>
                setCredentials({ ...credentials, password: e.target.value })
              }
            />
          </div>
          <div>
            <button
              type="submit"
              disabled={loading}
              className="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50"
            >
              {loading ? "Signing in..." : "Sign in"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;
```

---

## Security Flow Diagrams

### Login Flow

```
Browser                                    Server
   │                                          │
   │  POST /auth/login                        │
   │  Content-Type: application/json          │
   │  {email, password}                       │
   │─────────────────────────────────────────►│
   │                                          │
   │                                          │ 1. Validate credentials
   │                                          │ 2. Generate access token (15min)
   │                                          │ 3. Generate refresh token (7d)
   │                                          │ 4. Store refresh token hash in DB
   │                                          │ 5. Generate CSRF token
   │                                          │
   │  200 OK                                  │
   │  Set-Cookie: accessToken=xxx; HttpOnly   │
   │  Set-Cookie: refreshToken=yyy; HttpOnly  │
   │  Set-Cookie: csrfToken=zzz               │
   │  Body: {csrfToken: "zzz", user: {...}}   │
   │◄─────────────────────────────────────────│
   │                                          │
   │  Store csrfToken in sessionStorage       │
```

### Authenticated Request Flow

```
Browser                                    Server
   │                                          │
   │  GET /api/products                       │
   │  Cookie: accessToken=xxx                 │ (auto-sent)
   │  X-CSRF-Token: zzz                       │
   │─────────────────────────────────────────►│
   │                                          │
   │                                          │ 1. Read accessToken from cookie
   │                                          │ 2. Verify JWT signature
   │                                          │ 3. Check expiration
   │                                          │ 4. (Optional) Validate CSRF for mutations
   │                                          │
   │  200 OK                                  │
   │  {products: [...]}                       │
   │◄─────────────────────────────────────────│
```

### Token Refresh Flow

```
Browser                                    Server
   │                                          │
   │  GET /api/products                       │
   │  Cookie: accessToken=xxx (EXPIRED)       │
   │─────────────────────────────────────────►│
   │                                          │
   │  401 Unauthorized                        │
   │◄─────────────────────────────────────────│
   │                                          │
   │  POST /auth/refresh                      │
   │  Cookie: refreshToken=yyy                │
   │─────────────────────────────────────────►│
   │                                          │
   │                                          │ 1. Read refresh token from cookie
   │                                          │ 2. Decode expired access token for user
   │                                          │ 3. Validate refresh token in DB
   │                                          │ 4. Delete old refresh token (rotation)
   │                                          │ 5. Generate new token pair
   │                                          │ 6. Store new refresh token in DB
   │                                          │
   │  200 OK                                  │
   │  Set-Cookie: accessToken=NEW; HttpOnly   │
   │  Set-Cookie: refreshToken=NEW; HttpOnly  │
   │  Body: {csrfToken: "NEW"}                │
   │◄─────────────────────────────────────────│
   │                                          │
   │  Update csrfToken in sessionStorage      │
   │  Retry original request                  │
```

### Logout Flow

```
Browser                                    Server
   │                                          │
   │  POST /auth/logout                       │
   │  Cookie: accessToken=xxx                 │
   │  Cookie: refreshToken=yyy                │
   │─────────────────────────────────────────►│
   │                                          │
   │                                          │ 1. Verify access token
   │                                          │ 2. Delete refresh token from DB
   │                                          │ 3. Clear all cookies
   │                                          │
   │  200 OK                                  │
   │  Set-Cookie: accessToken=; Max-Age=0     │
   │  Set-Cookie: refreshToken=; Max-Age=0    │
   │  Set-Cookie: csrfToken=; Max-Age=0       │
   │◄─────────────────────────────────────────│
   │                                          │
   │  Remove csrfToken from sessionStorage    │
   │  Redirect to login                       │
```

---

## Environment Configuration

### Development (.env)

```env
NODE_ENV=development
JWT_SECRET=dev-jwt-secret-change-in-production
COOKIE_SECRET=dev-cookie-secret-32-chars-min
COOKIE_DOMAIN=localhost
COOKIE_SECURE=false
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

### Production (.env)

```env
NODE_ENV=production
JWT_SECRET=<strong-random-secret>
COOKIE_SECRET=<strong-random-secret-32-chars>
COOKIE_DOMAIN=.yourdomain.com
COOKIE_SECURE=true
ACCESS_TOKEN_EXPIRY=15m
REFRESH_TOKEN_EXPIRY=7d
```

### Cookie Behavior by Environment

| Setting | Development | Production |
|---------|-------------|------------|
| `httpOnly` | true | true |
| `secure` | false | true |
| `sameSite` | lax | strict |
| `domain` | undefined | .yourdomain.com |

---

## DynamoDB Schema

### Refresh Token Record

```
PK: USER#user@example.com
SK: REFRESH#a1b2c3d4  (first 8 chars of token hash)
tokenHash: full SHA256 hash of refresh token
deviceInfo: Mozilla/5.0 (Windows NT 10.0...)
createdAt: 2026-07-28T10:30:00.000Z
expiresAt: 2026-08-04T10:30:00.000Z  (TTL attribute)
```

### Access Pattern

```
Operation                    | Key Condition
----------------------------|--------------------------------
Save refresh token          | PK = USER#email, SK = REFRESH#prefix
Validate refresh token      | PK = USER#email, SK = REFRESH#prefix
Delete refresh token        | PK = USER#email, SK = REFRESH#prefix
Delete all user tokens      | PK = USER#email, SK begins_with REFRESH#
```

---

## Attack Prevention Matrix

| Attack Vector | Before | After | How It's Prevented |
|---------------|--------|-------|-------------------|
| **XSS steals token** | Vulnerable | Protected | HttpOnly cookies not accessible via JavaScript |
| **Token replay in another browser** | Vulnerable | Protected | SameSite=Strict blocks cross-origin requests |
| **CSRF attack** | Vulnerable | Protected | CSRF token validation required for mutations |
| **Stolen token used after logout** | Vulnerable | Protected | Refresh token deleted from DB on logout |
| **Long token exposure** | 24 hours | 15 minutes | Short-lived access tokens reduce risk window |
| **Token interception** | Vulnerable | Protected | Secure=true in production (HTTPS only) |
| **Refresh token theft** | N/A | Protected | Token rotation invalidates old tokens |
| **Brute force login** | Partially | Protected | Rate limiter on login endpoint |

---

## Files Modified Summary

### Backend

| File | Changes |
|------|---------|
| `package.json` | Add `cookie-parser` dependency |
| `config/cookieConfig.js` | **NEW** - Cookie configuration |
| `app.js` | Add cookie-parser, update CORS headers |
| `models/User.js` | Add refresh token CRUD methods |
| `middleware/auth.js` | Cookie-based auth, CSRF middleware |
| `routes/auth.js` | Login, refresh, logout endpoints |
| `.env` | Add cookie config variables |

### Frontend

| File | Changes |
|------|---------|
| `utils/api.js` | withCredentials, CSRF interceptor, refresh logic |
| `hooks/useAuth.js` | sessionStorage for CSRF, async logout |
| `pages/Login.jsx` | Store CSRF token instead of JWT |

---

## Testing Checklist

- [ ] Login sets HttpOnly cookies
- [ ] Login returns CSRF token in body
- [ ] Authenticated requests work with cookies
- [ ] CSRF token validated on mutations
- [ ] Access token refreshes automatically on 401
- [ ] Refresh token rotation works (old token invalidated)
- [ ] Logout clears all cookies and DB token
- [ ] Cookies not accessible via `document.cookie`
- [ ] SameSite prevents cross-origin requests
- [ ] Rate limiting works on login endpoint
- [ ] Password change invalidates all sessions

---

## Rollback Plan

If issues arise, revert to localStorage-based auth:

1. Remove `cookie-parser` from app.js
2. Revert `middleware/auth.js` to read from Authorization header
3. Revert `routes/auth.js` to return token in response body
4. Revert `utils/api.js` to use localStorage
5. Revert `hooks/useAuth.js` to localStorage
6. Revert `pages/Login.jsx` to store JWT
