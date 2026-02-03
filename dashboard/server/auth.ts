/**
 * Simple API Key Authentication
 */

import { Request, Response, NextFunction } from 'express';

const API_KEY = process.env.CLAWGUARD_API_KEY || 'clawguard-dev-key';

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  // Skip auth for OPTIONS requests (CORS preflight)
  if (req.method === 'OPTIONS') {
    next();
    return;
  }

  const authHeader = req.headers.authorization;
  const apiKey = authHeader?.replace('Bearer ', '') || req.query.apiKey;

  if (!apiKey || apiKey !== API_KEY) {
    res.status(401).json({
      error: 'Unauthorized',
      message: 'Invalid or missing API key',
    });
    return;
  }

  next();
}
