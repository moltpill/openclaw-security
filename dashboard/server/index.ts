/**
 * ClawGuard Dashboard API Server
 */

import express from 'express';
import cors from 'cors';
import path from 'path';
import { fileURLToPath } from 'url';
import { apiRouter } from './api.js';
import { authMiddleware } from './auth.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// API routes (protected)
app.use('/api', authMiddleware, apiRouter);

// Serve static files in production
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../dist')));
  app.get('*', (_req, res) => {
    res.sendFile(path.join(__dirname, '../dist/index.html'));
  });
}

app.listen(PORT, () => {
  console.log(`🛡️  ClawGuard Dashboard API running on http://localhost:${PORT}`);
  console.log(`   API Key: ${process.env.CLAWGUARD_API_KEY || 'clawguard-dev-key'}`);
});
