# ClawGuard Dashboard

A minimal web dashboard for monitoring and managing ClawGuard security.

## Features

- **Overview** — Threat stats, recent alerts, system health at a glance
- **Audit Log** — Searchable/filterable event log with detailed views
- **Policies** — View and edit security policies for all modules
- **Enclave** — Protected files list and pending change approvals

## Quick Start

```bash
# Install dependencies
npm install

# Start development (frontend + API server)
npm run dev

# Access at http://localhost:3000
```

## Authentication

The API requires an API key. Set `CLAWGUARD_API_KEY` environment variable or use the default dev key:

```
clawguard-dev-key
```

## Architecture

```
dashboard/
├── src/               # React frontend (Vite)
│   ├── pages/         # Page components
│   ├── components/    # Shared UI components
│   └── api.ts         # API client
├── server/            # Express API server
│   ├── index.ts       # Server entry
│   ├── api.ts         # API routes
│   └── auth.ts        # API key auth
└── public/            # Static assets
```

## API Endpoints

All endpoints require `Authorization: Bearer <api_key>` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/stats` | Overview statistics |
| GET | `/api/logs` | Fetch audit logs |
| GET | `/api/logs/search` | Search logs |
| GET | `/api/policies` | Get all policies |
| PUT | `/api/policies` | Update policies |
| GET | `/api/enclave/files` | List protected files |
| GET | `/api/enclave/pending` | Get pending approvals |
| POST | `/api/enclave/approve/:id` | Approve/deny change |
| GET | `/api/enclave/integrity` | Check file integrity |

## Production Build

```bash
# Build frontend
npm run build

# Start production server
NODE_ENV=production npm start
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3001` | API server port |
| `CLAWGUARD_API_KEY` | `clawguard-dev-key` | API authentication key |
| `NODE_ENV` | `development` | Environment mode |

## Development

The frontend runs on port 3000 with hot reload. API requests are proxied to port 3001.

```bash
# Frontend only
npm run dev:client

# API only
npm run dev:server

# Both
npm run dev
```

## Screenshots

The dashboard includes:
- Dark theme optimized for security monitoring
- Responsive design for mobile/tablet
- Real-time data refresh
- Expandable log entries with JSON details
- Interactive policy editor with validation
