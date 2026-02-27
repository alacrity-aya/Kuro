# Kuro Frontend

React-based web UI for the Kuro distributed network simulator.

## Tech Stack

- **Framework:** React 19 + TypeScript
- **Build Tool:** Vite 7
- **Topology Visualization:** ReactFlow + Dagre auto-layout
- **Charts:** ECharts (metrics dashboards)
- **YAML Editor:** Monaco Editor
- **State Management:** Zustand
- **Data Fetching:** TanStack React Query
- **Routing:** React Router DOM

## Getting Started

```bash
npm install
npm run dev       # Dev server at http://localhost:5173
```

The dev server proxies `/api` requests to `http://localhost:8080` (the Kuro controller).

## Scripts

| Command | Description |
|---------|-------------|
| `npm run dev` | Start development server |
| `npm run build` | TypeScript check + production build |
| `npm run lint` | Run ESLint |
| `npm run test` | Run Vitest in watch mode |
| `npm run test:run` | Run tests once |
| `npm run test:coverage` | Run tests with coverage |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `VITE_USE_MOCK_API` | `true` | Use mock Kuro API |
| `VITE_USE_MOCK_PROMETHEUS` | `true` | Use mock Prometheus |
| `VITE_API_BASE_URL` | `/api/v1` | Kuro API base URL |
| `VITE_PROMETHEUS_URL` | — | Prometheus service address |
| `VITE_GRAFANA_URL` | — | Grafana embed URL |

## Directory Structure

```
src/
├── api/            # API clients (mock + real)
├── components/     # React components
│   ├── topology/   # Topology canvas, node/link panels
│   ├── metrics/    # Charts and dashboards
│   ├── tsn/        # Time-Sensitive Networking
│   └── Layout/     # Sidebar, page layouts
├── hooks/          # Custom hooks (useHistory, useAutoRefresh)
├── pages/          # Route-level page components
├── stores/         # Zustand state stores
├── types/          # TypeScript type definitions
└── utils/          # Utility functions and validators
```
