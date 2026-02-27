# Metrics Page Grafana Integration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace MetricsPage custom charts with full-featured Grafana iframe, providing users complete Grafana functionality (Explore, dashboards, filters, PromQL queries).

**Architecture:** Keep Kuro's header/sidebar navigation. Main content area shows Grafana iframe in full mode (no kiosk). Minimal page header with title and "Open in Grafana" button only. Remove all custom chart components and PromQL editor.

**Tech Stack:** React, TypeScript, Grafana iframe embedding

---

## Overview

### Files to Delete
- `frontend/src/components/metrics/PromQLEditor.tsx`
- `frontend/src/components/metrics/PromQLEditor.css`

### Files to Modify
- `frontend/src/pages/MetricsPage.tsx` - Simplify to title + GrafanaEmbed
- `frontend/src/pages/MetricsPage.css` - Remove unused styles
- `frontend/src/components/metrics/GrafanaEmbed.tsx` - Use full mode (no kiosk)

### Files to Keep (unchanged)
- `frontend/src/components/metrics/GrafanaEmbed.css`
- All other metrics components (unused but not deleted for potential future use)

---

## Task 1: Delete PromQLEditor Components

**Files:**
- Delete: `frontend/src/components/metrics/PromQLEditor.tsx`
- Delete: `frontend/src/components/metrics/PromQLEditor.css`

**Step 1: Delete PromQLEditor.tsx**

```bash
rm frontend/src/components/metrics/PromQLEditor.tsx
```

**Step 2: Delete PromQLEditor.css**

```bash
rm frontend/src/components/metrics/PromQLEditor.css
```

**Step 3: Verify build still works**

Run: `cd frontend && npm run build`
Expected: Build succeeds without PromQLEditor import errors

**Step 4: Commit**

```bash
git add -A
git commit -m "refactor(metrics): remove PromQLEditor, will use Grafana instead"
```

---

## Task 2: Simplify GrafanaEmbed Component

**Files:**
- Modify: `frontend/src/components/metrics/GrafanaEmbed.tsx`

**Step 1: Update GrafanaEmbed to use full mode**

Replace the `iframeUrl` logic to remove kiosk mode and use full Grafana interface:

```typescript
// Find the iframeUrl useMemo and replace with:
const iframeUrl = useMemo(() => {
  // Full mode - no kiosk, shows complete Grafana UI
  const embedPath = panelId
    ? `/d-solo/${dashboardUid}`
    : `/d/${dashboardUid}`;

  const searchParams = new URLSearchParams({
    orgId: '1',
    theme,
    ...(currentRefresh !== '0' && { refresh: currentRefresh }),
    ...(panelId && { panelId: panelId.toString() }),
    ...(params || {}),
  });

  return `${grafanaUrl}${embedPath}?${searchParams.toString()}`;
}, [grafanaUrl, dashboardUid, panelId, currentRefresh, theme, params]);
```

**Step 2: Remove unused kiosk references**

Remove the `kiosk: panelId ? '' : 'tv'` line from searchParams.

**Step 3: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

**Step 4: Commit**

```bash
git add frontend/src/components/metrics/GrafanaEmbed.tsx
git commit -m "refactor(metrics): use Grafana full mode instead of kiosk"
```

---

## Task 3: Rewrite MetricsPage Component

**Files:**
- Modify: `frontend/src/pages/MetricsPage.tsx`

**Step 1: Replace entire MetricsPage with simplified version**

```typescript
/**
 * Metrics Page - Grafana Integration
 * 
 * Embeds full Grafana dashboard with all native features:
 * - Dashboard switching
 * - Time range selection
 * - Variable filters
 * - Explore (PromQL queries)
 * - Fullscreen mode
 */

import { GrafanaEmbed } from '../components/metrics/GrafanaEmbed';
import './MetricsPage.css';

export default function MetricsPage() {
  // Get Grafana URL from environment
  const grafanaUrl = import.meta.env.VITE_GRAFANA_URL || 'http://localhost:30092';

  return (
    <div className="metrics-page">
      {/* Minimal Header */}
      <div className="metrics-page__header">
        <h1 className="metrics-page__title">Network Metrics</h1>
        {grafanaUrl && (
          <a
            href={grafanaUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="metrics-page__grafana-link"
          >
            <span className="metrics-page__grafana-icon">📊</span>
            Open Grafana
          </a>
        )}
      </div>

      {/* Full Grafana iframe */}
      <div className="metrics-page__grafana-container">
        <GrafanaEmbed
          dashboardUid="kuro-network-metrics"
          theme="dark"
          height={800}
          showFullscreenButton={false}
          showRefreshControls={false}
          title="Kuro Network Dashboard"
        />
      </div>
    </div>
  );
}
```

**Step 2: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds without errors

**Step 3: Commit**

```bash
git add frontend/src/pages/MetricsPage.tsx
git commit -m "refactor(metrics): simplify MetricsPage to Grafana iframe only"
```

---

## Task 4: Simplify MetricsPage CSS

**Files:**
- Modify: `frontend/src/pages/MetricsPage.css`

**Step 1: Replace CSS with minimal styles**

```css
/* Metrics Page - Grafana Integration */

.metrics-page {
  padding: 24px;
  height: calc(100vh - 64px);
  display: flex;
  flex-direction: column;
  background: #0a0a0f;
}

/* Header */
.metrics-page__header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
  flex-shrink: 0;
}

.metrics-page__title {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  color: #fff;
}

.metrics-page__grafana-link {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 16px;
  background: #1f1f2e;
  border: 1px solid #2d2d3f;
  border-radius: 6px;
  color: #e5e7eb;
  text-decoration: none;
  font-size: 14px;
  transition: all 0.2s;
}

.metrics-page__grafana-link:hover {
  background: #2d2d3f;
  border-color: #4ade80;
  color: #4ade80;
}

.metrics-page__grafana-icon {
  font-size: 16px;
}

/* Grafana Container */
.metrics-page__grafana-container {
  flex: 1;
  min-height: 0;
  background: #111118;
  border: 1px solid #1f1f2e;
  border-radius: 8px;
  overflow: hidden;
}

/* Make Grafana iframe fill container */
.metrics-page__grafana-container .grafana-embed {
  height: 100%;
  border: none;
}

.metrics-page__grafana-container .grafana-embed__iframe {
  border: none;
}
```

**Step 2: Verify build**

Run: `cd frontend && npm run build`
Expected: Build succeeds

**Step 3: Commit**

```bash
git add frontend/src/pages/MetricsPage.css
git commit -m "refactor(metrics): simplify MetricsPage CSS for Grafana integration"
```

---

## Task 5: Update Grafana Dashboard UID

**Files:**
- Check: `deploy/quick-monitor.yaml`

**Step 1: Verify dashboard UID matches**

Check that the dashboard UID in `deploy/quick-monitor.yaml` is `kuro-network-metrics`:

```bash
grep -A 2 '"uid":' deploy/quick-monitor.yaml
```

Expected: `"uid": "kuro-network-metrics"`

If different, update `MetricsPage.tsx` to match the actual UID.

**Step 2: Redeploy Grafana if needed**

If changes were made:
```bash
kubectl apply -f deploy/quick-monitor.yaml
kubectl rollout restart deployment/grafana -n kuro-monitor
```

**Step 3: Commit if changed**

```bash
git add -A
git commit -m "fix(metrics): align dashboard UID with Grafana config"
```

---

## Task 6: Final Verification

**Step 1: Build frontend**

Run: `cd frontend && npm run build`
Expected: Build succeeds with no errors

**Step 2: Start frontend dev server**

Run: `cd frontend && npm run dev`

**Step 3: Verify Grafana accessibility**

Ensure port-forward is active:
```bash
kubectl port-forward svc/grafana -n kuro-monitor 30092:3000 &
```

**Step 4: Test in browser**

1. Open http://localhost:5173/metrics
2. Verify Grafana dashboard loads
3. Verify Grafana navigation (top bar) is visible
4. Verify can switch to Explore
5. Verify can change time range
6. Verify filters (Pod, Traffic Type, Direction) work

**Step 5: Final commit**

```bash
git add -A
git commit -m "refactor(metrics): complete Grafana integration for MetricsPage"
```

---

## Summary

| Task | Action | Files |
|------|--------|-------|
| 1 | Delete PromQLEditor | `PromQLEditor.tsx`, `PromQLEditor.css` |
| 2 | Simplify GrafanaEmbed | `GrafanaEmbed.tsx` |
| 3 | Rewrite MetricsPage | `MetricsPage.tsx` |
| 4 | Simplify CSS | `MetricsPage.css` |
| 5 | Verify dashboard UID | `quick-monitor.yaml` |
| 6 | Final verification | Build, test, commit |

---

## Notes

- Grafana must be accessible at `VITE_GRAFANA_URL` (default: `http://localhost:30092`)
- Prometheus must be scraping `kuro-agent` metrics
- Dashboard UID must match between `quick-monitor.yaml` and `MetricsPage.tsx`
