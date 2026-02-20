# Kuro Frontend Test Agent User Guide

## Introduction

Kuro Test Agent is a long-running frontend automation testing framework that supports both code-level tests and browser E2E tests.

## Quick Start

### 1. Use Interactive Menu (Recommended for Beginners)

```bash
./scripts/kuro-test-quick.sh
```

Select menu options to start testing.

### 2. Run Full Tests Directly

```bash
# Run all tests until completion (includes auto-fix)
./scripts/kuro-test-agent.sh

# Run code tests only (fast)
./scripts/kuro-test-agent.sh --no-browser

# Resume from last interruption
./scripts/kuro-test-agent.sh --resume
```

### 3. Monitor Test Progress

Run in another terminal:

```bash
# View current status
./scripts/kuro-test-monitor.sh status

# Continuous monitoring
./scripts/kuro-test-monitor.sh watch

# View recent logs
./scripts/kuro-test-monitor.sh logs 100
```

## Common Commands Reference

| Command | Description |
|---------|-------------|
| `./kuro-test-quick.sh` | Interactive menu |
| `./kuro-test-quick.sh full` | Full test |
| `./kuro-test-quick.sh code` | Code tests |
| `./kuro-test-quick.sh single FEAT-015` | Single feature |
| `./kuro-test-agent.sh -i 10` | Run 10 iterations |
| `./kuro-test-agent.sh --no-browser` | Skip browser tests |
| `./kuro-test-agent.sh --no-fix` | Disable auto-fix |

## Test Workflow

```
1. Start development server
        ↓
2. Select feature to test (by priority)
        ↓
3. Code-level tests
   ├── TypeScript type checking
   ├── Unit tests (vitest)
   └── Production build (vite build)
        ↓
4. Browser E2E tests (if code tests pass)
   ├── Navigate to page
   ├── Execute interactions
   ├── Verify results
   └── Take screenshots
        ↓
5. Update status
   ├── Update test-feature-list.json
   ├── Save test state
   └── Generate report
        ↓
6. Next feature or complete
```

## Feature Test List

Currently there are **10 features** to test:

### High Priority
- FEAT-014: Production Build Verification
- FEAT-015: Node Local View
- FEAT-016: Topology Creation with YAML Editor
- DASH-001: Dashboard Statistics Display
- CANVAS-001: Topology Canvas Visualization

### Medium Priority
- FEAT-017: TSN Mode
- FEAT-018: Topology Export/Import
- LIST-001: Topology List Filtering
- LAYOUT-001: Sidebar Navigation
- TC-001: Traffic Control Panel

## Output Files

The following files are generated during testing:

```
logs/
├── agent.log                    # Main log
├── dev-server.log              # Development server log
├── .state/
│   ├── test_state.json         # Test state
│   ├── checkpoint.txt          # Checkpoint
│   └── agent.pid               # Process ID
├── screenshots/                # Browser test screenshots
│   └── FEAT-XXX_*.png
├── reports/                    # Test reports
│   ├── test_report_*.html      # HTML report
│   └── test_report_*.json      # JSON report
└── session_*_*.log             # Session logs
```

## Test Passing Criteria

### Code Level
- ✅ TypeScript type check passes (`tsc --noEmit`)
- ✅ All unit tests pass (`npm run test:run`)
- ✅ Production build succeeds (`npm run build`)

### Browser Level
- ✅ Page loads normally, no white screen/errors
- ✅ Key interactive features work properly
- ✅ At least 3 screenshots saved
- ✅ No console.error errors

## Interruption and Recovery

You can interrupt at any time during testing by pressing `Ctrl+C`:

```bash
# State is automatically saved after interruption
^C
[INFO] State saved. Next run will resume from interruption point.

# Resume from last interruption
./scripts/kuro-test-agent.sh --resume
```

## Troubleshooting

### Port Already in Use

```bash
# Check port
lsof -i :5173

# Manually stop development server
pkill -f "vite"
```

### Test Agent Stuck

```bash
# Check agent status
./scripts/kuro-test-monitor.sh status

# Force stop
rm -f logs/.state/agent.pid
pkill -f "kuro-test-agent"
```

### Clean and Retest

```bash
./scripts/kuro-test-quick.sh clean
# or
rm -rf logs/*
```

## View Reports

After testing completes, you can view the generated HTML reports:

```bash
# List all reports
ls -la logs/reports/

# View latest report
firefox logs/reports/test_report_*.html
# or
google-chrome logs/reports/test_report_*.html
```

## Add New Feature Tests

1. Edit `agent-harness/test-feature-list.json`
2. Add new feature object:

```json
{
  "id": "FEAT-019",
  "category": "functional",
  "priority": "high",
  "name": "New Feature Name",
  "description": "Feature description",
  "codeTests": ["Test step 1", "Test step 2"],
  "browserTests": ["Browser test step 1"],
  "passes": false,
  "lastTested": null,
  "notes": ""
}
```

3. Run test:

```bash
./scripts/kuro-test-agent.sh -f FEAT-019
```

## Architecture Overview

The Test Agent contains three main scripts:

1. **kuro-test-agent.sh** - Core Engine
   - Intelligent scheduling algorithm
   - Code test execution
   - Browser E2E test coordination
   - Auto-fix triggering
   - Report generation

2. **kuro-test-monitor.sh** - Monitoring Tool
   - Real-time status display
   - Log viewing
   - Quick report generation

3. **kuro-test-quick.sh** - Quick Launch
   - Interactive menu
   - Common command shortcuts

## Important Notes

1. **Screenshot Evidence**: Browser tests must save at least 3 screenshots
2. **Independence**: Each feature test should run independently
3. **Failure Handling**: Code test failures will skip browser tests
4. **Resource Management**: Scripts automatically manage development server start/stop
5. **State Persistence**: Use `--resume` to recover from interruption point

## Getting Help

```bash
# View help
./scripts/kuro-test-agent.sh --help
./scripts/kuro-test-monitor.sh help
./scripts/kuro-test-quick.sh help

# View README
cat agent-harness/README.md
```

## Example Session

```bash
# Terminal 1: Start test
$ ./scripts/kuro-test-quick.sh
Select [0-7]: 1
[INFO] Starting full test...
...

# Terminal 2: Monitor progress
$ ./scripts/kuro-test-monitor.sh watch
Refreshing current status display...

# View report after testing completes
$ firefox logs/reports/test_report_*.html
```
