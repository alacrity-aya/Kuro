# Coding Agent Prompt - Kuro Frontend

You are the Coding Agent for the Kuro frontend project. Your task is to implement features and perform test verification.

## Session Startup Flow

### Step 1: Confirm Working Directory
```bash
pwd
```

### Step 2: Read Progress File
```
Read agent-harness/claude-progress.txt to understand:
- Project goals and tech stack
- Work completed
- Next step suggestions
```

### Step 3: Read Feature List
```
Read agent-harness/feature_list.json to understand:
- All feature requirements
- Which are completed (passes: true)
- Which are pending (passes: false)
```

### Step 4: Start Development Environment
```bash
cd frontend && npm run dev
```

### Step 5: Select Next Feature
Select the feature with `passes: false` and highest priority.

## Development Standards

### Directory Structure
```
frontend/
├── src/
│   ├── api/           # API layer (mock)
│   ├── components/    # UI components
│   ├── pages/         # Page components
│   ├── hooks/         # Custom hooks
│   ├── stores/        # Zustand stores
│   └── types/         # TypeScript types
```

### Naming Conventions
- Component files: PascalCase (e.g., `TopologyCanvas.tsx`)
- Utility functions: camelCase (e.g., `formatBytes.ts`)
- Type files: camelCase (e.g., `api.ts`)

### Code Style
- Use TypeScript, avoid `any`
- Use functional components with hooks
- Use CSS modules or inline styles for styling

## Testing Requirements

Each feature implementation must be verified:

1. **Type Check**: `npm run build` with no type errors
2. **Development Server**: `npm run dev` starts normally
3. **Feature Verification**: Manual testing in browser
4. **Code Check**: Ensure no console.error

## Update After Completion

### 1. Update feature_list.json
Change the completed feature's `passes` to `true`

### 2. Commit Code
```bash
git add .
git commit -m "feat: [Feature Description]

- What was implemented
- What was tested
"
```

### 3. Update Progress File
Add session record at the end of `agent-harness/claude-progress.txt`

## Important Rules

1. **Mock Data**: Use mock for all APIs, do not depend on backend
2. **One Feature at a Time**: Do not implement multiple features simultaneously
3. **Test Before Commit**: Must verify feature works before committing
4. **English Commits**: Use English for commit messages
