# Long-Running Agent Harness

An Agent workflow framework implemented based on Anthropic's article [Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents).

## Core Concepts

### Problem Background

AI Agents face the following challenges when handling complex tasks across multiple context windows:

1. **Attempting too much at once** - Agents tend to complete all tasks at once, leaving incomplete work when context runs out
2. **Prematurely declaring completion** - Subsequent sessions may incorrectly assume the task is complete after seeing progress
3. **Lack of test verification** - Agents may mark features as complete without proper testing

### Solution: Dual Agent Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    INITIALIZER AGENT                        │
│  - Create feature_list.json (feature requirements list)     │
│  - Create init.sh (environment startup script)              │
│  - Create claude-progress.txt (progress record file)        │
│  - Initialize git repository and commit initial files       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      CODING AGENT                            │
│  - Read progress file and git log to understand status      │
│  - Select one incomplete feature to develop                 │
│  - Perform end-to-end test verification                     │
│  - Commit code and update progress file                     │
└─────────────────────────────────────────────────────────────┘
```

## File Structure

```
agent-harness/
├── README.md                    # This document
├── init.sh                      # Environment initialization script template
├── initializer_prompt.md        # Initializer Agent prompt template
├── coding_agent_prompt.md       # Coding Agent prompt template
├── feature_list.json            # Feature requirements list example
└── claude-progress.txt          # Progress record file template
```

## Usage

### 1. Initializer Agent (First Run)

Use `initializer_prompt.md` as the prompt, and the Agent will:
- Parse user requirements and generate detailed feature_list.json
- Create init.sh script for starting the development environment
- Initialize the progress record file
- Create initial git commit

### 2. Coding Agent (Subsequent Runs)

Use `coding_agent_prompt.md` as the prompt, and each session will:
- Run `pwd` to confirm working directory
- Read git log and progress file to understand status
- Read feature_list.json to select next feature
- Implement feature and perform end-to-end testing
- Commit code and update progress file

## Best Practices

### Feature List Specification

Use JSON format to store feature list to avoid accidental modification by Agents:

```json
{
  "category": "functional",
  "description": "Feature description",
  "steps": [
    "Step 1",
    "Step 2"
  ],
  "passes": false
}
```

### Progress Record Specification

Record at the end of each session:
- What work was completed
- What problems were encountered
- What needs to be done next

### Testing Requirements

- Use end-to-end testing to verify features
- Simulate real user operations
- Do not rely solely on unit tests or code reviews

## Agent Failure Modes and Solutions

| Problem | Initializer Agent Behavior | Coding Agent Behavior |
|---------|---------------------------|----------------------|
| Prematurely declaring project complete | Create detailed feature_list.json | Process only one feature per session |
| Leaving incomplete code | Initialize git and progress files | Read progress and logs, run basic tests |
| Marking feature complete too early | Create feature_list.json | Must pass end-to-end test before marking as passing |

## References

- [Effective harnesses for long-running agents](https://www.anthropic.com/engineering/effective-harnesses-for-long-running-agents)
- [Claude 4 Prompting Guide](https://docs.anthropic.com/en/docs/claude-code/prompting-guide)