# Temporary Note: Worth Pulling From n8n

This is a temporary reference note for Primordial.

## Worth Pulling

### 1. Module registration and lazy feature loading

- Why it matters:
  Keep security mode, Caido, Notion, Discord, Claude, and future modes/adapters discoverable and decoupled.
- Primordial translation:
  Use a control-plane `ModuleRegistry` with lazy module loading and explicit lifecycle hooks.
- Reference files:
  - [backend-module-guide.md](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/scripts/backend-module/backend-module-guide.md)
  - [module-registry.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/backend-common/src/modules/module-registry.ts)

### 2. Typed internal event bus

- Why it matters:
  Reusable internal signaling for task lifecycle, sync, notifications, recovery, and observability.
- Primordial translation:
  Add a typed runtime event bus instead of wiring every subsystem directly together.
- Reference files:
  - [event-bus.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/utils/src/event-bus.ts)
  - [event-queue.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/utils/src/event-queue.ts)
  - [event.service.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/events/event.service.ts)

### 3. Concurrency gating

- Why it matters:
  Maps directly to the GPU hot path, Claude budget lane, and risky primitive lane.
- Primordial translation:
  Strengthen capacity reservations around provider routing and execution throttling.
- Reference files:
  - [concurrency-control.service.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/concurrency/concurrency-control.service.ts)
  - [concurrency-queue.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/concurrency/concurrency-queue.ts)

### 4. Crash-loop and resume handling

- Why it matters:
  Gives long-running control-plane behavior a clean recovery story.
- Primordial translation:
  Keep a crash journal marker, slow down crash loops, and make recovery state explicit.
- Reference files:
  - [crash-journal.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/crash-journal.ts)
  - [wait-tracker.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/wait-tracker.ts)

### 5. Worker broker semantics

- Why it matters:
  Good fit for future host/container primitive workers and isolated long-running execution lanes.
- Primordial translation:
  Move toward offer/accept worker dispatch instead of assuming all execution happens in-process.
- Reference files:
  - [task-runner.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/task-runner/src/task-runner.ts)

### 6. Artifact handling patterns

- Why it matters:
  Reinforces the SQL metadata + filesystem artifact store split.
- Primordial translation:
  Keep blobs on disk, keep lineage and metadata in SQL, keep access structured.
- Reference files:
  - [database.manager.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/cli/src/binary-data/database.manager.ts)

### 7. Validation plugins

- Why it matters:
  Useful for methodology validation, primitive manifest linting, and autonomous-plan checks before execution.
- Primordial translation:
  Add validator plugins that can reject or warn on unsafe or incomplete plans before the workflow engine runs them.
- Reference files:
  - [tool-node-validator.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/workflow-sdk/src/workflow-builder/plugins/validators/tool-node-validator.ts)
  - [agent-validator.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/workflow-sdk/src/workflow-builder/plugins/validators/agent-validator.ts)
  - [pin-data-utils.ts](/home/bitloop/Desktop/PRIMORDIAL/primordial/n8n-master/packages/@n8n/workflow-sdk/src/pin-data-utils.ts)

## Implemented First

This pass should prioritize:

1. `ModuleRegistry`
2. typed internal `EventBus`
3. crash journal lifecycle hooks

Those three improve modularity immediately without distorting Primordial into a generic workflow builder.
