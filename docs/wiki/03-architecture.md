# Architecture and data flow

## High-level flow

```text
CLI arguments
     |
     v
InvestigationContext
  - root boundary
  - time window
  - mode
  - shared scan budget
     |
     +--> platform detection
     +--> health collection
     +--> diagnostic modules
              |
              +--> bounded log readers
              +--> local filesystem readers
              +--> bounded process/service probes
              +--> optional public TLS probe
     |
     v
Report model
     |
     +--> terminal renderer: bounded evidence, operator context
     +--> JSON renderer: allowlisted fields + privacy redaction
```

## Main components

| Component | Responsibility |
| --- | --- |
| `cli.py` | Argument parsing, mode selection, exit policy |
| `context.py` | Root, time window, mode, and collection budget |
| `engine.py` | Module orchestration and partial-failure handling |
| `health.py` | Privilege, load, memory, swap, filesystem, and service checks |
| `platform.py` | OS, panel, web stack, PHP, and database identification |
| `util.py` | Bounded readers, timestamp parsing, command execution, root containment |
| `logs.py` | Access-log summaries and request time buckets |
| `modules/` | Domain-specific diagnostic logic |
| `models.py` | Evidence, incidents, recommendations, plans, and reports |
| `render.py` | Human and sanitized structured output |

## Module contract

Every diagnostic module implements `inspect(context)`. The base class provides conservative plan and execute behavior:

- `inspect()` returns evidence-backed incidents.
- `plan()` attaches proposed actions and rollback notes.
- `execute()` remains unsupported unless a module overrides it and explicitly marks actions executable.

Unexpected module failures become warning incidents so one broken collector does not erase the rest of a report. The failure carries an error type in structured output while raw exception detail remains in human evidence.

## Data handling

The terminal renderer intentionally includes source paths and bounded evidence because an engineer needs context. The JSON renderer omits the host field, domain values, raw evidence, customer paths, and network identifiers. It emits `schema_version: 1` so downstream consumers can evolve deliberately.

## Platform behavior

Live mode may use system commands such as `df`, `systemctl`, `ps`, `php`, and database client version probes. They run without a shell, with a trusted minimal environment and bounded timeouts. Offline mode reads only the supplied root for snapshot state and does not fall back to live-host commands.
