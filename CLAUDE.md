# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Koolo is an automated bot for Diablo II: Resurrected written in Go. It reads game memory via the `d2go` library and injects keystrokes/mouse clicks to automate gameplay. Windows-only (uses Win32 APIs, DLL injection, and Windows process management).

## Build Commands

```bash
# Build (Windows batch script, creates build/ directory with exe + configs)
.\build.bat              # version defaults to "dev"
.\build.bat v1.2.3       # with version tag

# Build just the binary (without asset copying)
go build -trimpath -tags static -ldflags="-s -w -H windowsgui" -o koolo.exe ./cmd/koolo

# Run tests (only pathfinding has tests)
go test ./internal/pather/astar/...

# Run all tests
go test ./...
```

## Architecture

### Execution Model

The bot uses a **multi-goroutine priority system** managed by `errgroup`. When a game starts, four concurrent loops run:

| Priority | Loop | Purpose |
|----------|------|---------|
| `PriorityBackground` (5) | Background | Refreshes game data every 100ms |
| `PriorityHigh` (0) | Health | Potion management, chicken (emergency exit), max game length |
| `PriorityHigh` (0) | High Priority | Area correction, item pickup, buff management |
| `PriorityNormal` (1) | Normal | Executes runs sequentially |

Priority is tracked per-goroutine using `runtime.Stack()` to identify goroutine IDs, stored in a global map (`botContexts`).

### Key Abstractions

**Context** (`internal/context/context.go`): Central struct holding all runtime state — game data, config, HID, memory reader/injector, pathfinder, health manager, and character strategy. Accessed by all actions.

**Character interface** (`internal/context/character.go`): Strategy pattern for class-specific behavior. Each character type implements boss-specific kill methods (`KillCountess()`, `KillMephisto()`, etc.) and `KillMonsterSequence()` for generic clearing. Implementations live in `internal/character/`.

**Run interface** (`internal/run/run.go`): Represents a farming run (e.g., Countess, Mephisto, Baal). `BuildRuns()` factory creates run instances from character config. 25+ run types in `internal/run/`.

**Supervisor** (`internal/bot/single_supervisor.go`): Wraps a Bot instance with lifecycle management (Start/Stop/Pause). The `SupervisorManager` (`internal/bot/manager.go`) manages multiple supervisors for multi-character support.

### Package Responsibilities

- `cmd/koolo/` — Entry point. Initializes WebView UI, HTTP server (:8087), event system, Discord/Telegram integrations.
- `internal/bot/` — Bot orchestration, supervisor management, scheduling, crash detection.
- `internal/action/` — High-level actions (clear area, manage belt, cube recipes). Sub-package `step/` has fine-grained steps.
- `internal/character/` — Character class implementations (sorceress variants, hammerdin, trapsin, etc.).
- `internal/run/` — Farm run implementations (one file per run type).
- `internal/game/` — Game interaction layer: memory reading (`d2go`), DLL injection, HID (mouse/keyboard), screenshot, crash detection.
- `internal/pather/` — A* pathfinding with `astar/` sub-package.
- `internal/health/` — Health/mana potion management and belt tracking.
- `internal/town/` — Town-specific NPC interactions, one file per act (A1-A5).
- `internal/config/` — YAML config loading. Main config (`koolo.yaml`) + per-character configs.
- `internal/server/` — HTTP REST API + WebSocket server with HTML templates.
- `internal/event/` — Pub/sub event system for bot status notifications.
- `internal/remote/` — Discord and Telegram integrations.
- `internal/ui/` — Game UI coordinate helpers and screen management.

### Key Dependencies

- `github.com/hectorgimenez/d2go` — Core dependency for D2R memory reading and game data types (areas, items, skills, stats, monsters).
- `github.com/inkeliz/gowebview` — Native WebView for the desktop UI.
- `github.com/lxn/win` — Windows API bindings.
- `golang.org/x/sync` — errgroup for goroutine management.

### Configuration

- `config/koolo.yaml.dist` — Main bot config template (paths, debug settings, Discord/Telegram).
- `config/template/config.yaml` — Per-character config template (class, runs, health thresholds, game settings).
- `config/template/pickit/` — Item pickup rules in NIP format.

### Adding a New Character Class

1. Create a new file in `internal/character/` implementing the `Character` interface.
2. Add the class to the `BuildCharacter()` factory in `internal/character/character.go`.
3. Add the class name as a config option.

### Adding a New Run

1. Create a new file in `internal/run/` implementing the `Run` interface (`Name()` and `Run()` methods).
2. Register it in the `BuildRuns()` switch statement in `internal/run/run.go`.
3. Add the run name constant to `internal/config/runs.go`.
