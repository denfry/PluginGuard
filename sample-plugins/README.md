# Sample plugins

Synthetic plugin JARs used to demo and test PluginGuard.

| Source folder       | Built JAR              | Expected verdict |
|---------------------|------------------------|------------------|
| `benign-plugin/`    | `BenignChat-1.2.0.jar` | Low / Minimal    |
| `malicious-plugin/` | `FreeRanks-2.3.jar`    | Critical         |

- **BenignChat** — a well-behaved plugin: a documented GitHub update check (HTTP) and a touch of
  reflection. PluginGuard should score it highly.
- **FreeRanks** — *simulates* a malicious plugin: process execution, remote class loading,
  exfiltration to a Discord webhook, Minecraft credential theft and a hard-coded C2 IP. The hostile
  code lives in a method that is **never called**, and all targets are non-functional placeholders.
  Do not run it on a real server — it exists only to give the static analyzer realistic indicators.

## Build

Both samples are dependency-free (plain JDK), so a normal `javac` + `jar` is enough:

```bash
./build.sh        # macOS/Linux/Git-Bash
```

```powershell
./build.ps1       # Windows PowerShell
```

The JARs are written next to the scripts in this folder.
