# MECCHA CHAMELEON Box ESP

A fully external box ESP for **MECCHA CHAMELEON** (Steam / UE5.6). No DLL injection, no UE4SS dependency — it pattern-scans the running game process and reads memory through `pymem`.

## Features

- Fully external (no injected code, no hooks)
- Pattern-scans `GUObjectArray` and walks the UE object array
- Dynamic box ESP with distance scaling
- Corner or 2D box style
- Snap lines, name & distance labels
- Toggleable menu (Insert / F1)
- Separate local-player box for testing

## Requirements

- Windows 10/11
- Python 3.11+
- Game running in windowed/borderless mode

```bash
pip install pymem PyQt5 pywin32
```

## Usage

1. Launch MECCHA CHAMELEON.
2. Run the ESP:
   ```bash
   python esp.py
   ```
3. A transparent overlay will appear over the game window.
4. Use **Insert** or **F1** to show/hide the menu.
5. Toggle features from the menu.

> The ESP reads `GameState -> PlayerArray` for other players. Load into a match/lobby with other players for enemy boxes to appear. Enable **Show Local Player** to verify the projection without needing enemies.

## Notes

- Offsets and the pattern signature are for the current UE5.6 build of MECCHA CHAMELEON. Game updates may break them.
- The script expects the game window title `Chameleon  `. If the title changes, update `Overlay._find_game_window()`.

## Disclaimer

This project is provided for **educational and research purposes only**. Using cheats or unauthorized third-party tools in online games may violate the game's Terms of Service and can result in account suspension or permanent ban. The authors assume no liability for any damages, bans, or other consequences resulting from the use or misuse of this software. Use at your own risk.
