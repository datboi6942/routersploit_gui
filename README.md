# RouterSploit GUI

A sleek, kid-proof graphical interface for RouterSploit that makes network penetration testing accessible through an intuitive PySimpleGUI-based desktop application with zero configuration required.

## Install

```bash
pip install routersploit PySimpleGUI structlog
```

## Hello World

```python
from routersploit_gui.main import main_entry
main_entry()  # Launch the GUI
# Click any module → configure options → hit "Run Module"
```

## Features

- 🎯 **Zero Configuration**: Works out of the box with any RouterSploit installation
- 🌳 **Module Discovery**: Automatically discovers all available RouterSploit modules
- 🎨 **Modern UI**: Clean, dark-themed interface built with PySimpleGUI
- 📝 **Real-time Output**: Live console output with color-coded messages
- 💾 **Target History**: Remembers your last 10 targets for quick reuse
- 🚫 **Kid-proof**: Simple, intuitive interface that prevents accidental damage
- 📊 **Status Tracking**: Clear visual feedback on module execution status

## Architecture

```
routersploit_gui/
├── gui.py              # Main window & event loop
├── module_loader.py    # Discovers modules, builds tree data  
├── runner.py           # Thread wrapper for module execution
├── config.py           # Centralized configuration
└── main.py             # Entry point
```

## Development

```bash
git clone <this-repo>
cd routersploit_gui
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
python main.py
```

## Packaging

```bash
pip install pyinstaller
pyinstaller --onefile --noconsole main.py
# Creates dist/main.exe (Windows) or dist/main (Linux/Mac)
```

## Requirements

- Python 3.11+
- RouterSploit 3.4.0+
- PySimpleGUI 4.60.0+

## License

Same as RouterSploit (BSD-3-Clause) 