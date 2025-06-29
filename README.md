# RouterSploit GUI

A modern, web-based GUI for RouterSploit - making penetration testing accessible and user-friendly.

## ✨ Features

- 🌐 **Web-based Interface**: Access from any browser, no desktop environment required
- 🔍 **Automatic Module Discovery**: Automatically discovers all RouterSploit modules
- 🌳 **Hierarchical Module Tree**: Organized view of exploits, scanners, payloads, and more
- ⚙️ **Dynamic Option Configuration**: Automatic form generation for module options
- 🔄 **Real-time Output**: Live execution output via WebSockets
- 💾 **Target History**: Quick target setup for repeated testing
- 🎨 **Modern UI**: Clean, responsive interface built with Bootstrap
- 📊 **Color-coded Output**: Easy-to-read execution results
- 💥 **Background Execution**: Non-blocking module execution
- 🛡️ **Error Handling**: Comprehensive validation and error reporting

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/routersploit_gui.git
cd routersploit_gui

# Install dependencies
pip install -r requirements.txt

# Or using Poetry (recommended)
poetry install
poetry shell
```

### Running the GUI

```bash
# Start the web server
python demo.py

# Or run directly
python main.py

# The GUI will be available at http://127.0.0.1:5000
```

### Command Line Options

```bash
python main.py --help

# Custom host and port
python main.py --host 0.0.0.0 --port 8080

# Debug mode
python main.py --debug
```

## 🖥️ Usage

1. **Start the Server**: Run `python demo.py` to start the web server
2. **Open Browser**: Navigate to `http://127.0.0.1:5000`
3. **Select Module**: Browse the module tree and click on any module
4. **Configure Options**: Fill in the required options (marked with red asterisk)
5. **Quick Target**: Use the target field to quickly set IP addresses
6. **Run Module**: Click "Run Module" to execute
7. **View Results**: Watch real-time output in the right panel

## 📋 Module Categories

- **Exploits**: Remote code execution, authentication bypass, etc.
- **Scanners**: Network discovery and vulnerability detection
- **Creds**: Credential testing and brute force modules
- **Generic**: General-purpose security testing tools
- **Payloads**: Code execution payloads for exploits

## 🛠️ Architecture

The application follows a clean, modular architecture:

- **Flask Backend**: RESTful API for module management and execution
- **WebSocket Communication**: Real-time updates during execution
- **ModuleLoader**: Discovers and loads RouterSploit modules
- **RunnerManager**: Handles background execution with thread safety
- **Modern Frontend**: Bootstrap + vanilla JavaScript for the UI

## 📁 Project Structure

```
routersploit_gui/
├── routersploit_gui/
│   ├── __init__.py
│   ├── config.py           # Application configuration
│   ├── web_gui.py          # Flask web application
│   ├── module_loader.py    # RouterSploit module discovery
│   ├── runner.py           # Background execution management
│   ├── templates/          # HTML templates
│   │   └── index.html
│   └── static/             # CSS, JavaScript, assets
│       ├── css/style.css
│       └── js/app.js
├── tests/                  # Test suite
├── demo.py                 # Demo script
├── main.py                 # Main entry point
└── pyproject.toml         # Project configuration
```

## 🔧 Development

### Requirements

- Python 3.11+
- RouterSploit installed and accessible
- Modern web browser with JavaScript enabled

### Dependencies

- **Flask**: Web framework
- **Flask-SocketIO**: Real-time communication
- **RouterSploit**: The core penetration testing framework
- **structlog**: Structured logging

### Running Tests

```bash
# Run the test suite
pytest

# With coverage
pytest --cov --cov-branch

# Type checking
mypy routersploit_gui
```

### Code Quality

```bash
# Format code
black routersploit_gui

# Lint code
ruff routersploit_gui

# Run all checks
pre-commit run --all-files
```

## 🌐 Web API

The application exposes a RESTful API:

- `GET /` - Main web interface
- `GET /api/modules` - Get all modules tree
- `GET /api/module/<path>` - Get specific module details
- `POST /api/run` - Execute a module
- `POST /api/stop` - Stop execution
- `GET /api/status` - Get execution status

WebSocket events:
- `output` - Real-time execution output
- `complete` - Execution completion
- `status` - Status updates

## 🔒 Security Considerations

- **Local Use**: Designed for local security testing environments
- **Network Access**: Be cautious when binding to public interfaces
- **Privilege Escalation**: Some modules may require elevated privileges
- **Target Authorization**: Only test against systems you own or have permission to test

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Run the test suite
6. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [RouterSploit](https://github.com/threat9/routersploit) - The underlying penetration testing framework
- [Flask](https://flask.palletsprojects.com/) - Web framework
- [Bootstrap](https://getbootstrap.com/) - UI components
- [Font Awesome](https://fontawesome.com/) - Icons

## 📞 Support

- **Issues**: Report bugs and feature requests on GitHub
- **Documentation**: Check the wiki for detailed documentation
- **Security**: Report security issues privately via email

---

**⚠️ Disclaimer**: This tool is intended for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. 