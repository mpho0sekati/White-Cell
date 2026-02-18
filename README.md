# White Cell

A conversational cybersecurity CLI assistant with a beautiful terminal interface powered by Rich.

## Features

- **Interactive CLI Shell**: Built with Rich for elegant terminal formatting
- **Modular Architecture**: Easy to extend with detection and command modes
- **Cybersecurity Focused**: Designed for security professionals and learners
- **Python 3.10+ Compatible**: Modern Python practices throughout

## Installation

### Prerequisites

- Python 3.10 or higher
- pip (Python package manager)

### Setup

1. Clone or download the White Cell project:
   ```bash
   cd whitecell_project
   ```

2. Create a virtual environment (recommended):
   ```bash
   python -m venv venv
   
   # On Windows:
   venv\Scripts\activate
   
   # On macOS/Linux:
   source venv/bin/activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the CLI from the project root:

```bash
python main.py
```

### Commands

- **exit**: Quit the application
- **help**: Display available commands
- **Any other text**: Send input to the engine for processing (currently echoes input)

### Example Session

```
━━━━━━━━━━━━━━━━━━━━━━ White Cell - Cybersecurity Assistant ━━━━━━━━━━━━━━━━━━━━━━
White Cell
A conversational cybersecurity CLI

Type "exit" to quit, "help" for commands

> help
Command            Description
────────────────   ──────────────────────────────────────────────
exit               Exit the application
help               Show this help message
(any text)         Send input to the engine for processing

> what is SQL injection?
You said: what is SQL injection?

> exit
Goodbye!
```

## Project Structure

```
whitecell_project/
├── whitecell/
│   ├── __init__.py       # Package initialization and metadata
│   ├── cli.py            # Interactive CLI shell using Rich
│   ├── engine.py         # Core processing engine
├── main.py               # Application entry point
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Module Overview

### `whitecell/__init__.py`
Package initialization with metadata and version information.

### `whitecell/engine.py`
Core processing module with:
- `handle_input(user_input)`: Process user input and return responses
- `parse_command(user_input)`: Parse input into command and arguments (for future modular commands)

### `whitecell/cli.py`
Interactive CLI interface with:
- `WhiteCellCLI`: Main CLI class managing the event loop
- Rich-formatted prompts, banners, and output
- Command handling (exit, help, input processing)

### `main.py`
Entry point that initializes and runs the CLI.

## Architecture & Extensibility

The project is designed with modularity in mind:

1. **Engine Module**: The `engine.py` module can be extended to:
   - Add cybersecurity detection modes
   - Implement command routing and processing
   - Integrate external APIs or ML models
   - Add context-aware responses

2. **CLI Module**: The `WhiteCellCLI` class can be extended to:
   - Add new command handlers
   - Implement different UI modes
   - Add session management and history
   - Support configuration options

3. **Separation of Concerns**: CLI and engine logic are separate, allowing:
   - Easy testing of the engine
   - Alternative interfaces (web, API)
   - Integration into larger systems

## Development

To extend White Cell:

1. Add new functions to `engine.py` for processing
2. Add command handlers to `WhiteCellCLI.process_input()` for new CLI commands
3. Update `parse_command()` for more complex command parsing
4. Create new modules in `whitecell/` as needed

## Requirements

- **rich**: Terminal formatting and user interface library

Install all requirements with:
```bash
pip install -r requirements.txt
```

## License

Open source - use and modify as needed.

## Author

White Cell Team
