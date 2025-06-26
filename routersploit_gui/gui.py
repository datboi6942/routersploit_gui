"""Main GUI application for RouterSploit."""

import json
from typing import Any, Dict, List, Optional, Union

import PySimpleGUI as sg
import structlog

from . import config
from .module_loader import ModuleLoader, ModuleMeta
from .runner import RunnerManager

logger = structlog.get_logger(__name__)


class RouterSploitGUI:
    """Main GUI application for RouterSploit.
    
    Provides a user-friendly interface for discovering, configuring,
    and executing RouterSploit modules.
    """
    
    def __init__(self) -> None:
        """Initialize the RouterSploit GUI."""
        # Set the theme and custom colors
        sg.theme(config.THEME)
        sg.set_options(
            font=config.FONT_MAIN,
            button_color=(sg.theme_text_color(), config.PRIMARY_COLOR),
            progress_meter_color=(config.PRIMARY_COLOR, sg.theme_background_color()),
            border_width=1,
            slider_border_width=0,
            progress_meter_border_depth=0,
        )
        
        # Initialize components
        self.module_loader = ModuleLoader()
        self.runner_manager = RunnerManager()
        self.window: Optional[sg.Window] = None
        self.current_module: Optional[ModuleMeta] = None
        self.active_module_options_key: Optional[str] = None
        self.created_module_layouts: set[str] = set()

        # Load history
        self.target_history: List[str] = self._load_history()
        
        # Initialize GUI
        self._create_window()
        self._populate_module_tree()
        
    def _create_window(self) -> None:
        """Create the main application window with modern styling."""
        # Module tree section
        tree_section = [
            [
                sg.Text(
                    "📋 RouterSploit Modules",
                    font=config.FONT_HEADING,
                    text_color=config.INFO_COLOR,
                    pad=((5, 5), (10, 10))
                )
            ],
            [
                sg.Tree(
                    data=sg.TreeData(),
                    headings=["Description"],
                    key="-MODULE_TREE-",
                    show_expanded=False,
                    enable_events=True,
                    num_rows=30,
                    col0_width=35,
                    col_widths=[50],
                    auto_size_columns=False,
                    expand_x=True,
                    expand_y=True,
                    background_color=sg.theme_background_color(),
                    selected_row_colors=(config.ACCENT_COLOR, sg.theme_text_color()),
                    header_background_color=config.PRIMARY_COLOR,
                    header_text_color="white",
                    font=config.FONT_MAIN,
                    pad=((5, 5), (0, 10))
                )
            ],
        ]
        
        # Module info and options section using a scrollable frame
        module_info_section = [
            [
                sg.Text(
                    "⚙️ Module Configuration",
                    font=config.FONT_HEADING,
                    text_color=config.INFO_COLOR,
                    pad=((5, 5), (10, 5))
                )
            ],
            [
                sg.Text("Select a module from the tree to configure its options", 
                       key="-MODULE_INFO-", 
                       font=config.FONT_MAIN,
                       text_color=config.SECONDARY_COLOR,
                       pad=((10, 10), (5, 10)))
            ],
            # Module details frame
            [
                sg.Frame(
                    "Module Details",
                    [
                        [
                            sg.Text("", key="-MODULE_NAME-", font=config.FONT_HEADING, 
                                   text_color=config.PRIMARY_COLOR, visible=False)
                        ],
                        [
                            sg.Text("", key="-MODULE_PATH-", font=config.FONT_MAIN, 
                                   text_color=config.SECONDARY_COLOR, visible=False)
                        ],
                        [
                            sg.Text("", key="-MODULE_DESC-", font=config.FONT_MAIN, 
                                   text_color=sg.theme_text_color(), visible=False)
                        ],
                    ],
                    key="-MODULE_DETAILS_FRAME-",
                    visible=False,
                    expand_x=True,
                    pad=((5, 5), (5, 10))
                )
            ],
            # Target history frame
            [
                sg.Frame(
                    "Recent Targets",
                    [
                        [
                            sg.Combo(
                                self.target_history,
                                key="-TARGET_HISTORY-",
                                enable_events=True,
                                size=(40, 1),
                                font=config.FONT_MAIN,
                                readonly=False,
                                pad=((5, 5), (5, 5))
                            )
                        ]
                    ],
                    key="-TARGET_FRAME-",
                    visible=False,
                    expand_x=True,
                    pad=((5, 5), (5, 10))
                )
            ],
            # Options frame with a container for dynamic options
            [
                sg.Frame(
                    "Module Options",
                    [
                        [
                            sg.Column(
                                [],
                                key="-OPTIONS_CONTAINER-",
                                expand_x=True,
                                expand_y=True,
                                scrollable=True,
                                vertical_scroll_only=True,
                                size=(None, 200),
                            )
                        ]
                    ],
                    key="-OPTIONS_FRAME-",
                    visible=False,
                    expand_x=True,
                    expand_y=True,
                    pad=((5, 5), (5, 10)),
                )
            ],
            # Text for when there are no options
            [
                sg.Text(
                    "ℹ️ This module has no configurable options.",
                    key="-NO_OPTIONS_TEXT-",
                    font=config.FONT_MAIN,
                    text_color=config.WARNING_COLOR,
                    visible=False,
                    pad=((10, 10), (10, 10)),
                )
            ],
        ]
        
        # Control buttons with modern styling
        control_section = [
            [
                sg.Button(
                    "🚀 Run Module",
                    key="-RUN-",
                    disabled=True,
                    button_color=("white", config.SUCCESS_COLOR),
                    size=config.BUTTON_SIZE,
                    font=config.FONT_MAIN,
                    border_width=0,
                    pad=((5, 10), (5, 5))
                ),
                sg.Button(
                    "⏹️ Stop",
                    key="-STOP-",
                    disabled=True,
                    button_color=("white", config.ERROR_COLOR),
                    size=(8, 1),
                    font=config.FONT_MAIN,
                    border_width=0,
                    pad=((0, 10), (5, 5))
                ),
                sg.Push(),
                sg.Button(
                    "🗑️ Clear Console",
                    key="-CLEAR-",
                    size=config.BUTTON_SIZE,
                    font=config.FONT_MAIN,
                    border_width=0,
                    pad=((5, 5), (5, 5))
                ),
                sg.Button(
                    "💾 Save Output",
                    key="-SAVE-",
                    size=config.BUTTON_SIZE,
                    font=config.FONT_MAIN,
                    border_width=0,
                    pad=((5, 5), (5, 5))
                ),
                sg.Button(
                    "❓ Help",
                    key="-HELP-",
                    size=(8, 1),
                    font=config.FONT_MAIN,
                    border_width=0,
                    pad=((5, 5), (5, 5))
                ),
            ]
        ]
        
        # Console output section
        console_section = [
            [
                sg.Text(
                    "📟 Console Output",
                    font=config.FONT_HEADING,
                    text_color=config.INFO_COLOR,
                    pad=((5, 5), (10, 5))
                )
            ],
            [
                sg.Multiline(
                    size=(120, 12),
                    key="-CONSOLE-",
                    disabled=True,
                    autoscroll=True,
                    background_color="#1e1e1e",
                    text_color="#ffffff",
                    font=config.FONT_MONO,
                    expand_x=True,
                    expand_y=True,
                    border_width=1,
                    pad=((5, 5), (0, 10))
                )
            ]
        ]
        
        # Status bar
        status_section = [
            [
                sg.StatusBar(
                    "🔄 Starting up...",
                    key="-STATUS-",
                    size=(100, 1),
                    expand_x=True,
                    font=config.FONT_MAIN,
                    text_color=config.INFO_COLOR,
                    background_color=sg.theme_background_color(),
                    pad=((5, 5), (5, 5))
                )
            ]
        ]
        
        # Main layout with proper sizing and modern spacing
        layout = [
            [
                sg.Column(
                    tree_section,
                    size=(400, 550),
                    expand_y=True,
                    element_justification="left",
                    pad=((10, 5), (10, 10))
                ),
                sg.VSeparator(pad=((5, 5), (10, 10))),
                sg.Column(
                    module_info_section,
                    expand_x=True,
                    expand_y=True,
                    element_justification="left",
                    scrollable=True,
                    vertical_scroll_only=True,
                    pad=((5, 10), (10, 10))
                ),
            ],
            [sg.HSeparator(pad=((10, 10), (5, 5)))],
            control_section,
            [sg.HSeparator(pad=((10, 10), (5, 5)))],
            console_section,
            status_section,
        ]
        
        self.window = sg.Window(
            f"{config.APP_NAME} v{config.APP_VERSION}",
            layout,
            size=(1400, 900),
            resizable=True,
            finalize=True,
            icon=None,
            element_justification="left",
            margins=(0, 0),
            border_depth=0,
            alpha_channel=0.95,
        )
        
        # Set window icon if available
        try:
            icon_path = config.ASSETS_DIR / "icon.ico"
            if icon_path.exists():
                self.window.set_icon(str(icon_path))
        except Exception:
            pass  # Ignore icon loading errors
        
    def _populate_module_tree(self) -> None:
        """Populate the module tree with discovered modules."""
        try:
            self._update_status("🔍 Discovering RouterSploit modules...")
            modules = self.module_loader.discover_modules()
            tree = self.module_loader.build_tree()
            
            tree_data = sg.TreeData()
            self._build_tree_data(tree_data, tree, "")
            
            self.window["-MODULE_TREE-"].update(values=tree_data)
            self._update_status(f"✅ Ready - {len(modules)} modules loaded")
            
        except Exception as e:
            error_msg = f"❌ Failed to load modules: {str(e)}"
            logger.error("Module discovery failed", error=str(e))
            self._update_status(error_msg)
            self._add_console_output(error_msg, "error")
            
    def _build_tree_data(
        self, tree_data: sg.TreeData, tree: Dict[str, Any], parent_key: str
    ) -> None:
        """Recursively build tree data for PySimpleGUI.
        
        Args:
            tree_data: PySimpleGUI TreeData object
            tree: Nested dictionary of modules
            parent_key: Parent node key for insertion
        """
        for key, value in tree.items():
            node_key = f"{parent_key}/{key}" if parent_key else key
            
            if isinstance(value, ModuleMeta):
                # Leaf node (actual module) with emoji indicators
                icon = "🔧" if value.opts else "📄"
                display_name = f"{icon} {key}"
                tree_data.Insert(
                    parent_key,
                    node_key,
                    display_name,
                    values=[value.description],
                )
            else:
                # Branch node (category) with folder emoji
                display_name = f"📁 {key.title()}"
                tree_data.Insert(
                    parent_key,
                    node_key,
                    display_name,
                    values=[""],
                )
                # Recursively add children
                self._build_tree_data(tree_data, value, node_key)
                
    def _handle_module_selection(self, selected_key: str) -> None:
        """Handle module selection from the tree."""
        try:
            module_meta = self.module_loader.get_module_by_key(selected_key)

            if module_meta:
                self.current_module = module_meta
                # Use a sanitized, unique key for the module's layout column
                module_layout_key = f"-MODULE_LAYOUT_{module_meta.dotted_path.replace('.', '_')}-"

                # Hide the previously active module options column
                if self.active_module_options_key and self.active_module_options_key != module_layout_key:
                    self.window[self.active_module_options_key].update(visible=False)

                # If we've already created the layout for this module, just make it visible
                if module_layout_key in self.created_module_layouts:
                    self.window[module_layout_key].update(visible=True)
                else:
                    # Otherwise, create the layout and add it to the container
                    new_layout = self._create_module_options_layout(module_meta)
                    # The layout is wrapped in a Column which is then added.
                    self.window.extend_layout(self.window['-OPTIONS_CONTAINER-'], [[sg.Column(new_layout, key=module_layout_key)]])
                    self.created_module_layouts.add(module_layout_key)
                
                self.active_module_options_key = module_layout_key

                # Update shared module info panel
                self._update_module_info(module_meta)
                self.window["-RUN-"].update(disabled=False)
                self._update_status(f"📋 Selected: {module_meta.name}")
            else:
                # It's a category, not a module
                self._clear_module_options()
                self.window["-RUN-"].update(disabled=True)
                self.window["-MODULE_INFO-"].update("📂 Category selected - choose a specific module")

        except Exception as e:
            logger.error("Error handling module selection", error=str(e), exc_info=True)
            self._clear_module_options()

    def _create_module_options_layout(self, module_meta: ModuleMeta) -> List[List[sg.Element]]:
        """Creates a layout list for a module's options. Each option is a pinned row."""
        options_layout = []
        for opt_name, opt_info in module_meta.opts.items():
            default_value = opt_info.get("default", "")
            description = opt_info.get("description", "No description available.")
            required = opt_info.get("required", False)
            label_text = f"{'🔴' if required else '🔵'} {opt_name}:"
            # Sanitize keys
            path_key = module_meta.dotted_path.replace('.', '_')
            opt_key = opt_name.replace(' ', '_')
            input_key = f"-OPT_INPUT_{path_key}_{opt_key}-"

            option_row = [
                sg.Text(label_text, size=(20, 1), font=config.FONT_MAIN, text_color=config.PRIMARY_COLOR if not required else config.ERROR_COLOR, tooltip=description),
                sg.Input(str(default_value) if default_value is not None else "", key=input_key, size=(40, 1), font=config.FONT_MAIN, tooltip=description)
            ]
            # Pin each row to maintain its position
            options_layout.append([sg.pin(sg.Column([option_row], pad=(0,0)))])
        return options_layout

    def _update_module_info(self, module_meta: ModuleMeta) -> None:
        """Update the non-option parts of the module info panel."""
        self.window["-MODULE_NAME-"].update(f"🎯 {module_meta.name}", visible=True)
        self.window["-MODULE_PATH-"].update(f"📍 {module_meta.dotted_path}", visible=True)
        self.window["-MODULE_DESC-"].update(f"📝 {module_meta.description}", visible=True)
        self.window["-MODULE_DETAILS_FRAME-"].update(visible=True)

        has_target = any(opt_name.lower() in ["target", "rhost", "host"] for opt_name in module_meta.opts)
        if has_target and self.target_history:
            self.window["-TARGET_FRAME-"].update(visible=True)
        else:
            self.window["-TARGET_FRAME-"].update(visible=False)

        required_count = len([o for o in module_meta.opts.values() if o.get("required", False)])
        info_text = f"Module: {module_meta.name} | Options: {len(module_meta.opts)} | Required: {required_count}"
        self.window["-MODULE_INFO-"].update(info_text)
        
        if not module_meta.opts:
            self.window["-OPTIONS_FRAME-"].update(visible=False)
            self.window["-NO_OPTIONS_TEXT-"].update(visible=True)
        else:
            self.window["-OPTIONS_FRAME-"].update(visible=True)
            self.window["-NO_OPTIONS_TEXT-"].update(visible=False)

    def _clear_module_options(self) -> None:
        """Hide the active module's options and reset info panels."""
        if self.active_module_options_key and self.window:
            if self.window.find_element(self.active_module_options_key, silent_on_error=True):
                self.window[self.active_module_options_key].update(visible=False)
        
        self.active_module_options_key = None
        self.current_module = None

        if self.window:
            self.window["-MODULE_DETAILS_FRAME-"].update(visible=False)
            self.window["-TARGET_FRAME-"].update(visible=False)
            self.window["-OPTIONS_FRAME-"].update(visible=False)
            self.window["-NO_OPTIONS_TEXT-"].update(visible=False)
            self.window["-MODULE_INFO-"].update("Select a module from the tree to configure its options")

    def _handle_run_module(self, values: Dict[str, Any]) -> None:
        """Collect options and start the module execution."""
        if not self.current_module:
            self._add_console_output("❌ No module selected", "error")
            return

        if self.runner_manager.is_running():
            self._add_console_output("⚠️ Another module is already running!", "warning")
            return

        options = {}
        missing_required = []

        for opt_name, opt_info in self.current_module.opts.items():
            path_key = self.current_module.dotted_path.replace('.', '_')
            opt_key = opt_name.replace(' ', '_')
            input_key = f"-OPT_INPUT_{path_key}_{opt_key}-"
            
            value = values.get(input_key, "").strip()

            # Special handling for target history
            if opt_name.lower() in ["target", "rhost", "host"]:
                history_value = values.get("-TARGET_HISTORY-", "").strip()
                if history_value:
                    value = history_value

            if value:
                # Convert value to the correct type based on the stored original value
                try:
                    original_value = opt_info.get("original_value")
                    converted_value = self._convert_option_value(value, original_value)
                    options[opt_name] = converted_value
                except Exception as e:
                    self._add_console_output(f"⚠️ Warning: Could not convert option '{opt_name}' value '{value}': {str(e)}", "warning")
                    options[opt_name] = value  # Fallback to string
            elif opt_info.get("required", False):
                missing_required.append(opt_name)

        if missing_required:
            error_msg = f"❌ Missing required options: {', '.join(missing_required)}"
            self._add_console_output(error_msg, "error")
            sg.popup_error(f"Please fill in the following required options:\n\n- " + "\n- ".join(missing_required), title="Missing Required Options", font=config.FONT_MAIN)
            return
        
        target_value = options.get("target") or options.get("rhost")
        if target_value:
            self._add_to_history(str(target_value))

        # Clear console and start execution
        self.window["-CONSOLE-"].update("")
        self._add_console_output(f"🚀 Starting module: {self.current_module.name}", "info")
        self._add_console_output(f"📋 Options: {json.dumps(options, default=str)}", "info")
        self._update_status(f"🔄 Running: {self.current_module.name}")

        # Update button states
        self.window["-RUN-"].update(disabled=True)
        self.window["-STOP-"].update(disabled=False)

        # Start the runner using the correct method
        success = self.runner_manager.start_module(
            self.current_module,
            options,
            self._add_console_output,
            self._handle_module_complete,
        )

        if not success:
            self._add_console_output("❌ Failed to start module execution", "error")
            self._reset_controls()

    def _convert_option_value(self, user_input: str, original_value: Any) -> Any:
        """Convert user input to the correct data type based on the original module value.
        
        Args:
            user_input: The string value from the GUI input
            original_value: The original value from the module to determine type
            
        Returns:
            Converted value of the correct type or string format RouterSploit expects
        """
        if original_value is None:
            return user_input
            
        # Get the type of the original value
        original_type = type(original_value)
        
        try:
            if original_type == bool:
                # RouterSploit modules expect lowercase string "true"/"false" for boolean options
                # The module's property setter will convert these to actual boolean values
                lower_input = user_input.lower()
                if lower_input in ['true', '1', 'yes', 'on']:
                    return 'true'  # RouterSploit expects lowercase string
                elif lower_input in ['false', '0', 'no', 'off']:
                    return 'false'  # RouterSploit expects lowercase string
                else:
                    # Default to false for any other input
                    return 'false'
            elif original_type == int:
                return int(user_input)
            elif original_type == float:
                return float(user_input)
            elif original_type == str:
                return user_input
            else:
                # For other types, try to convert to string
                return user_input
                
        except (ValueError, TypeError):
            # If conversion fails, return the string value and let the module handle it
            return user_input

    def _handle_stop_module(self) -> None:
        """Handle stopping the current module."""
        self.runner_manager.stop_current()
        self._add_console_output("⏹️ Stop requested...", "warning")
        self._update_status("⏹️ Stopping execution...")
        
    def _handle_module_complete(self, success: bool, error_msg: Optional[str]) -> None:
        """Handle module execution completion.
        
        Args:
            success: Whether the module executed successfully
            error_msg: Error message if execution failed
        """
        if success:
            self._add_console_output("✅ Module execution completed successfully", "success")
            self._update_status("✅ Execution completed successfully")
        else:
            error_text = error_msg or "Module execution failed"
            self._add_console_output(f"❌ {error_text}", "error")
            self._update_status(f"❌ Execution failed: {error_text}")
            
        self._reset_controls()
        
    def _reset_controls(self) -> None:
        """Reset control button states."""
        self.window["-RUN-"].update(disabled=False if self.current_module else True)
        self.window["-STOP-"].update(disabled=True)
        
    def _add_console_output(self, text: str, level: str = "info") -> None:
        """Add text to the console output with color coding.
        
        Args:
            text: Text to add
            level: Output level (info, error, warning, success)
        """
        # Color-code based on level
        color_map = {
            "info": "#ffffff",
            "error": config.ERROR_COLOR,
            "warning": config.WARNING_COLOR,
            "success": config.SUCCESS_COLOR,
        }
        
        color = color_map.get(level, "#ffffff")
        
        # Add timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        formatted_text = f"[{timestamp}] {text}\n"
        
        self.window["-CONSOLE-"].print(formatted_text, text_color=color, end="")
        
    def _update_status(self, message: str) -> None:
        """Update the status bar.
        
        Args:
            message: Status message to display
        """
        self.window["-STATUS-"].update(message)
        
    def _handle_clear_console(self) -> None:
        """Clear the console output."""
        self.window["-CONSOLE-"].update("")
        self._add_console_output("🗑️ Console cleared", "info")
        
    def _handle_save_output(self) -> None:
        """Save console output to a file."""
        output = self.window["-CONSOLE-"].get()
        if not output.strip():
            self._add_console_output("⚠️ No output to save", "warning")
            return
            
        filename = sg.popup_get_file(
            "Save console output as:",
            save_as=True,
            default_extension=".txt",
            file_types=(("Text Files", "*.txt"), ("All Files", "*.*")),
            font=config.FONT_MAIN,
        )
        
        if filename:
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(output)
                self._add_console_output(f"💾 Output saved to: {filename}", "success")
            except Exception as e:
                self._add_console_output(f"❌ Failed to save: {str(e)}", "error")
                
    def _handle_target_history(self, target: str) -> None:
        """Handle target selection from history.
        
        Args:
            target: Selected target
        """
        if self.current_module:
            # Find target-related options and update them
            for opt_name in self.current_module.opts:
                if opt_name.lower() in ["target", "rhost", "host"]:
                    path_key = self.current_module.dotted_path.replace('.', '_')
                    opt_key = opt_name.replace(' ', '_')
                    input_key = f"-OPT_INPUT_{path_key}_{opt_key}-"
                    
                    # Update the input field if it exists
                    element = self.window.find_element(input_key, silent_on_error=True)
                    if element:
                        element.update(target)
                        self._add_console_output(f"🎯 Target set from history: {target}", "info")
                        return
            
            # If no target option found, just log
            self._add_console_output(f"⚠️ No target option found for this module", "warning")

    def _handle_help(self) -> None:
        """Show help dialog."""
        help_text = """
RouterSploit GUI Help

🚀 Getting Started:
1. Select a module from the tree on the left
2. Configure the required options (marked with 🔴)
3. Click 'Run Module' to execute
4. Monitor progress in the console output

🔧 Module Types:
📁 Exploits - Security vulnerability exploits
📁 Scanners - Network and service scanners  
📁 Creds - Credential testing modules
📁 Payloads - Exploit payloads

💡 Tips:
• Use the target history dropdown for quick access
• Required options are marked with red indicators
• Save console output for later analysis
• Use the stop button to interrupt long-running modules

⚠️ Disclaimer:
Only use this tool on networks and systems you own or have explicit permission to test.
        """
        
        sg.popup_scrolled(
            help_text,
            title="RouterSploit GUI Help",
            size=(60, 20),
            font=config.FONT_MAIN,
        )
        
    def _load_history(self) -> List[str]:
        """Load target history from file.
        
        Returns:
            List of historical targets
        """
        try:
            if config.HISTORY_FILE.exists():
                with open(config.HISTORY_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception as e:
            logger.debug("Failed to load history", error=str(e))
        return []
        
    def _save_history(self) -> None:
        """Save target history to file."""
        try:
            with open(config.HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(self.target_history[-20:], f)  # Keep last 20 entries
        except Exception as e:
            logger.debug("Failed to save history", error=str(e))
            
    def _add_to_history(self, target: str) -> None:
        """Add a target to the history.
        
        Args:
            target: Target to add
        """
        if target and target not in self.target_history:
            self.target_history.append(target)
            self._save_history()
            # Update the dropdown if visible
            if self.window["-TARGET_FRAME-"].visible:
                self.window["-TARGET_HISTORY-"].update(values=self.target_history)
            
    def run(self) -> None:
        """Main application event loop."""
        if not self.window:
            logger.error("Window not created")
            return

        self._add_console_output(f"🎉 {config.APP_NAME} v{config.APP_VERSION} started successfully!", "success")
        self._add_console_output("👈 Select a module from the tree to get started", "info")

        try:
            while True:
                try:
                    event, values = self.window.read(timeout=100)
                    
                    if event == sg.WIN_CLOSED:
                        break
                    if event == "-MODULE_TREE-" and values["-MODULE_TREE-"]:
                        self._handle_module_selection(values["-MODULE_TREE-"][0])
                    elif event == "-RUN-":
                        self._handle_run_module(values)
                    elif event == "-STOP-":
                        self._handle_stop_module()
                    elif event == "-CLEAR-":
                        self._handle_clear_console()
                    elif event == "-SAVE-":
                        self._handle_save_output()
                    elif event == "-HELP-":
                        self._handle_help()
                    elif event == "-TARGET_HISTORY-":
                        if values["-TARGET_HISTORY-"]:
                            self._handle_target_history(values["-TARGET_HISTORY-"])
                            
                    # Update runner status
                    self.runner_manager.update()
                    
                except KeyboardInterrupt:
                    self._add_console_output("🛑 Interrupted by user", "warning")
                    break
                except Exception as e:
                    logger.error("GUI error", error=str(e))
                    self._add_console_output(f"❌ GUI Error: {str(e)}", "error")
                    # Continue the loop, don't exit on individual errors
                    
        finally:
            # Cleanup only when the main loop actually exits
            self._cleanup()

    def _cleanup(self) -> None:
        """Clean up resources."""
        try:
            self.runner_manager.cleanup()
            self._save_history()
            if self.window:
                self.window.close()
        except Exception as e:
            logger.debug("Cleanup error", error=str(e))


def main() -> None:
    """Main entry point for the GUI application."""
    try:
        app = RouterSploitGUI()
        app.run()
    except Exception as e:
        logger.error("Application startup failed", error=str(e))
        sg.popup_error(
            "Startup Error",
            f"Failed to start RouterSploit GUI:\n\n{str(e)}",
            font=("Segoe UI", 10),
        )


if __name__ == "__main__":
    main() 