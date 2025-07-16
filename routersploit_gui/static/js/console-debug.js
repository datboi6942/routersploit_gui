// Console Debug Script for RouterSploit GUI

class ConsoleDebugger {
    constructor() {
        this.socket = null;
        this.consoleConnected = false;
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentPrompt = 'rsf > ';
        
        console.log('🔧 Console Debugger initialized');
        this.init();
    }
    
    init() {
        console.log('🚀 Initializing console debugger...');
        
        // Initialize Socket.IO
        this.initSocket();
        
        // Setup console handlers
        this.setupConsoleHandlers();
        
        // Try to connect to console immediately
        setTimeout(() => {
            this.connectConsole();
        }, 1000);
    }
    
    initSocket() {
        try {
            console.log('🔌 Initializing Socket.IO for console...');
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('✅ Socket connected - attempting console connection');
                this.updateConsoleStatus('Socket Connected', 'warning');
                // Try to connect console when socket connects
                setTimeout(() => {
                    this.connectConsole();
                }, 500);
            });
            
            this.socket.on('disconnect', () => {
                console.log('❌ Socket disconnected');
                this.updateConsoleStatus('Disconnected', 'danger');
                this.consoleConnected = false;
                this.enableConsoleInput(false);
            });
            
            // Console-specific event handlers
            this.socket.on('console_connected', (data) => {
                console.log('🎉 Console connected!', data);
                this.consoleConnected = true;
                this.currentPrompt = data.prompt || 'rsf > ';
                this.updateConsoleStatus('Connected', 'success');
                this.updateConsolePrompt(this.currentPrompt);
                this.addConsoleOutput(data.welcome || 'Console connected', 'info');
                this.enableConsoleInput(true);
            });
            
            this.socket.on('console_output', (data) => {
                console.log('📝 Console output:', data);
                this.addConsoleOutput(data.data, data.level || 'info');
            });
            
            this.socket.on('console_prompt', (data) => {
                console.log('📍 Prompt update:', data);
                this.currentPrompt = data.prompt;
                this.updateConsolePrompt(data.prompt);
            });
            
            this.socket.on('console_clear', () => {
                console.log('🧹 Console clear signal received');
                this.clearConsole();
            });
            
            this.socket.on('console_exit', () => {
                console.log('🚪 Console exit signal received');
                this.addConsoleOutput('Console session ended.', 'warning');
                this.enableConsoleInput(false);
                this.updateConsoleStatus('Disconnected', 'secondary');
                this.consoleConnected = false;
            });
            
            console.log('✅ Socket.IO event handlers set up');
            
        } catch (error) {
            console.error('❌ Failed to initialize Socket.IO:', error);
        }
    }
    
    setupConsoleHandlers() {
        console.log('🔧 Setting up console DOM handlers...');
        
        const consoleInput = document.getElementById('consoleInput');
        const consoleSendBtn = document.getElementById('consoleSendBtn');
        const clearConsoleBtn = document.getElementById('clearConsoleBtn');
        
        if (!consoleInput) {
            console.error('❌ Console input element not found!');
            return;
        }
        
        if (!consoleSendBtn) {
            console.error('❌ Console send button not found!');
            return;
        }
        
        if (!clearConsoleBtn) {
            console.error('❌ Clear console button not found!');
            return;
        }
        
        // Input event handlers
        consoleInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                console.log('🔑 Enter key pressed');
                this.sendConsoleCommand();
            }
        });
        
        consoleInput.addEventListener('keydown', (e) => {
            this.handleConsoleKeydown(e);
        });
        
        // Send button
        consoleSendBtn.addEventListener('click', () => {
            console.log('🖱️ Send button clicked');
            this.sendConsoleCommand();
        });
        
        // Clear button
        clearConsoleBtn.addEventListener('click', () => {
            console.log('🧹 Clear button clicked');
            this.clearConsole();
        });
        
        // Tab completion
        consoleInput.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                e.preventDefault();
                this.handleTabCompletion();
            }
        });
        
        console.log('✅ Console DOM handlers set up successfully');
    }
    
    connectConsole() {
        console.log('🔌 Attempting to connect to console...');
        
        if (!this.socket) {
            console.error('❌ No socket available for console connection');
            return;
        }
        
        if (!this.socket.connected) {
            console.error('❌ Socket not connected, cannot connect console');
            return;
        }
        
        console.log('📡 Emitting console_connect event...');
        this.socket.emit('console_connect');
        this.updateConsoleStatus('Connecting...', 'warning');
    }
    
    sendConsoleCommand() {
        const consoleInput = document.getElementById('consoleInput');
        const command = consoleInput.value.trim();
        
        console.log('📤 Sending command:', command);
        
        if (!command) {
            console.log('⚠️ Empty command, not sending');
            return;
        }
        
        if (!this.consoleConnected) {
            console.log('⚠️ Console not connected, cannot send command');
            return;
        }
        
        if (!this.socket || !this.socket.connected) {
            console.log('⚠️ Socket not connected, cannot send command');
            return;
        }
        
        // Add to history
        this.commandHistory.push(command);
        this.historyIndex = this.commandHistory.length;
        
        // Display command in output
        this.addConsoleOutput(`${this.currentPrompt}${command}`, 'command');
        
        // Clear input
        consoleInput.value = '';
        
        // Send to server
        console.log('📡 Emitting console_command event with:', { command });
        this.socket.emit('console_command', { command: command });
    }
    
    handleConsoleKeydown(e) {
        const consoleInput = document.getElementById('consoleInput');
        
        // Command history navigation
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (this.historyIndex > 0) {
                this.historyIndex--;
                consoleInput.value = this.commandHistory[this.historyIndex];
                setTimeout(() => {
                    consoleInput.setSelectionRange(consoleInput.value.length, consoleInput.value.length);
                }, 0);
            }
        } else if (e.key === 'ArrowDown') {
            e.preventDefault();
            if (this.historyIndex < this.commandHistory.length - 1) {
                this.historyIndex++;
                consoleInput.value = this.commandHistory[this.historyIndex];
                setTimeout(() => {
                    consoleInput.setSelectionRange(consoleInput.value.length, consoleInput.value.length);
                }, 0);
            } else if (this.historyIndex === this.commandHistory.length - 1) {
                this.historyIndex = this.commandHistory.length;
                consoleInput.value = '';
            }
        }
    }
    
    handleTabCompletion() {
        const consoleInput = document.getElementById('consoleInput');
        const currentValue = consoleInput.value;
        const cursorPos = consoleInput.selectionStart;
        
        // Basic tab completion
        const commands = ['help', 'show', 'use', 'set', 'unset', 'run', 'exploit', 'back', 'info', 'search', 'sessions', 'session', 'exit', 'clear'];
        const words = currentValue.substr(0, cursorPos).split(' ');
        const currentWord = words[words.length - 1];
        
        if (words.length === 1) {
            const matches = commands.filter(cmd => cmd.startsWith(currentWord));
            if (matches.length === 1) {
                const newValue = currentValue.substring(0, cursorPos - currentWord.length) + matches[0] + currentValue.substring(cursorPos);
                consoleInput.value = newValue;
                const newCursorPos = cursorPos - currentWord.length + matches[0].length;
                consoleInput.setSelectionRange(newCursorPos, newCursorPos);
            } else if (matches.length > 1) {
                this.addConsoleOutput(`Available commands: ${matches.join(', ')}`, 'info');
            }
        }
    }
    
    addConsoleOutput(text, level = 'info') {
        console.log(`📝 Adding console output [${level}]:`, text);
        
        const consoleOutput = document.getElementById('consoleOutput');
        if (!consoleOutput) {
            console.error('❌ Console output element not found!');
            return;
        }
        
        const line = document.createElement('div');
        line.className = `console-line ${level} new-line`;
        
        // Handle special formatting for command lines
        if (level === 'command') {
            const parts = text.split('> ');
            if (parts.length === 2) {
                line.innerHTML = `<span class="prompt-text">${parts[0]}></span> <span class="command-text">${parts[1]}</span>`;
            } else {
                line.textContent = text;
            }
        } else {
            line.textContent = text;
        }
        
        consoleOutput.appendChild(line);
        
        // Animation cleanup
        setTimeout(() => {
            line.classList.remove('new-line');
        }, 300);
        
        // Auto-scroll
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
        
        // Limit lines
        const lines = consoleOutput.querySelectorAll('.console-line');
        if (lines.length > 1000) {
            for (let i = 0; i < lines.length - 1000; i++) {
                lines[i].remove();
            }
        }
    }
    
    clearConsole() {
        console.log('🧹 Clearing console output');
        const consoleOutput = document.getElementById('consoleOutput');
        if (consoleOutput) {
            consoleOutput.innerHTML = '<div class="console-line text-muted">Console cleared</div>';
        }
    }
    
    updateConsolePrompt(prompt) {
        console.log('📍 Updating console prompt to:', prompt);
        const consolePrompt = document.getElementById('consolePrompt');
        if (consolePrompt) {
            consolePrompt.textContent = prompt;
        }
    }
    
    updateConsoleStatus(text, type) {
        console.log(`📊 Updating console status: ${text} (${type})`);
        const statusBadge = document.getElementById('consoleStatus');
        if (statusBadge) {
            statusBadge.innerHTML = `<i class="fas fa-circle"></i> ${text}`;
            statusBadge.className = `badge bg-${type} ms-2`;
            
            if (type === 'warning') {
                statusBadge.classList.add('console-connecting');
            } else {
                statusBadge.classList.remove('console-connecting');
            }
        }
    }
    
    enableConsoleInput(enabled) {
        console.log('🔒 Console input enabled:', enabled);
        const consoleInput = document.getElementById('consoleInput');
        const consoleSendBtn = document.getElementById('consoleSendBtn');
        
        if (consoleInput) {
            consoleInput.disabled = !enabled;
            consoleInput.placeholder = enabled ? 'Enter command...' : 'Console not connected';
        }
        
        if (consoleSendBtn) {
            consoleSendBtn.disabled = !enabled;
        }
        
        // Focus input if enabled
        if (enabled && consoleInput) {
            consoleInput.focus();
        }
    }
    
    // Debug methods
    getStatus() {
        return {
            socketConnected: this.socket ? this.socket.connected : false,
            consoleConnected: this.consoleConnected,
            currentPrompt: this.currentPrompt,
            commandHistory: this.commandHistory.length
        };
    }
    
    testConnection() {
        console.log('🧪 Testing console connection...');
        console.log('Status:', this.getStatus());
        
        if (this.socket && this.socket.connected) {
            this.connectConsole();
        } else {
            console.log('❌ Socket not connected');
        }
    }
}

// Initialize console debugger when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    console.log('🌐 DOM ready - initializing console debugger');
    window.consoleDebugger = new ConsoleDebugger();
});

// Expose debugger globally for testing
if (typeof window !== 'undefined') {
    window.ConsoleDebugger = ConsoleDebugger;
}