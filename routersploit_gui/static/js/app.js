// RouterSploit GUI JavaScript

class RouterSploitGUI {
    constructor() {
        this.socket = null;
        this.currentModule = null;
        this.modules = {};
        this.moduleTree = {};
        this.isRunning = false;
        this.selectedPayload = null;
        this.initialized = false;
        
        // Console state
        this.consoleConnected = false;
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentPrompt = 'rsf > ';
        
        // Effects integration (optional)
        this.effectsManager = null;
        
        console.log('🚀 RouterSploit GUI constructor called');
        this.init();
    }
    
    init() {
        console.log('🔧 Starting RouterSploit GUI initialization...');
        
        // Initialize immediately without waiting for effects
        this.initializeCore();
        
        // Try to get effects manager, but don't wait for it
        if (window.effectsManager) {
            this.effectsManager = window.effectsManager;
            console.log('✅ Effects manager found and linked');
        } else {
            console.log('⚠️ Effects manager not available, continuing without effects');
        }
    }

    initializeCore() {
        try {
            console.log('🔧 Initializing core functionality...');
            
            // Test basic DOM access first
            this.testDOMAccess();
            
            // Initialize Socket.IO connection
            this.initializeSocket();
            
            // Setup event handlers for all buttons
            this.setupAllEventHandlers();
            
            // Load modules
            this.loadModules();
            
            // Initialize console
            this.initializeConsole();
            
            // Mark as initialized
            this.initialized = true;
            console.log('✅ Core functionality initialized successfully');
            
        } catch (error) {
            console.error('❌ Failed to initialize core functionality:', error);
            this.showCriticalError('Failed to initialize application: ' + error.message);
        }
    }
    
    testDOMAccess() {
        console.log('🧪 Testing DOM access...');
        
        const elements = {
            'startAutoOwnBtn': document.getElementById('startAutoOwnBtn'),
            'autoOwnTarget': document.getElementById('autoOwnTarget'),
            'openaiApiKey': document.getElementById('openaiApiKey'),
            'saveApiKeyBtn': document.getElementById('saveApiKeyBtn'),
            'exploitDbApiKey': document.getElementById('exploitDbApiKey'),
            'saveExploitDbKeyBtn': document.getElementById('saveExploitDbKeyBtn'),
            'moduleTree': document.getElementById('moduleTree'),
            'runBtn': document.getElementById('runBtn'),
            'statusBadge': document.getElementById('statusBadge'),
            'moduleInfo': document.getElementById('moduleInfo'),
            'noModuleSelected': document.getElementById('noModuleSelected')
        };
        
        console.log('🔍 Element availability:', elements);
        
        let missing = [];
        for (const [name, element] of Object.entries(elements)) {
            if (!element) {
                missing.push(name);
            }
        }
        
        if (missing.length > 0) {
            console.warn('⚠️ Missing elements:', missing);
        } else {
            console.log('✅ All required elements found');
        }
    }

    initializeSocket() {
        try {
            console.log('🔌 Initializing Socket.IO connection...');
            this.socket = io();
            this.setupSocketHandlers();
            console.log('✅ Socket.IO initialized');
        } catch (error) {
            console.error('❌ Failed to initialize Socket.IO:', error);
        }
    }

    setupAllEventHandlers() {
        console.log('🔧 Setting up all event handlers...');
        
        // Core button handlers (with null checks)
        this.setupCoreButtons();
        
        // Console event handlers
        this.setupConsoleEventHandlers();
        
        // Auto-Own event handlers  
        this.setupAutoOwnEventHandlers();
        
        // Tab change handlers
        this.setupTabHandlers();
        
        console.log('✅ All event handlers set up');
    }

    setupCoreButtons() {
        console.log('🔧 Setting up core buttons...');
        
        // Stop button
        const stopBtn = document.getElementById('stopBtn');
        if (stopBtn) {
            stopBtn.addEventListener('click', () => {
                console.log('🛑 Stop button clicked');
                this.stopExecution();
            });
            console.log('✅ Stop button handler added');
        } else {
            console.warn('⚠️ Stop button not found');
        }

        // Clear output button
        const clearOutputBtn = document.getElementById('clearOutputBtn');
        if (clearOutputBtn) {
            clearOutputBtn.addEventListener('click', () => {
                console.log('🧹 Clear output button clicked');
                this.clearOutput();
            });
            console.log('✅ Clear output button handler added');
        } else {
            console.warn('⚠️ Clear output button not found');
        }

        // Run button
        const runBtn = document.getElementById('runBtn');
        if (runBtn) {
            runBtn.addEventListener('click', () => {
                console.log('▶️ Run button clicked');
                this.runModule();
            });
            console.log('✅ Run button handler added');
        } else {
            console.warn('⚠️ Run button not found');
        }

        // Apply target button
        const applyTargetBtn = document.getElementById('applyTargetBtn');
        if (applyTargetBtn) {
            applyTargetBtn.addEventListener('click', () => {
                console.log('🎯 Apply target button clicked');
                this.applyQuickTarget();
            });
            console.log('✅ Apply target button handler added');
        } else {
            console.warn('⚠️ Apply target button not found');
        }

        // Payload selection
        const payloadSelect = document.getElementById('payloadSelect');
        if (payloadSelect) {
            payloadSelect.addEventListener('change', (e) => {
                console.log('📦 Payload selected:', e.target.value);
                this.onPayloadSelect(e.target.value);
            });
            console.log('✅ Payload select handler added');
        } else {
            console.warn('⚠️ Payload select not found');
        }

        // Quick target input (Enter key)
        const quickTarget = document.getElementById('quickTarget');
        if (quickTarget) {
            quickTarget.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    console.log('⚡ Quick target Enter key pressed');
                    this.applyQuickTarget();
                }
            });
            console.log('✅ Quick target input handler added');
        } else {
            console.warn('⚠️ Quick target input not found');
        }
    }

    setupTabHandlers() {
        console.log('🔧 Setting up tab handlers...');
        
        const consoleTab = document.getElementById('console-tab');
        if (consoleTab) {
            consoleTab.addEventListener('shown.bs.tab', () => {
                console.log('📟 Console tab shown');
                this.onConsoleTabShown();
            });
            console.log('✅ Console tab handler added');
        }

        const autoOwnTab = document.getElementById('auto-own-tab');
        if (autoOwnTab) {
            autoOwnTab.addEventListener('shown.bs.tab', () => {
                console.log('🤖 Auto-own tab shown');
                this.onAutoOwnTabShown();
            });
            console.log('✅ Auto-own tab handler added');
        }

        const customScriptsTab = document.getElementById('custom-scripts-tab');
        if (customScriptsTab) {
            customScriptsTab.addEventListener('shown.bs.tab', () => {
                console.log('📝 Custom scripts tab shown');
                this.onCustomScriptsTabShown();
            });
            console.log('✅ Custom scripts tab handler added');
        }
    }

    showCriticalError(message) {
        console.error('💥 Critical Error:', message);
        
        // Try to show error in UI
        const errorContainer = document.createElement('div');
        errorContainer.className = 'alert alert-danger position-fixed top-0 start-0 w-100';
        errorContainer.style.zIndex = '9999';
        errorContainer.innerHTML = `
            <h4>🚨 Application Error</h4>
            <p>${message}</p>
            <p><small>Check browser console for details. Try refreshing the page.</small></p>
        `;
        document.body.insertBefore(errorContainer, document.body.firstChild);
    }
    
    setupSocketHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.updateStatus('Connected', 'success');
            
            // CONSOLE FIX: Enable console input immediately when socket connects
            console.log('🔧 Enabling console input after socket connection');
            this.enableConsoleInput(true);
            this.updateConsoleStatus('Connected', 'success');
            
            // Try to connect to console
            if (this.socket && this.socket.connected) {
                console.log('🔌 Requesting console connection...');
                this.socket.emit('console_connect', {});
            }
            
            if (this.effectsManager) {
                this.effectsManager.updateStatus('Connected', 'success');
                this.effectsManager.playSound('success');
            }
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.updateStatus('Disconnected', 'danger');
            this.updateConsoleStatus('Disconnected', 'danger');
            this.consoleConnected = false;
            if (this.effectsManager) {
                this.effectsManager.updateStatus('Disconnected', 'danger');
                this.effectsManager.playSound('error');
            }
        });
        
        this.socket.on('output', (data) => {
            this.addOutput(data.line, data.level);
            
            // Also send to custom scripts output if a custom script is running
            if (this.currentModule && this.currentModule.startsWith('custom_scripts.')) {
                this.addScriptOutput(data.line, data.level);
            }
            
            if (this.effectsManager) {
                this.effectsManager.addConsoleOutput(data.line, data.level);
            }
        });
        
        this.socket.on('complete', (data) => {
            this.onExecutionComplete(data.success, data.error);
            if (this.effectsManager) {
                if (data.success) {
                    this.effectsManager.playSound('success');
                    this.effectsManager.updateStatus('Execution Complete', 'success');
                } else {
                    this.effectsManager.playSound('error');
                    this.effectsManager.updateStatus('Execution Failed', 'danger');
                }
            }
        });
        
        this.socket.on('status', (data) => {
            this.isRunning = data.running;
            this.updateUI();
        });
        
        // --- START CONSOLE EVENT HANDLER REPLACEMENT ---
        // Replacing old handlers with more robust ones from console-debug.js

        this.socket.on('console_connected', (data) => {
            console.log('🎉 Console connected!', data);
            this.consoleConnected = true;
            this.currentPrompt = data.prompt || 'rsf > ';
            this.updateConsoleStatus('Connected', 'success');
            this.updateConsolePrompt(this.currentPrompt);
            this.addConsoleOutput(data.welcome || 'Console connected successfully!', 'success');
            this.enableConsoleInput(true);
        });
        
        this.socket.on('console_output', (data) => {
            this.addConsoleOutput(data.data, data.level || 'info');
        });
        
        this.socket.on('console_prompt', (data) => {
            this.currentPrompt = data.prompt;
            this.updateConsolePrompt(data.prompt);
        });
        
        this.socket.on('console_clear', () => {
            this.clearConsole();
        });
        
        this.socket.on('console_exit', () => {
            this.addConsoleOutput('Console session ended.', 'warning');
            this.enableConsoleInput(false);
            this.updateConsoleStatus('Disconnected', 'secondary');
            this.consoleConnected = false;
        });
        // --- END CONSOLE EVENT HANDLER REPLACEMENT ---
        
        // Auto-Own event handlers
        this.socket.on('auto_own_output', (data) => {
            this.addAutoOwnOutput(data.line, data.level);
        });
        
        this.socket.on('auto_own_complete', (data) => {
            this.onAutoOwnComplete(data.success, data.error);
        });
        
        this.socket.on('auto_own_progress', (data) => {
            this.updateAutoOwnProgress(data.status, data.percentage);
        });
        
        // RCE Session event handlers
        this.socket.on('session_created', (data) => {
            this.onSessionCreated(data);
        });
        
        this.socket.on('session_connected', (data) => {
            this.onSessionConnected(data);
        });
        
        this.socket.on('session_output', (data) => {
            this.onSessionOutput(data);
        });
        
        this.socket.on('session_error', (data) => {
            this.onSessionError(data);
        });
    }
    
    setupConsoleEventHandlers() {
        console.log('🔧 Setting up console event handlers...');
        
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
        
        console.log('✅ All console elements found');
        
        // Console input handling
        consoleInput.addEventListener('keydown', (e) => {
            this.handleConsoleKeydown(e);
        });
        
        consoleInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                console.log('🔑 Enter key pressed in console');
                this.sendConsoleCommand();
            }
        });
        
        // Send button
        consoleSendBtn.addEventListener('click', () => {
            console.log('🖱️ Console send button clicked');
            this.sendConsoleCommand();
        });
        
        // Clear console button
        clearConsoleBtn.addEventListener('click', () => {
            console.log('🧹 Clear console button clicked');
            this.clearConsole();
        });
        
        // Tab completion (basic implementation)
        consoleInput.addEventListener('keydown', (e) => {
            if (e.key === 'Tab') {
                e.preventDefault();
                this.handleTabCompletion();
            }
        });
        
        console.log('✅ Console event handlers set up successfully');
    }
    
    // --- START CONSOLE INITIALIZATION REPLACEMENT ---
    // Replacing complex retry logic with a more direct approach
    initializeConsole() {
        console.log('🔧 Initializing console...');
        this.updateConsoleStatus('Connecting...', 'warning');
        
        // CONSOLE FIX: Enable console input by default during initialization
        console.log('🔧 Enabling console input by default during initialization');
        this.enableConsoleInput(true);
        
        // Connection will be attempted when the socket connects or the tab is shown.
        // This avoids race conditions.
        if (this.socket && this.socket.connected) {
            this.connectConsole();
        }
    }

    connectConsole() {
        if (this.socket && this.socket.connected) {
            if (!this.consoleConnected) {
                console.log('📡 Emitting console_connect event...');
                this.socket.emit('console_connect');
            } else {
                console.log('✅ Console is already connected.');
            }
        } else {
            console.error('❌ Cannot connect console: socket not available.');
            this.updateConsoleStatus('Socket Down', 'danger');
        }
    }
    // --- END CONSOLE INITIALIZATION REPLACEMENT ---

    onConsoleTabShown() {
        console.log('📟 Console tab shown');
        
        // When console tab is shown, ensure we're connected
        this.connectConsole();
        
        // Focus the console input
        const consoleInput = document.getElementById('consoleInput');
        if (consoleInput && !consoleInput.disabled) {
            consoleInput.focus();
        } else {
             // If input is still disabled after a moment, it means connection failed.
             // Enable it for offline mode.
            setTimeout(() => {
                if (consoleInput && consoleInput.disabled) {
                    console.warn('⚠️ Console not connected, enabling input for offline mode.');
                    this.enableConsoleInput(true);
                    this.updateConsoleStatus('Offline Mode', 'warning');
                    this.addConsoleOutput('Backend not connected. Limited offline commands available.', 'warning');
                }
            }, 2000);
        }
    }
    
    sendConsoleCommand() {
        const consoleInput = document.getElementById('consoleInput');
        const command = consoleInput.value.trim();
        
        if (!command) {
            return;
        }
        
        // Add command to history
        this.commandHistory.push(command);
        this.historyIndex = this.commandHistory.length;
        
        // Display the command in the output
        this.addConsoleOutput(`${this.currentPrompt}${command}`, 'command');
        
        // Clear input
        consoleInput.value = '';
        
        if (this.consoleConnected && this.socket && this.socket.connected) {
            // Send command to server if connected
            console.log('📡 Sending command to backend:', command);
            this.socket.emit('console_command', { command: command });
        } else {
            // Handle command locally if backend is down
            console.log('⚠️ Backend not available, handling command locally:', command);
            this.handleOfflineCommand(command);
        }
    }
    
    handleOfflineCommand(command) {
        let response = '';
        
        switch(command.toLowerCase()) {
            case 'help':
                response = `RouterSploit Console (Offline Mode)
                
Available commands:
- help          Show this help
- status        Show console status
- clear         Clear console output
- history       Show command history
- test          Test console functionality

Note: Backend connection failed. Only basic commands available.
To fix this, restart the RouterSploit application.`;
                break;
                
            case 'status':
                response = `Console Status (Offline Mode):
- Backend connection: ❌ FAILED
- Frontend: ✅ Working
- Commands in history: ${this.commandHistory.length}
- Socket.IO connected: ${this.socket && this.socket.connected ? '✅ Yes' : '❌ No'}

The RouterSploit backend appears to be down or misconfigured.`;
                break;
                
            case 'clear':
                this.clearConsole();
                return;
                
            case 'history':
                if (this.commandHistory.length > 0) {
                    response = `Command History (last 10):
${this.commandHistory.slice(-10).map((cmd, i) => `${i + 1}. ${cmd}`).join('\n')}`;
                } else {
                    response = 'No commands in history.';
                }
                break;
                
            case 'test':
                response = `🧪 Console Test Results:
✅ Frontend JavaScript: Working
✅ Console input: Functional  
✅ Command processing: Local mode
✅ Command history: Working
❌ Backend connection: Failed
❌ RouterSploit modules: Not available

The console frontend is working, but backend connection failed.`;
                break;
                
            default:
                response = `Command "${command}" not recognized in offline mode.
The RouterSploit backend is not available.
Type 'help' for available offline commands.`;
        }
        
        // Add response to output
        setTimeout(() => {
            this.addConsoleOutput(response, 'info');
        }, 100);
    }
    
    handleConsoleKeydown(e) {
        const consoleInput = document.getElementById('consoleInput');
        
        // Command history navigation
        if (e.key === 'ArrowUp') {
            e.preventDefault();
            if (this.historyIndex > 0) {
                this.historyIndex--;
                consoleInput.value = this.commandHistory[this.historyIndex];
                // Move cursor to end
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
        
        // Basic tab completion for common commands
        const commands = ['help', 'show', 'use', 'set', 'unset', 'run', 'exploit', 'back', 'info', 'search', 'sessions', 'session', 'exit', 'clear'];
        const words = currentValue.substr(0, cursorPos).split(' ');
        const currentWord = words[words.length - 1];
        
        if (words.length === 1) {
            // Complete command
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
        const consoleOutput = document.getElementById('consoleOutput');
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
            // Convert line breaks and handle ANSI codes if any
            line.textContent = text;
        }
        
        consoleOutput.appendChild(line);
        
        // Remove animation class after animation completes
        setTimeout(() => {
            line.classList.remove('new-line');
        }, 300);
        
        // Auto-scroll to bottom
        consoleOutput.scrollTop = consoleOutput.scrollHeight;
        
        // Limit output lines to prevent memory issues (keep last 1000 lines)
        const lines = consoleOutput.querySelectorAll('.console-line');
        if (lines.length > 1000) {
            for (let i = 0; i < lines.length - 1000; i++) {
                lines[i].remove();
            }
        }
    }
    
    clearConsole() {
        const consoleOutput = document.getElementById('consoleOutput');
        consoleOutput.innerHTML = '<div class="console-line text-muted">Console cleared</div>';
    }
    
    updateConsoleStatus(text, type) {
        const statusBadge = document.getElementById('consoleStatus');
        statusBadge.innerHTML = `<i class="fas fa-circle"></i> ${text}`;
        statusBadge.className = `badge bg-${type}`;
        
        if (type === 'warning') {
            statusBadge.classList.add('console-connecting');
        } else {
            statusBadge.classList.remove('console-connecting');
        }
    }
    
    updateConsolePrompt(prompt) {
        const consolePrompt = document.getElementById('consolePrompt');
        consolePrompt.textContent = prompt;
    }
    
    enableConsoleInput(enabled) {
        const consoleInput = document.getElementById('consoleInput');
        const consoleSendBtn = document.getElementById('consoleSendBtn');
        
        consoleInput.disabled = !enabled;
        consoleSendBtn.disabled = !enabled;
        
        if (enabled) {
            consoleInput.placeholder = 'Enter command...';
        } else {
            consoleInput.placeholder = 'Console not connected';
        }
    }
    
    async loadModules() {
        try {
            console.log('📚 Loading modules from API...');
            
            // Show loading indicator
            const treeContainer = document.getElementById('moduleTree');
            if (treeContainer) {
                treeContainer.innerHTML = `
                    <div class="text-center p-3">
                        <div class="spinner-border text-primary" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <p class="mt-2">Loading modules...</p>
                    </div>
                `;
            }
            
            if (this.effectsManager) {
                this.effectsManager.startScanning();
                this.effectsManager.updateStatus('Scanning modules...', 'info');
            }
            
            const response = await fetch('/api/modules');
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('📊 Received module data from API:', {
                count: data.count,
                hasTree: !!data.tree,
                hasModules: !!data.modules,
                treeKeys: data.tree ? Object.keys(data.tree) : []
            });
            
            this.moduleTree = data.tree;
            this.modules = data.modules;
            
            console.log('🌳 About to render module tree...');
            this.renderModuleTree();
            this.updateModuleCount(data.count);
            
            console.log('✅ Module tree rendering completed successfully');
            
            if (this.effectsManager) {
                this.effectsManager.playSound('success');
                this.effectsManager.updateStatus(`${data.count} modules loaded`, 'success');
            }
            
        } catch (error) {
            console.error('❌ Failed to load modules:', error);
            this.showError('Failed to load modules: ' + error.message);
            
            if (this.effectsManager) {
                this.effectsManager.playSound('error');
                this.effectsManager.updateStatus('Module loading failed', 'danger');
            }
            
            // Show detailed error in tree container
            const treeContainer = document.getElementById('moduleTree');
            if (treeContainer) {
                treeContainer.innerHTML = `
                    <div class="text-center p-3 text-danger">
                        <i class="fas fa-exclamation-triangle fa-2x mb-3"></i>
                        <h5>Failed to Load Modules</h5>
                        <p><strong>Error:</strong> ${error.message}</p>
                        <button class="btn btn-warning btn-sm" onclick="window.routerSploitGUI.loadModules()">
                            <i class="fas fa-redo"></i> Retry
                        </button>
                    </div>
                `;
            }
        }
    }
    
    renderModuleTree() {
        const treeContainer = document.getElementById('moduleTree');
        if (!treeContainer) {
            console.error('❌ Module tree container not found!');
            return;
        }
        
        treeContainer.innerHTML = '';
        
        console.log('🌳 Rendering module tree structure:', {
            hasTree: !!this.moduleTree,
            treeType: typeof this.moduleTree,
            topLevelKeys: this.moduleTree ? Object.keys(this.moduleTree) : []
        });
        
        if (!this.moduleTree || Object.keys(this.moduleTree).length === 0) {
            treeContainer.innerHTML = `
                <div class="text-center p-3 text-warning">
                    <i class="fas fa-info-circle fa-2x mb-3"></i>
                    <p>No modules found</p>
                </div>
            `;
            return;
        }
        
        try {
            // Handle the nested structure returned by the API
            // The API returns { creds: {...}, exploits: {...}, etc. } at the top level
            this.renderTreeNode(this.moduleTree, treeContainer, '', 0);
            
            console.log('✅ Module tree rendered successfully');
            
            // Initialize search functionality
            this.initializeSearch();
            
        } catch (error) {
            console.error('❌ Error rendering module tree:', error);
            treeContainer.innerHTML = `
                <div class="text-center p-3 text-danger">
                    <i class="fas fa-exclamation-triangle fa-2x mb-3"></i>
                    <p>Error rendering module tree</p>
                    <small>${error.message}</small>
                </div>
            `;
        }
    }
    
    renderTreeNode(node, container, parentPath, depth = 0) {
        if (!node || typeof node !== 'object') {
            console.warn(`⚠️ Invalid node at depth ${depth}:`, node);
            return;
        }
        
        console.log(`🔄 Rendering tree node at depth ${depth}, parentPath: "${parentPath}"`);
        console.log(`📊 Node contains ${Object.keys(node).length} items`);
        
        for (const [key, value] of Object.entries(node)) {
            const path = parentPath ? `${parentPath}.${key}` : key;
            
            console.log(`🔍 Processing "${key}" of type ${typeof value}`);
            
            if (value && typeof value === 'object') {
                if (value.dotted_path && value.name) {
                    // This is a direct module (leaf node)
                    console.log(`📦 Rendering module: ${value.name} (${value.dotted_path})`);
                    this.renderModule(value, container, depth);
                } else if (value.modules || value.categories || Object.keys(value).some(k => typeof value[k] === 'object')) {
                    // This is a category with modules and/or subcategories
                    const moduleCount = value.modules ? value.modules.length : 0;
                    const categoryCount = value.categories ? Object.keys(value.categories).length : 0;
                    const subObjectCount = Object.keys(value).filter(k => typeof value[k] === 'object' && k !== 'modules' && k !== 'categories').length;
                    
                    console.log(`📁 Rendering category: "${key}" with ${moduleCount} modules, ${categoryCount} categories, ${subObjectCount} sub-objects`);
                    this.renderCategory(key, value, container, path, depth);
                } else {
                    console.log(`❓ Unknown object structure for "${key}":`, Object.keys(value));
                }
            } else {
                console.log(`⏭️ Skipping non-object "${key}": ${typeof value}`);
            }
        }
    }
    
    renderModule(module, container, depth) {
        const moduleDiv = document.createElement('div');
        moduleDiv.className = 'tree-node module';
        moduleDiv.dataset.modulePath = module.dotted_path;
        moduleDiv.style.paddingLeft = `${(depth + 1) * 20}px`;
        
        const categoryBadge = this.getCategoryBadge(module.category);
        
        moduleDiv.innerHTML = `
            <div class="module-name">
                ${module.name}
                ${categoryBadge}
            </div>
            <small class="module-description">${module.description}</small>
        `;
        
        moduleDiv.addEventListener('click', () => {
            this.selectModule(module.dotted_path);
        });
        
        container.appendChild(moduleDiv);
    }
    
    renderCategory(key, categoryData, container, path, depth) {
        // Count all items in this category
        const moduleCount = (categoryData.modules ? categoryData.modules.length : 0);
        const categoryCount = (categoryData.categories ? Object.keys(categoryData.categories).length : 0);
        
        // Count sub-objects that might be categories or modules
        const subObjectCount = Object.keys(categoryData).filter(k => 
            typeof categoryData[k] === 'object' && 
            k !== 'modules' && 
            k !== 'categories'
        ).length;
        
        const totalCount = moduleCount + categoryCount + subObjectCount;
        
        console.log(`📁 Creating category "${key}" with ${moduleCount} direct modules, ${categoryCount} subcategories, ${subObjectCount} sub-objects (total: ${totalCount})`);
        
        // Create a unique ID for this category
        const categoryId = `category-${path.replace(/\./g, '-')}-${Math.random().toString(36).substr(2, 9)}`;
        
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'tree-node category';
        categoryDiv.style.paddingLeft = `${depth * 20}px`;
        
        // Capitalize category name for display
        const displayName = key.charAt(0).toUpperCase() + key.slice(1).replace(/_/g, ' ');
        
        categoryDiv.innerHTML = `
            <span class="tree-toggle" data-target="${categoryId}">
                <i class="fas fa-chevron-right"></i>
            </span>
            <i class="fas fa-folder text-warning"></i> ${displayName}
            <span class="badge bg-secondary ms-2">${totalCount}</span>
        `;
        
        // Create container for child elements
        const childContainer = document.createElement('div');
        childContainer.className = 'tree-children';
        childContainer.id = categoryId;
        childContainer.style.display = 'none';
        
        // Add click handler for toggle
        const toggleElement = categoryDiv.querySelector('.tree-toggle');
        if (toggleElement) {
            toggleElement.addEventListener('click', (e) => {
                e.stopPropagation();
                this.toggleCategory(categoryId, toggleElement);
            });
        }
        
        container.appendChild(categoryDiv);
        container.appendChild(childContainer);
        
        // Add direct modules if any
        if (categoryData.modules && categoryData.modules.length > 0) {
            console.log(`📦 Adding ${categoryData.modules.length} direct modules to category "${key}"`);
            categoryData.modules.forEach((module, index) => {
                console.log(`📦 Module ${index + 1}: ${module.name || module.dotted_path}`);
                this.renderModule(module, childContainer, depth + 1);
            });
        }
        
        // Add subcategories if any
        if (categoryData.categories && Object.keys(categoryData.categories).length > 0) {
            console.log(`📁 Recursing into ${Object.keys(categoryData.categories).length} subcategories for "${key}"`);
            this.renderTreeNode(categoryData.categories, childContainer, path, depth + 1);
        }
        
        // Handle other object properties that might be categories or modules
        Object.keys(categoryData).forEach(subKey => {
            if (subKey !== 'modules' && subKey !== 'categories' && typeof categoryData[subKey] === 'object') {
                console.log(`🔄 Processing sub-object "${subKey}" in category "${key}"`);
                this.renderTreeNode({[subKey]: categoryData[subKey]}, childContainer, path, depth + 1);
            }
        });
    }
    
    toggleCategory(categoryId, toggleElement) {
        console.log(`🔄 Toggle category: ${categoryId}`);
        
        const container = document.getElementById(categoryId);
        const chevron = toggleElement.querySelector('i');
        const categoryNode = toggleElement.closest('.tree-node.category');
        
        if (!container) {
            console.warn(`⚠️ Category container not found: ${categoryId}`);
            return;
        }
        
        if (container.style.display === 'none') {
            // Expand
            console.log(`📁 Expanding category: ${categoryId}`);
            container.style.display = 'block';
            chevron.className = 'fas fa-chevron-down';
            categoryNode.classList.add('expanded');
        } else {
            // Collapse
            console.log(`📁 Collapsing category: ${categoryId}`);
            container.style.display = 'none';
            chevron.className = 'fas fa-chevron-right';
            categoryNode.classList.remove('expanded');
        }
        
        console.log(`✅ Category toggle completed for: ${categoryId}`);
    }
    
    getCategoryBadge(category) {
        const badges = {
            'exploits': '<span class="module-type-badge module-type-exploit">EXPLOIT</span>',
            'scanners': '<span class="module-type-badge module-type-scanner">SCANNER</span>',
            'creds': '<span class="module-type-badge module-type-creds">CREDS</span>',
            'generic': '<span class="module-type-badge module-type-generic">GENERIC</span>',
            'payloads': '<span class="module-type-badge module-type-payload">PAYLOAD</span>'
        };
        return badges[category] || '';
    }
    
    async selectModule(modulePath) {
        try {
            // Update UI selection
            document.querySelectorAll('.tree-node.module').forEach(node => {
                node.classList.remove('selected');
            });
            
            const selectedNode = document.querySelector(`[data-module-path="${modulePath}"]`);
            if (selectedNode) {
                selectedNode.classList.add('selected');
            }
            
            // Load module details
            const response = await fetch(`/api/module/${encodeURIComponent(modulePath)}`);
            const module = await response.json();
            
            if (response.ok) {
                this.currentModule = module;
                this.renderModuleDetails(module);
            } else {
                this.showError(module.error || 'Failed to load module');
            }
            
        } catch (error) {
            console.error('Failed to select module:', error);
            this.showError('Failed to load module details');
        }
    }
    
    renderModuleDetails(module) {
        // Show module info section
        document.getElementById('noModuleSelected').classList.add('d-none');
        document.getElementById('moduleInfo').classList.remove('d-none');
        
        // Update module details
        document.getElementById('moduleName').textContent = module.name;
        document.getElementById('modulePath').textContent = module.path;
        document.getElementById('moduleDescription').textContent = module.description;
        
        // Update CVE information
        console.log('Module object received:', module);
        console.log('CVE list from module:', module.cve_list);
        this.renderCVEInfo(module.cve_list || []);
        
        // Render module options
        this.renderModuleOptions(module.options);
        
        // Handle payload section for exploits
        if (module.is_exploit && module.payloads.length > 0) {
            this.renderPayloadSection(module.payloads);
        } else {
            document.getElementById('payloadSection').classList.add('d-none');
        }
        
        // Enable run button if module is selected
        this.updateUI();
    }
    
    renderCVEInfo(cveList) {
        console.log('renderCVEInfo called with:', cveList);
        console.log('CVE Array Length:', cveList ? cveList.length : 'undefined');
        const cveContainer = document.getElementById('cveInfo');
        if (!cveContainer) {
            console.warn('CVE container not found');
            return;
        }
        
        if (!cveList || cveList.length === 0) {
            console.log('No CVEs to display, hiding container');
            cveContainer.style.display = 'none';
            return;
        } else {
            console.log('CVEs found! Showing container with CVEs:', cveList);
        }
        
        console.log('Displaying CVEs:', cveList);
        cveContainer.style.display = 'block';
        
        const cveContent = cveList.map(cve => {
            // Create clickable CVE links to CVE details
            const cveUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`;
            const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cve}`;
            
            return `
                <div class="cve-item">
                    <span class="cve-badge">${cve}</span>
                    <div class="cve-links">
                        <a href="${cveUrl}" target="_blank" class="cve-link" title="View CVE details on MITRE">MITRE</a>
                        <a href="${nvdUrl}" target="_blank" class="cve-link" title="View CVE details on NVD">NVD</a>
                    </div>
                </div>
            `;
        }).join('');
        
        document.getElementById('cveList').innerHTML = cveContent;
        console.log('CVE HTML content set:', cveContent);
        console.log('CVE container display style:', cveContainer.style.display);
    }
    
    renderModuleOptions(options) {
        const container = document.getElementById('moduleOptions');
        container.innerHTML = '';
        
        if (!options || Object.keys(options).length === 0) {
            container.innerHTML = '<p class="text-muted">No configurable options</p>';
            return;
        }
        
        for (const [optName, optInfo] of Object.entries(options)) {
            const optionDiv = this.createOptionInput(optName, optInfo, 'module');
            container.appendChild(optionDiv);
        }
    }
    
    renderPayloadSection(payloads) {
        const payloadSection = document.getElementById('payloadSection');
        const payloadSelect = document.getElementById('payloadSelect');
        
        // Clear existing options
        payloadSelect.innerHTML = '<option value="">Select a payload...</option>';
        
        // Add payload options
        payloads.forEach(payload => {
            const option = document.createElement('option');
            option.value = payload.path;
            option.textContent = payload.name;
            payloadSelect.appendChild(option);
        });
        
        // Show payload section
        payloadSection.classList.remove('d-none');
        
        // Clear payload options
        document.getElementById('payloadOptions').innerHTML = '';
    }
    
    onPayloadSelect(payloadPath) {
        if (!payloadPath) {
            document.getElementById('payloadOptions').innerHTML = '';
            this.selectedPayload = null;
            return;
        }
        
        // Find the selected payload
        const payload = this.currentModule.payloads.find(p => p.path === payloadPath);
        if (payload) {
            this.selectedPayload = payload;
            this.renderPayloadOptions(payload.options);
        }
    }
    
    renderPayloadOptions(options) {
        const container = document.getElementById('payloadOptions');
        container.innerHTML = '';
        
        if (!options || Object.keys(options).length === 0) {
            container.innerHTML = '<p class="text-muted">No configurable payload options</p>';
            return;
        }
        
        for (const [optName, optInfo] of Object.entries(options)) {
            const optionDiv = this.createOptionInput(optName, optInfo, 'payload');
            container.appendChild(optionDiv);
        }
    }
    
    createOptionInput(optName, optInfo, prefix) {
        const div = document.createElement('div');
        div.className = `option-group ${optInfo.required ? 'required' : ''}`;
        
        const inputId = `${prefix}_${optName}`;
        const currentValue = optInfo.current_value !== undefined ? optInfo.current_value : '';
        const optionType = optInfo.option_type || 'text';
        
        let inputElement = '';
        
        // Handle dropdown choices (encoder, output format, etc.)
        if (optInfo.choices && Array.isArray(optInfo.choices)) {
            inputElement = `
                <select class="form-select option-input" id="${inputId}" ${optInfo.required ? 'required' : ''}>
                    ${optInfo.choices.map(choice => 
                        `<option value="${choice}" ${choice === currentValue ? 'selected' : ''}>${choice || '(none)'}</option>`
                    ).join('')}
                </select>
            `;
        } else if (optionType === 'boolean') {
            const checked = currentValue === true || currentValue === 'True' || currentValue === 'true' ? 'checked' : '';
            inputElement = `
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="${inputId}" ${checked}>
                    <label class="form-check-label" for="${inputId}">
                        ${optInfo.description || 'Enable this option'}
                    </label>
                </div>
            `;
        } else if (optionType === 'port' || optionType === 'integer') {
            const minValue = optInfo.min_value ? `min="${optInfo.min_value}"` : '';
            const maxValue = optInfo.max_value ? `max="${optInfo.max_value}"` : '';
            inputElement = `
                <input type="number" class="form-control option-input" id="${inputId}" 
                       value="${currentValue}" placeholder="${optInfo.description || ''}"
                       ${minValue} ${maxValue} ${optInfo.required ? 'required' : ''}>
            `;
        } else if (optionType === 'file') {
            inputElement = `
                <div class="input-group">
                    <input type="text" class="form-control option-input" id="${inputId}" 
                           value="${currentValue}" placeholder="${optInfo.description || 'Enter file path'}"
                           ${optInfo.required ? 'required' : ''}>
                    <button class="btn btn-outline-secondary" type="button" onclick="this.previousElementSibling.click()">
                        <i class="fas fa-folder-open"></i>
                    </button>
                </div>
            `;
        } else {
            // Text input (default)
            const placeholder = optInfo.type_hint === 'hostname' ? 'Enter hostname or IP address' : 
                               (optInfo.description || '');
            inputElement = `
                <input type="text" class="form-control option-input" id="${inputId}" 
                       value="${currentValue}" placeholder="${placeholder}"
                       ${optInfo.required ? 'required' : ''}>
            `;
        }
        
        const typeBadge = this.getTypeBadge(optionType, optInfo.choices);
        
        div.innerHTML = `
            <div class="option-label ${optInfo.required ? 'required' : ''}">
                ${optName}
                ${typeBadge}
            </div>
            ${optInfo.description ? `<div class="option-description">${optInfo.description}</div>` : ''}
            ${inputElement}
        `;
        
        return div;
    }
    
    getTypeBadge(optionType, choices) {
        const badges = {
            'text': '<span class="badge bg-info option-type-badge">TEXT</span>',
            'port': '<span class="badge bg-warning option-type-badge">PORT</span>',
            'integer': '<span class="badge bg-warning option-type-badge">INT</span>',
            'boolean': '<span class="badge bg-success option-type-badge">BOOL</span>',
            'file': '<span class="badge bg-secondary option-type-badge">FILE</span>',
            'choice': '<span class="badge bg-primary option-type-badge">CHOICE</span>'
        };
        
        // If choices are available, show choice badge
        if (choices && Array.isArray(choices) && choices.length > 0) {
            return badges['choice'] || '';
        }
        
        return badges[optionType] || '';
    }
    
    applyQuickTarget() {
        const targetValue = document.getElementById('quickTarget').value.trim();
        if (!targetValue) return;
        
        // Apply to all target-related fields
        const targetFields = ['target', 'rhost', 'host'];
        targetFields.forEach(fieldName => {
            const input = document.getElementById(`module_${fieldName}`) || 
                         document.getElementById(`payload_${fieldName}`);
            if (input) {
                input.value = targetValue;
            }
        });
        
        this.showSuccess(`Applied target "${targetValue}" to relevant fields`);
    }
    
    async runModule() {
        if (!this.currentModule || this.isRunning) return;
        
        try {
            // Collect module options
            const moduleOptions = this.collectOptions('module');
            
            // Collect payload options if selected
            let payloadOptions = {};
            let payloadPath = '';
            
            if (this.selectedPayload) {
                payloadOptions = this.collectOptions('payload');
                payloadPath = this.selectedPayload.path;
            }
            
            // Validate required fields
            if (!this.validateOptions(moduleOptions, this.currentModule.options)) {
                return;
            }
            
            // Send execution request
            const response = await fetch('/api/run', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    module_path: this.currentModule.path,
                    options: moduleOptions,
                    payload_path: payloadPath,
                    payload_options: payloadOptions
                }),
            });
            
            const result = await response.json();
            
            if (response.ok) {
                this.isRunning = true;
                this.updateUI();
                this.updateStatus('Running', 'success');
                this.addOutput(`Starting ${this.currentModule.name}...`, 'info');
                
                if (this.effectsManager) {
                    this.effectsManager.showLoading('Executing module...');
                    this.effectsManager.playSound('scan');
                    this.effectsManager.updateStatus('Executing module...', 'info');
                }
            } else {
                this.showError(result.error || 'Failed to start module');
                if (this.effectsManager) {
                    this.effectsManager.playSound('error');
                    this.effectsManager.updateStatus('Module execution failed', 'danger');
                }
            }
            
        } catch (error) {
            console.error('Failed to run module:', error);
            this.showError('Failed to start module execution');
            if (this.effectsManager) {
                this.effectsManager.playSound('error');
                this.effectsManager.updateStatus('Module execution failed', 'danger');
            }
        }
    }
    
    collectOptions(prefix) {
        const options = {};
        const inputs = document.querySelectorAll(`[id^="${prefix}_"]`);
        
        inputs.forEach(input => {
            const optionName = input.id.replace(`${prefix}_`, '');
            
            if (input.type === 'checkbox') {
                options[optionName] = input.checked;
            } else {
                options[optionName] = input.value;
            }
        });
        
        return options;
    }
    
    validateOptions(options, optionSpecs) {
        for (const [optName, optInfo] of Object.entries(optionSpecs)) {
            if (optInfo.required && (!options[optName] || options[optName].toString().trim() === '')) {
                this.showError(`Required field "${optName}" is empty`);
                return false;
            }
        }
        return true;
    }
    
    async stopExecution() {
        try {
            const response = await fetch('/api/stop', {
                method: 'POST',
            });
            
            if (response.ok) {
                this.addOutput('Stopping execution...', 'warning');
            }
        } catch (error) {
            console.error('Failed to stop execution:', error);
        }
    }
    
    onExecutionComplete(success, error) {
        this.isRunning = false;
        this.updateUI();
        
        if (this.effectsManager) {
            this.effectsManager.hideLoading();
        }
        
        if (success) {
            this.updateStatus('Complete', 'success');
            this.addOutput('Module execution completed successfully', 'success');
            if (this.effectsManager) {
                this.effectsManager.updateStatus('Execution completed', 'success');
                this.effectsManager.playSound('success');
            }
        } else {
            this.updateStatus('Error', 'danger');
            this.addOutput(`Module execution failed: ${error || 'Unknown error'}`, 'error');
            if (this.effectsManager) {
                this.effectsManager.updateStatus('Execution failed', 'danger');
                this.effectsManager.playSound('error');
            }
        }
    }
    
    addOutput(line, level) {
        const container = document.getElementById('outputContainer');
        const outputLine = document.createElement('div');
        outputLine.className = `output-line ${level}`;
        outputLine.textContent = line;
        
        container.appendChild(outputLine);
        container.scrollTop = container.scrollHeight;
    }
    
    clearOutput() {
        const container = document.getElementById('outputContainer');
        container.innerHTML = '<div class="output-line text-muted">Output cleared...</div>';
    }
    
    updateStatus(text, type) {
        const badge = document.getElementById('statusBadge');
        badge.className = `badge bg-${type}`;
        badge.innerHTML = `<i class="fas fa-circle"></i> ${text}`;
        
        if (type === 'success' && this.isRunning) {
            badge.classList.add('running');
        } else {
            badge.classList.remove('running');
        }
    }
    
    updateUI() {
        const runBtn = document.getElementById('runBtn');
        const stopBtn = document.getElementById('stopBtn');
        
        if (this.isRunning) {
            runBtn.disabled = true;
            stopBtn.disabled = false;
        } else {
            runBtn.disabled = !this.currentModule;
            stopBtn.disabled = true;
        }
    }
    
    updateModuleCount(count) {
        document.getElementById('moduleCount').textContent = count;
    }
    
    showError(message) {
        this.showToast(message, 'danger');
    }
    
    showSuccess(message) {
        this.showToast(message, 'success');
    }
    
    showToast(message, type) {
        // Simple alert for now - could be enhanced with proper toast notifications
        console.log(`${type.toUpperCase()}: ${message}`);
        
        // Add to output as well
        this.addOutput(message, type === 'danger' ? 'error' : 'info');
    }
    
    // Add search functionality
    initializeSearch() {
        // Check if search box already exists
        if (document.getElementById('moduleSearchInput')) {
            console.log('Search box already exists, skipping initialization');
            return;
        }
        
        console.log('Initializing search functionality');
        const searchInput = document.createElement('div');
        searchInput.className = 'module-search position-relative mb-3';
        searchInput.innerHTML = `
            <i class="fas fa-search search-icon"></i>
            <input type="text" class="form-control" id="moduleSearchInput" 
                   placeholder="Search modules..." autocomplete="off">
        `;
        
        const treeContainer = document.getElementById('moduleTree');
        treeContainer.parentNode.insertBefore(searchInput, treeContainer);
        
        const input = document.getElementById('moduleSearchInput');
        let searchTimeout;
        
        input.addEventListener('input', (e) => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                this.filterModules(e.target.value.toLowerCase());
            }, 300);
        });
        
        console.log('Search functionality initialized');
    }
    
    filterModules(searchTerm) {
        const allNodes = document.querySelectorAll('.tree-node');
        const allContainers = document.querySelectorAll('.tree-children');
        
        if (!searchTerm) {
            // Show all nodes and reset to collapsed state
            allNodes.forEach(node => {
                node.style.display = 'block';
                if (node.classList.contains('category')) {
                    node.classList.remove('expanded');
                    const chevron = node.querySelector('.tree-toggle i');
                    if (chevron) {
                        chevron.className = 'fas fa-chevron-right';
                    }
                }
            });
            allContainers.forEach(container => {
                container.style.display = 'none';
            });
            return;
        }
        
        // Hide all nodes first
        allNodes.forEach(node => node.style.display = 'none');
        allContainers.forEach(container => container.style.display = 'none');
        
        // Show matching modules and their parent categories
        const moduleNodes = document.querySelectorAll('.tree-node.module');
        const matchingModules = Array.from(moduleNodes).filter(node => {
            const moduleName = node.querySelector('.module-name').textContent.toLowerCase();
            const moduleDesc = node.querySelector('.module-description').textContent.toLowerCase();
            return moduleName.includes(searchTerm) || moduleDesc.includes(searchTerm);
        });
        
        matchingModules.forEach(moduleNode => {
            moduleNode.style.display = 'block';
            
            // Show parent containers and categories
            let parent = moduleNode.parentElement;
            while (parent && parent.id !== 'moduleTree') {
                if (parent.classList.contains('tree-children')) {
                    parent.style.display = 'block';
                    
                    // Find and show the corresponding category
                    const categoryId = parent.id;
                    const categoryNode = document.querySelector(`[data-target="${categoryId}"]`)?.closest('.tree-node.category');
                    if (categoryNode) {
                        categoryNode.style.display = 'block';
                        categoryNode.classList.add('expanded');
                        const chevron = categoryNode.querySelector('.tree-toggle i');
                        if (chevron) {
                            chevron.className = 'fas fa-chevron-down';
                        }
                    }
                }
                parent = parent.parentElement;
            }
        });
    }
    
    // Auto-Own Methods
    setupAutoOwnEventHandlers() {
        console.log('Setting up Auto-Own event handlers...');
        
        // Use a timeout to ensure DOM is fully loaded
        setTimeout(() => {
            const startAutoOwnBtn = document.getElementById('startAutoOwnBtn');
            const stopAutoOwnBtn = document.getElementById('stopAutoOwnBtn');
            const clearAutoOwnBtn = document.getElementById('clearAutoOwnBtn');
            const targetHistorySelect = document.getElementById('targetHistorySelect');
            const saveApiKeyBtn = document.getElementById('saveApiKeyBtn');
            const openaiApiKeyInput = document.getElementById('openaiApiKey');

            console.log('Auto-Own elements found:', {
                startAutoOwnBtn: !!startAutoOwnBtn,
                stopAutoOwnBtn: !!stopAutoOwnBtn,
                clearAutoOwnBtn: !!clearAutoOwnBtn,
                targetHistorySelect: !!targetHistorySelect,
                saveApiKeyBtn: !!saveApiKeyBtn,
                openaiApiKeyInput: !!openaiApiKeyInput
            });

            // Check if elements exist before adding event listeners
            if (!startAutoOwnBtn) {
                console.error('startAutoOwnBtn element not found');
                return;
            }

            // Start auto-own button
            startAutoOwnBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                console.log('Start Auto-Own button clicked');
                this.startAutoOwn();
            });

            // Also add event listener for Enter key on target input
            const targetInput = document.getElementById('autoOwnTarget');
            if (targetInput) {
                targetInput.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        console.log('Enter key pressed in target input');
                        this.startAutoOwn();
                    }
                });
            }

            // Stop auto-own button
            if (stopAutoOwnBtn) {
                stopAutoOwnBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.stopAutoOwn();
                });
            }

            // Clear auto-own output button
            if (clearAutoOwnBtn) {
                clearAutoOwnBtn.addEventListener('click', (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    this.clearAutoOwnOutput();
                });
            }

            // Save API key button
            if (saveApiKeyBtn) {
                saveApiKeyBtn.addEventListener('click', async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    try {
                        const apiKey = openaiApiKeyInput.value.trim();
                        if (!apiKey) {
                            this.showError('Please enter a valid OpenAI API key');
                            return;
                        }
                        
                        // Show saving state
                        saveApiKeyBtn.disabled = true;
                        saveApiKeyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
                        
                        // Send to backend to save in file (where Python reads from)
                        const response = await fetch('/api/auto-own/set-api-key', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                api_key: apiKey
                            })
                        });
                        
                        const result = await response.json();
                        
                        if (response.ok && result.status === 'success') {
                            // Also save to localStorage as backup
                            localStorage.setItem('openai_api_key', apiKey);
                            
                            this.showSuccess('API key saved successfully to backend!');
                            console.log('API key saved to backend file and localStorage');
                            
                            // Clear the input field for security
                            openaiApiKeyInput.value = '';
                            
                        } else {
                            throw new Error(result.error || 'Failed to save API key to backend');
                        }
                        
                    } catch (error) {
                        console.error('Error saving API key:', error);
                        this.showError('Failed to save API key: ' + error.message);
                    } finally {
                        // Restore button state
                        saveApiKeyBtn.disabled = false;
                        saveApiKeyBtn.innerHTML = '<i class="fas fa-save"></i> Save';
                    }
                });
            }

            // Save ExploitDB API key button
            const saveExploitDbKeyBtn = elements.saveExploitDbKeyBtn;
            const exploitDbApiKeyInput = elements.exploitDbApiKey;
            
            if (saveExploitDbKeyBtn && exploitDbApiKeyInput) {
                saveExploitDbKeyBtn.addEventListener('click', async (e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    
                    try {
                        const apiKey = exploitDbApiKeyInput.value.trim();
                        
                        // Show saving state
                        saveExploitDbKeyBtn.disabled = true;
                        saveExploitDbKeyBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
                        
                        // Send to backend to save ExploitDB API key
                        const response = await fetch('/api/auto-own/set-exploitdb-key', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                api_key: apiKey || '' // Allow empty string to clear key
                            })
                        });
                        
                        const result = await response.json();
                        
                        if (response.ok && result.status === 'success') {
                            // Also save to localStorage as backup
                            if (apiKey) {
                                localStorage.setItem('exploitdb_api_key', apiKey);
                                this.showSuccess('ExploitDB API key saved successfully!');
                            } else {
                                localStorage.removeItem('exploitdb_api_key');
                                this.showSuccess('ExploitDB API key cleared - ExploitDB will be skipped');
                            }
                            
                            console.log('ExploitDB API key saved to backend and localStorage');
                            
                            // Clear the input field for security
                            exploitDbApiKeyInput.value = '';
                            
                        } else {
                            throw new Error(result.error || 'Failed to save ExploitDB API key');
                        }
                        
                    } catch (error) {
                        console.error('Error saving ExploitDB API key:', error);
                        this.showError('Failed to save ExploitDB API key: ' + error.message);
                    } finally {
                        // Restore button state
                        saveExploitDbKeyBtn.disabled = false;
                        saveExploitDbKeyBtn.innerHTML = '<i class="fas fa-save"></i> Save';
                    }
                });
            }

            // Target history select
            if (targetHistorySelect) {
                targetHistorySelect.addEventListener('change', (e) => {
                    const selectedTarget = e.target.value;
                    if (selectedTarget) {
                        const targetInput = document.getElementById('autoOwnTarget');
                        if (targetInput) {
                            targetInput.value = selectedTarget;
                        }
                    }
                });
            }

            // Load saved API key
            const savedApiKey = localStorage.getItem('openai_api_key');
            if (savedApiKey && openaiApiKeyInput) {
                openaiApiKeyInput.value = savedApiKey;
            }

            // Load target history
            this.loadAutoOwnTargets();
            
            console.log('Auto-Own event handlers setup completed');
        }, 100);
    }
    
    onAutoOwnTabShown() {
        // Load target history when auto-own tab is shown
        this.loadAutoOwnTargets();
    }
    
    async loadAutoOwnTargets() {
        try {
            const targets = JSON.parse(localStorage.getItem('auto_own_targets') || '[]');
            
            const select = document.getElementById('targetHistorySelect');
            if (select) {
                select.innerHTML = '<option value="">Select from history...</option>';
                
                targets.forEach(target => {
                    const option = document.createElement('option');
                    option.value = target;
                    option.textContent = target;
                    select.appendChild(option);
                });
            }
        } catch (error) {
            console.error('Failed to load auto-own targets:', error);
        }
    }
    
    async startAutoOwn() {
        console.log('🚀 startAutoOwn method called');
        
        // Get all required elements
        const targetInput = document.getElementById('autoOwnTarget');
        const verboseCheckbox = document.getElementById('autoOwnVerbose');
        const debugCheckbox = document.getElementById('autoOwnDebug');
        const startBtn = document.getElementById('startAutoOwnBtn');
        
        console.log('Elements found:', {
            targetInput: !!targetInput,
            verboseCheckbox: !!verboseCheckbox,
            debugCheckbox: !!debugCheckbox,
            startBtn: !!startBtn
        });
        
        if (!targetInput) {
            console.error('❌ autoOwnTarget input not found');
            this.showError('Auto-Own target input not found');
            return;
        }
        
        const target = targetInput.value.trim();
        const isVerbose = verboseCheckbox ? verboseCheckbox.checked : false;
        const isDebug = debugCheckbox ? debugCheckbox.checked : false;
        
        console.log(`📊 Auto-Own parameters: target="${target}", verbose=${isVerbose}, debug=${isDebug}`);

        if (!target) {
            console.warn('⚠️ No target specified');
            this.showError("Please enter a target IP address or hostname.");
            return;
        }

        // Validate target format (basic check)
        const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
        const hostnamePattern = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
        
        if (!ipPattern.test(target) && !hostnamePattern.test(target)) {
            console.warn('⚠️ Invalid target format');
            this.showError("Please enter a valid IP address or hostname.");
            return;
        }
        
        // Disable start button to prevent multiple clicks
        if (startBtn) {
            startBtn.disabled = true;
            startBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
        }
        
        // Clear and setup output
        this.clearAutoOwnOutput();
        this.addAutoOwnOutput(`🎯 Starting Auto-Own process for target: ${target}`, 'info');
        
        if (isVerbose) {
            this.addAutoOwnOutput(`📢 Verbose mode enabled - showing detailed output`, 'info');
        }
        
        if (isDebug) {
            this.addAutoOwnOutput(`🐛 Debug mode enabled - showing internal agent operations`, 'warning');
        }
        
        // Show progress and update UI
        this.enableAutoOwnControls(true);
        this.showAutoOwnProgress();
        this.updateAutoOwnProgress('Initializing Auto-Own Agent', 10);

        try {
            console.log('📡 Sending start request to server...');
            
            const response = await fetch('/api/auto-own/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, verbose: isVerbose, debug: isDebug }),
            });

            console.log('📡 Server response status:', response.status);

            if (!response.ok) {
                throw new Error(`Server returned ${response.status}: ${response.statusText}`);
            }

            const result = await response.json();
            console.log('📡 Server response data:', result);

            if (result.success !== false) {
                console.log('✅ Auto-Own process started successfully');
                this.showSuccess('Auto-Own process started successfully');
                this.updateAutoOwnStatus('Running', 'warning');
                this.updateAutoOwnProgress('Auto-Own Agent Running', 20);
                
                // Save target to history
                this.saveAutoOwnTarget(target);
                
                // Start polling for updates
                this.startAutoOwnPolling();
            } else {
                throw new Error(result.error || 'Unknown error from server');
            }
        } catch (error) {
            console.error('❌ Failed to start auto-own:', error);
            this.showError(`Failed to start Auto-Own process: ${error.message}`);
            this.updateAutoOwnStatus('Error', 'danger');
            this.hideAutoOwnProgress();
            this.enableAutoOwnControls(false);
        } finally {
            // Re-enable start button
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.innerHTML = '<i class="fas fa-play"></i> Start Auto-Own';
            }
        }
    }
    
    saveAutoOwnTarget(target) {
        try {
            let targets = JSON.parse(localStorage.getItem('auto_own_targets') || '[]');
            if (!targets.includes(target)) {
                targets.unshift(target);
                // Keep only last 10 targets
                targets = targets.slice(0, 10);
                localStorage.setItem('auto_own_targets', JSON.stringify(targets));
                this.loadAutoOwnTargets();
            }
        } catch (error) {
            console.error('Failed to save target to history:', error);
        }
    }
    
    startAutoOwnPolling() {
        if (this.autoOwnPollingInterval) {
            clearInterval(this.autoOwnPollingInterval);
        }
        
        this.autoOwnPollingInterval = setInterval(async () => {
            try {
                const response = await fetch('/api/auto-own/status');
                const data = await response.json();
                
                if (data.status === 'completed') {
                    this.updateAutoOwnStatus('Completed', 'success');
                    this.updateAutoOwnProgress('Auto-Own Completed', 100);
                    this.enableAutoOwnControls(false);
                    clearInterval(this.autoOwnPollingInterval);
                } else if (data.status === 'error') {
                    this.updateAutoOwnStatus('Error', 'danger');
                    this.enableAutoOwnControls(false);
                    clearInterval(this.autoOwnPollingInterval);
                } else if (data.status === 'running') {
                    this.updateAutoOwnProgress(data.current_step || 'Processing', data.progress || 20);
                }
                
                // Update output if there's new data
                if (data.output) {
                    this.addAutoOwnOutput(data.output, 'info');
                }
            } catch (error) {
                console.error('Error polling auto-own status:', error);
            }
        }, 2000); // Poll every 2 seconds
    }
    
    updateAutoOwnStatus(status, variant) {
        const statusElement = document.getElementById('autoOwnStatus');
        if (statusElement) {
            statusElement.textContent = status;
            statusElement.className = `badge bg-${variant}`;
        }
    }
    
    updateAutoOwnProgress(message, percentage) {
        const progressBar = document.getElementById('autoOwnProgressBar');
        const progressText = document.getElementById('autoOwnProgressText');
        
        if (progressBar) {
            progressBar.style.width = `${percentage}%`;
            progressBar.setAttribute('aria-valuenow', percentage);
        }
        
        if (progressText) {
            progressText.textContent = message;
        }
    }
    
    showAutoOwnProgress() {
        const progressContainer = document.getElementById('autoOwnProgress');
        if (progressContainer) {
            progressContainer.style.display = 'block';
        }
    }
    
    hideAutoOwnProgress() {
        const progressContainer = document.getElementById('autoOwnProgress');
        if (progressContainer) {
            progressContainer.style.display = 'none';
        }
    }
    
    enableAutoOwnControls(running) {
        const startBtn = document.getElementById('startAutoOwnBtn');
        const stopBtn = document.getElementById('stopAutoOwnBtn');
        
        if (startBtn) {
            startBtn.disabled = running;
        }
        
        if (stopBtn) {
            stopBtn.disabled = !running;
        }
    }
    
    async stopAutoOwn() {
        try {
            const response = await fetch('/api/auto-own/stop', {
                method: 'POST'
            });
            
            const data = await response.json();
            
            if (response.ok) {
                this.showSuccess('Auto-Own process stopped');
                this.updateAutoOwnStatus('Stopped', 'secondary');
                this.enableAutoOwnControls(false);
                this.hideAutoOwnProgress();
            } else {
                this.showError(data.error || 'Failed to stop Auto-Own process');
            }
        } catch (error) {
            console.error('Failed to stop auto-own:', error);
            this.showError('Failed to stop Auto-Own process');
        }
    }
    
    addAutoOwnOutput(line, level) {
        const outputContainer = document.getElementById('autoOwnOutput');
        const outputLine = document.createElement('div');
        outputLine.className = `auto-own-line mb-1`;
        
        // Add timestamp
        const timestamp = new Date().toLocaleTimeString();
        const timestampSpan = document.createElement('span');
        timestampSpan.className = 'text-muted me-2';
        timestampSpan.textContent = `[${timestamp}]`;
        outputLine.appendChild(timestampSpan);
        
        // Add content with appropriate styling
        const contentSpan = document.createElement('span');
        contentSpan.textContent = line;
        
        switch (level) {
            case 'success':
                contentSpan.className = 'text-success';
                break;
            case 'error':
                contentSpan.className = 'text-danger';
                break;
            case 'warning':
                contentSpan.className = 'text-warning';
                break;
            case 'info':
                contentSpan.className = 'text-info';
                break;
            default:
                contentSpan.className = 'text-dark';
        }
        
        outputLine.appendChild(contentSpan);
        outputContainer.appendChild(outputLine);
        
        // Auto-scroll to bottom
        outputContainer.scrollTop = outputContainer.scrollHeight;
    }
    
    clearAutoOwnOutput() {
        const outputContainer = document.getElementById('autoOwnOutput');
        outputContainer.innerHTML = `
            <div class="text-muted">
                <i class="fas fa-robot"></i> Auto-Own AI Agent Ready<br>
                <small>Enter a target IP address and click "Start Auto-Own" to begin automated vulnerability assessment and exploitation.</small>
            </div>
        `;
    }
    
    onAutoOwnComplete(success, error) {
        if (success) {
            this.addAutoOwnOutput('Auto-Own process completed successfully!', 'success');
            this.updateAutoOwnStatus('Completed', 'success');
        } else {
            this.addAutoOwnOutput(`Auto-Own process failed: ${error}`, 'error');
            this.updateAutoOwnStatus('Failed', 'danger');
        }
        
        this.enableAutoOwnControls(false);
        this.hideAutoOwnProgress();
    }
    
    updateAutoOwnProgress(status, percentage) {
        const progressContainer = document.getElementById('autoOwnProgress');
        const progressText = document.getElementById('autoOwnProgressText');
        const progressPercent = document.getElementById('autoOwnProgressPercent');
        const progressBar = document.getElementById('autoOwnProgressBar');
        
        progressText.textContent = status;
        progressPercent.textContent = `${Math.round(percentage)}%`;
        progressBar.style.width = `${percentage}%`;
        
        if (percentage >= 100) {
            progressBar.className = 'progress-bar bg-success';
        } else if (percentage >= 50) {
            progressBar.className = 'progress-bar bg-warning';
        } else {
            progressBar.className = 'progress-bar bg-info';
        }
    }
    
    showAutoOwnProgress() {
        document.getElementById('autoOwnProgress').style.display = 'block';
    }
    
    hideAutoOwnProgress() {
        document.getElementById('autoOwnProgress').style.display = 'none';
    }
    
    updateAutoOwnStatus(text, type) {
        const statusBadge = document.getElementById('autoOwnStatus');
        statusBadge.className = `badge bg-${type}`;
        statusBadge.innerHTML = `<i class="fas fa-circle"></i> ${text}`;
    }
    
    // RCE Session Methods
    onSessionCreated(data) {
        console.log('🎉 RCE Session created:', data);
        
        // Show the sessions panel
        const sessionsPanel = document.getElementById('rceSessions');
        if (sessionsPanel) {
            sessionsPanel.style.display = 'block';
        }
        
        // Add success message to auto-own output
        this.addAutoOwnOutput('🎉 REMOTE CODE EXECUTION ACHIEVED!', 'success');
        this.addAutoOwnOutput(`Session ID: ${data.session_id}`, 'success');
        this.addAutoOwnOutput(`Target: ${data.target}`, 'success');
        this.addAutoOwnOutput(`Session Type: ${data.session_type}`, 'success');
        this.addAutoOwnOutput('Interactive terminal is now available below!', 'success');
        
        // Update sessions container
        this.updateSessionsContainer([data]);
        
        // Automatically connect to the session
        this.connectToSession(data.session_id);
        
        // Play success sound if available
        if (this.effectsManager) {
            this.effectsManager.playSound('success');
        }
    }
    
    onSessionConnected(data) {
        console.log('🔌 Connected to RCE session:', data);
        this.addAutoOwnOutput(`Connected to ${data.session_type} session on ${data.target}`, 'info');
        this.addAutoOwnOutput('You can now execute commands directly on the compromised target!', 'info');
        
        // Show the interactive terminal
        this.showSessionTerminal(data);
    }
    
    onSessionOutput(data) {
        console.log('📤 Session output:', data);
        // Display the command output in the session terminal
        this.displaySessionOutput(data);
    }
    
    onSessionError(data) {
        console.error('❌ Session error:', data);
        this.addAutoOwnOutput(`Session Error: ${data.error}`, 'error');
    }
    
    async updateSessionsContainer(sessions = null) {
        if (!sessions) {
            // Fetch current sessions from API
            try {
                const response = await fetch('/api/sessions');
                const data = await response.json();
                sessions = Object.values(data.sessions || {});
            } catch (error) {
                console.error('Failed to fetch sessions:', error);
                return;
            }
        }
        
        const container = document.getElementById('sessionsContainer');
        if (!container) return;
        
        if (sessions.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted">
                    <i class="fas fa-search"></i> No active sessions found
                </div>
            `;
            return;
        }
        
        container.innerHTML = sessions.map(session => `
            <div class="session-item border border-success rounded p-3 mb-2" data-session-id="${session.session_id}">
                <div class="row">
                    <div class="col-md-8">
                        <h6 class="text-success mb-1">
                            <i class="fas fa-terminal"></i> ${session.session_id}
                        </h6>
                        <p class="mb-1 text-light">
                            <strong>Target:</strong> ${session.target}<br>
                            <strong>Type:</strong> ${session.session_type}<br>
                            <strong>Status:</strong> <span class="badge bg-success">${session.status}</span>
                        </p>
                    </div>
                    <div class="col-md-4 text-end">
                        <button class="btn btn-success btn-sm connect-session-btn" data-session-id="${session.session_id}">
                            <i class="fas fa-plug"></i> Connect
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
        
        // Add click handlers for connect buttons
        container.querySelectorAll('.connect-session-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const sessionId = e.target.closest('.connect-session-btn').dataset.sessionId;
                this.connectToSession(sessionId);
            });
        });
    }
    
    connectToSession(sessionId) {
        console.log(`🔌 Connecting to session: ${sessionId}`);
        this.socket.emit('session_connect', { session_id: sessionId });
    }
    
    showSessionTerminal(sessionData) {
        // For now, use the existing console output area to show session terminal
        // In a more advanced implementation, you could create a separate terminal window
        this.addAutoOwnOutput('='.repeat(50), 'info');
        this.addAutoOwnOutput('🚀 INTERACTIVE TERMINAL READY', 'success');
        this.addAutoOwnOutput('='.repeat(50), 'info');
        this.addAutoOwnOutput(sessionData.welcome, 'info');
        
        // You could enhance this by adding a dedicated terminal input/output area
        this.addAutoOwnOutput('💡 Tip: Use the console tab for direct command interaction', 'info');
    }
    
    displaySessionOutput(data) {
        // Display session command output
        this.addAutoOwnOutput(`> ${data.command}`, 'command');
        this.addAutoOwnOutput(data.output, 'info');
    }
    
    enableAutoOwnControls(running) {
        const startBtn = document.getElementById('startAutoOwnBtn');
        const stopBtn = document.getElementById('stopAutoOwnBtn');
        const targetInput = document.getElementById('autoOwnTarget');
        
        startBtn.disabled = running;
        stopBtn.disabled = !running;
        targetInput.disabled = running;
    }

    // Custom Scripts Methods
    onCustomScriptsTabShown() {
        console.log('📝 Custom scripts tab shown, initializing...');
        this.setupCustomScriptsHandlers();
        this.loadCustomScripts();
    }

    setupCustomScriptsHandlers() {
        console.log('🔧 Setting up custom scripts handlers...');
        
        // Upload button
        const uploadBtn = document.getElementById('uploadScriptBtn');
        const fileInput = document.getElementById('scriptUpload');
        if (uploadBtn && fileInput) {
            uploadBtn.addEventListener('click', () => fileInput.click());
            fileInput.addEventListener('change', (e) => this.uploadCustomScript(e.target.files[0]));
        }

        // Refresh button
        const refreshBtn = document.getElementById('refreshScriptsBtn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadCustomScripts());
        }
    }

    async loadCustomScripts() {
        console.log('📋 Loading custom scripts...');
        try {
            const response = await fetch('/api/custom-scripts');
            const data = await response.json();
            
            console.log('📋 Custom scripts loaded:', data);
            this.updateCustomScriptsUI(data.scripts);
            this.updateCustomScriptsCount(data.count);
        } catch (error) {
            console.error('❌ Failed to load custom scripts:', error);
        }
    }

    updateCustomScriptsUI(scripts) {
        const container = document.getElementById('customScriptsList');
        if (!container) return;

        if (!scripts || scripts.length === 0) {
            container.innerHTML = `
                <div class="text-center text-muted p-3">
                    <i class="fas fa-file-code"></i><br>No scripts uploaded
                </div>
            `;
            return;
        }

        container.innerHTML = scripts.map(script => `
            <div class="list-group-item list-group-item-action custom-script-item" data-script="${script.name}">
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${script.name}</h6>
                    <small class="${script.valid ? 'text-success' : 'text-danger'}">${script.valid ? '✅' : '❌'}</small>
                </div>
                <p class="mb-1">${script.class_name}</p>
                <small>Size: ${(script.size / 1024).toFixed(1)} KB</small>
                <div class="mt-2">
                    <button class="btn btn-primary btn-sm execute-script-btn" data-script="${script.name}" ${!script.valid ? 'disabled' : ''}>
                        <i class="fas fa-play"></i> Execute
                    </button>
                    <button class="btn btn-danger btn-sm delete-script-btn" data-script="${script.name}">
                        <i class="fas fa-trash"></i> Delete
                    </button>
                </div>
            </div>
        `).join('');

        // Add event handlers
        container.querySelectorAll('.execute-script-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const scriptName = e.target.closest('.execute-script-btn').dataset.script;
                this.selectCustomScript(scriptName);
            });
        });

        container.querySelectorAll('.delete-script-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const scriptName = e.target.closest('.delete-script-btn').dataset.script;
                this.deleteCustomScript(scriptName);
            });
        });
    }

    updateCustomScriptsCount(count) {
        const badge = document.getElementById('customScriptsCount');
        if (badge) {
            badge.textContent = count;
        }
    }

    async uploadCustomScript(file) {
        if (!file) return;

        console.log('📤 Uploading custom script:', file.name);
        
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await fetch('/api/custom-scripts/upload', {
                method: 'POST',
                body: formData
            });

            const result = await response.json();
            
            if (response.ok) {
                console.log('✅ Script uploaded successfully:', result);
                this.loadCustomScripts(); // Refresh the list
            } else {
                console.error('❌ Upload failed:', result);
                alert(`Upload failed: ${result.error}`);
            }
        } catch (error) {
            console.error('❌ Upload error:', error);
            alert('Upload failed. Please try again.');
        }
    }

    async deleteCustomScript(scriptName) {
        if (!confirm(`Are you sure you want to delete ${scriptName}?`)) {
            return;
        }

        console.log('🗑️ Deleting custom script:', scriptName);

        try {
            const response = await fetch(`/api/custom-scripts/${scriptName}`, {
                method: 'DELETE'
            });

            const result = await response.json();
            
            if (response.ok) {
                console.log('✅ Script deleted successfully:', result);
                this.loadCustomScripts(); // Refresh the list
            } else {
                console.error('❌ Delete failed:', result);
                alert(`Delete failed: ${result.error}`);
            }
        } catch (error) {
            console.error('❌ Delete error:', error);
            alert('Delete failed. Please try again.');
        }
    }

    selectCustomScript(scriptName) {
        console.log('📝 Selecting custom script:', scriptName);
        
        // Show script execution interface
        const executionContent = document.getElementById('scriptExecutionContent');
        const scriptNameHeader = document.getElementById('selectedScriptName');
        
        if (scriptNameHeader) {
            scriptNameHeader.innerHTML = `<i class="fas fa-play text-neon"></i> ${scriptName}`;
        }

        if (executionContent) {
            executionContent.innerHTML = `
                <div class="mb-3">
                    <h6>Script Options</h6>
                    <div id="scriptOptionsForm">
                        <div class="mb-2">
                            <label class="form-label">Target IP</label>
                            <input type="text" class="form-control" id="script-target" value="192.168.1.1">
                        </div>
                        <div class="mb-2">
                            <label class="form-label">Port</label>
                            <input type="number" class="form-control" id="script-port" value="80">
                        </div>
                        <div class="mb-2">
                            <label class="form-label">Timeout</label>
                            <input type="number" class="form-control" id="script-timeout" value="10">
                        </div>
                    </div>
                </div>
                <div class="mb-3">
                    <button class="btn btn-primary" onclick="window.routerSploitGUI.executeCustomScript('${scriptName}')">
                        <i class="fas fa-play"></i> Run Script
                    </button>
                </div>
                <div class="mb-3">
                    <h6>Output</h6>
                    <div id="scriptOutput" class="bg-dark border rounded p-3" style="height: 300px; overflow-y: auto; font-family: monospace;">
                        <div class="text-muted">Ready to execute script...</div>
                    </div>
                </div>
            `;
        }
    }

    async executeCustomScript(scriptName) {
        console.log('▶️ Executing custom script:', scriptName);
        
        const target = document.getElementById('script-target')?.value || '';
        const port = document.getElementById('script-port')?.value || '80';
        const timeout = document.getElementById('script-timeout')?.value || '10';

        const options = {
            target: target,
            port: parseInt(port),
            timeout: parseInt(timeout)
        };

        try {
            // For now, use the regular module execution API with custom script path
            const modulePath = `custom_scripts.${scriptName.replace('.py', '')}`;
            
            const response = await fetch('/api/run', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    module_path: modulePath,
                    options: options
                })
            });

            const result = await response.json();
            
            if (response.ok) {
                console.log('✅ Script execution started:', result);
                this.currentModule = modulePath; // Track the current module for output routing
                this.addScriptOutput('Script execution started...', 'info');
            } else {
                console.error('❌ Execution failed:', result);
                this.addScriptOutput(`Execution failed: ${result.error}`, 'error');
            }
        } catch (error) {
            console.error('❌ Execution error:', error);
            this.addScriptOutput(`Execution error: ${error.message}`, 'error');
        }
    }

    addScriptOutput(message, level = 'info') {
        const output = document.getElementById('scriptOutput');
        if (!output) return;

        const timestamp = new Date().toLocaleTimeString();
        const levelClass = level === 'error' ? 'text-danger' : level === 'success' ? 'text-success' : 'text-light';
        
        const messageDiv = document.createElement('div');
        messageDiv.className = levelClass;
        messageDiv.innerHTML = `[${timestamp}] ${message}`;
        
        output.appendChild(messageDiv);
        output.scrollTop = output.scrollHeight;
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('🌐 DOM Content Loaded - Starting RouterSploit GUI');
    
    try {
        window.routerSploitGUI = new RouterSploitGUI();
        window.app = window.routerSploitGUI; // Backward compatibility alias
        console.log('✅ RouterSploit GUI initialized successfully');
    } catch (error) {
        console.error('❌ Failed to initialize RouterSploit GUI:', error);
        
        // Show user-friendly error
        const errorDiv = document.createElement('div');
        errorDiv.className = 'alert alert-danger m-3';
        errorDiv.innerHTML = `
            <h4>🚨 Application Failed to Start</h4>
            <p>RouterSploit GUI failed to initialize properly.</p>
            <p><strong>Error:</strong> ${error.message}</p>
            <p><small>Please refresh the page or check browser console for details.</small></p>
            <button class="btn btn-warning" onclick="location.reload()">🔄 Reload Page</button>
        `;
        
        const container = document.querySelector('.container-fluid') || document.body;
        container.insertBefore(errorDiv, container.firstChild);
    }
});

// Fallback initialization if DOMContentLoaded already fired
if (document.readyState === 'loading') {
    // Still loading, DOMContentLoaded will fire
    console.log('📄 Document still loading, waiting for DOMContentLoaded');
} else {
    // DOM is already ready
    console.log('📄 DOM already ready, initializing immediately');
    setTimeout(() => {
        if (!window.routerSploitGUI) {
            console.log('🔄 Fallback initialization triggered');
            try {
                window.routerSploitGUI = new RouterSploitGUI();
                window.app = window.routerSploitGUI;
                console.log('✅ Fallback initialization successful');
            } catch (error) {
                console.error('❌ Fallback initialization failed:', error);
            }
        }
    }, 100);
}

// Shared Matrix Rain Effect Function
function initMatrixRain() {
    const matrixRain = document.getElementById('matrixRain');
    if (matrixRain) {
        try {
            const context = matrixRain.getContext('2d');
            matrixRain.width = window.innerWidth;
            matrixRain.height = window.innerHeight;
            const alphabet = 'アァカサタナハマヤャラワガザダバパイィキシチニヒミリヰギジヂビピウゥクスツヌフムユュルグズブヅプエェケセテネヘメレヱゲゼデベペオォコソトノホモヨョロヲゴゾドボポヴッンABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
            const fontSize = 16;
            const columns = matrixRain.width / fontSize;
            const rainDrops = [];
            
            for (let x = 0; x < columns; x++) {
                rainDrops[x] = 1;
            }
            
            const draw = () => {
                context.fillStyle = 'rgba(0, 0, 0, 0.05)';
                context.fillRect(0, 0, matrixRain.width, matrixRain.height);
                context.fillStyle = '#0F0';
                context.font = fontSize + 'px monospace';
                
                for (let i = 0; i < rainDrops.length; i++) {
                    const text = alphabet.charAt(Math.floor(Math.random() * alphabet.length));
                    context.fillText(text, i * fontSize, rainDrops[i] * fontSize);
                    
                    if (rainDrops[i] * fontSize > matrixRain.height && Math.random() > 0.975) {
                        rainDrops[i] = 0;
                    }
                    rainDrops[i]++;
                }
            };
            
            setInterval(draw, 30);
            
            // Handle window resize
            window.addEventListener('resize', () => {
                matrixRain.width = window.innerWidth;
                matrixRain.height = window.innerHeight;
            });
            
            console.log('✅ Matrix rain effect initialized');
            
        } catch (error) {
            console.warn('⚠️ Matrix rain animation failed:', error);
        }
    }
}

// Auto-initialize matrix rain when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initMatrixRain);
} else {
    initMatrixRain();
} 