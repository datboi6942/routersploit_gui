// RouterSploit GUI - Debug Version
// This simplified version focuses on core functionality

console.log('🔧 Debug App Loading...');

class DebugRouterSploitGUI {
    constructor() {
        console.log('🚀 Debug RouterSploit GUI starting...');
        this.modules = {};
        this.moduleTree = {};
        this.socket = null;
        
        // Console state
        this.consoleConnected = false;
        this.commandHistory = [];
        this.historyIndex = -1;
        this.currentPrompt = 'rsf > ';
        
        this.init();
    }
    
    init() {
        console.log('🔧 Initializing debug app...');
        
        // Wait for DOM
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }
    
    setup() {
        console.log('🔧 Setting up debug app...');
        
        try {
            // Test basic DOM access
            this.testDOMAccess();
            
            // Test server connectivity
            this.testServerConnectivity();
            
            // Initialize Socket.IO
            this.initSocket();
            
            // Setup button handlers
            this.setupButtons();
            
            // Setup console handlers
            this.setupConsoleHandlers();
            
            // Load modules
            this.loadModules();
            
            console.log('✅ Debug app setup complete');
            
        } catch (error) {
            console.error('❌ Debug app setup failed:', error);
            this.showError('App initialization failed: ' + error.message);
        }
    }
    
    testDOMAccess() {
        console.log('🧪 Testing DOM access...');
        
        const elements = {
            'startAutoOwnBtn': document.getElementById('startAutoOwnBtn'),
            'autoOwnTarget': document.getElementById('autoOwnTarget'),
            'openaiApiKey': document.getElementById('openaiApiKey'),
            'saveApiKeyBtn': document.getElementById('saveApiKeyBtn'),
            'moduleTree': document.getElementById('moduleTree'),
            'runBtn': document.getElementById('runBtn'),
            'statusBadge': document.getElementById('statusBadge')
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
    
    async testServerConnectivity() {
        console.log('🌐 Testing server connectivity...');
        
        try {
            const response = await fetch('/api/auto-own/check-api-key', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });
            
            console.log('🌐 Server connectivity test response:', response.status);
            
            if (response.ok) {
                const data = await response.json();
                console.log('✅ Server is reachable, API key status:', data);
            } else {
                console.warn('⚠️ Server responded but with error:', response.status);
            }
        } catch (error) {
            console.error('❌ Server connectivity test failed:', error);
            console.error('🚨 WARNING: Cannot reach server! Button clicks may not work.');
        }
    }
    
    initSocket() {
        try {
            console.log('🔌 Initializing Socket.IO...');
            if (typeof io === 'undefined') {
                console.warn('⚠️ Socket.IO not available');
                return;
            }
            
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('🔌 Socket connected');
                this.updateStatus('Connected', 'success');
                
                // Try to connect console when socket connects
                setTimeout(() => {
                    this.connectConsole();
                }, 500);
            });
            
            this.socket.on('disconnect', () => {
                console.log('🔌 Socket disconnected');
                this.updateStatus('Disconnected', 'danger');
                this.updateConsoleStatus('Disconnected', 'danger');
                this.consoleConnected = false;
                this.enableConsoleInput(false);
            });
            
            // Auto-Own event handlers
            this.socket.on('auto_own_output', (data) => {
                console.log('🤖 Auto-Own output received:', data);
                this.addAutoOwnOutput(data.line, data.level);
            });
            
            this.socket.on('auto_own_complete', (data) => {
                console.log('🤖 Auto-Own completed:', data);
                this.onAutoOwnComplete(data.success, data.error);
            });
            
            this.socket.on('auto_own_progress', (data) => {
                console.log('🤖 Auto-Own progress:', data);
                this.updateAutoOwnProgress(data.status, data.percentage);
            });
            
            // Console event handlers
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
            
            console.log('✅ Socket.IO initialized');
            
        } catch (error) {
            console.error('❌ Socket.IO initialization failed:', error);
        }
    }
    
    setupButtons() {
        console.log('🔧 Setting up button handlers...');
        
        // Auto-Own Start Button
        const startBtn = document.getElementById('startAutoOwnBtn');
        if (startBtn) {
            startBtn.addEventListener('click', (e) => {
                console.log('🎯 Auto-Own start button clicked!');
                e.preventDefault();
                this.startAutoOwn();
            });
            console.log('✅ Auto-Own start button handler added');
        } else {
            console.error('❌ startAutoOwnBtn not found');
        }
        
        // Auto-Own Target Input (Enter key)
        const targetInput = document.getElementById('autoOwnTarget');
        if (targetInput) {
            targetInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') {
                    console.log('⚡ Auto-Own target Enter pressed!');
                    e.preventDefault();
                    this.startAutoOwn();
                }
            });
            
            // Test typing
            targetInput.addEventListener('input', (e) => {
                console.log('📝 Target input changed:', e.target.value);
            });
            
            console.log('✅ Auto-Own target input handlers added');
        } else {
            console.error('❌ autoOwnTarget not found');
        }
        
        // API Key Save Button
        const saveApiBtn = document.getElementById('saveApiKeyBtn');
        if (saveApiBtn) {
            console.log('✅ Found saveApiKeyBtn. Adding listener...');
            saveApiBtn.addEventListener('click', (e) => {
                console.log('--- SAVE API KEY BUTTON CLICK DETECTED ---');
                e.preventDefault();
                this.saveApiKey();
            });
            console.log('✅ API key save button handler added');
        } else {
            console.error('❌ saveApiKeyBtn not found');
        }
        
        // Run Button
        const runBtn = document.getElementById('runBtn');
        if (runBtn) {
            runBtn.addEventListener('click', (e) => {
                console.log('▶️ Run button clicked!');
                e.preventDefault();
                alert('Run button works! Module execution would happen here.');
            });
            console.log('✅ Run button handler added');
        } else {
            console.error('❌ runBtn not found');
        }
    }
    
    async loadModules() {
        console.log('📚 Loading modules...');
        
        const moduleTree = document.getElementById('moduleTree');
        if (!moduleTree) {
            console.error('❌ moduleTree container not found');
            return;
        }
        
        // Show loading
        moduleTree.innerHTML = `
            <div class="text-center p-3">
                <div class="spinner-border text-primary" role="status"></div>
                <p class="mt-2">Loading modules...</p>
            </div>
        `;
        
        try {
            console.log('📡 Fetching modules from API...');
            const response = await fetch('/api/modules');
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const data = await response.json();
            console.log('📊 Modules loaded:', {
                count: data.count,
                treeKeys: Object.keys(data.tree || {})
            });
            
            this.modules = data.modules || {};
            this.moduleTree = data.tree || {};
            
            this.renderModuleTree();
            
            console.log('✅ Modules loaded successfully');
            
        } catch (error) {
            console.error('❌ Failed to load modules:', error);
            moduleTree.innerHTML = `
                <div class="text-center p-3 text-danger">
                    <i class="fas fa-exclamation-triangle"></i>
                    <p>Failed to load modules</p>
                    <small>${error.message}</small>
                    <button class="btn btn-warning btn-sm mt-2" onclick="window.debugApp.loadModules()">
                        Retry
                    </button>
                </div>
            `;
        }
    }
    
    renderModuleTree() {
        console.log('🌳 Rendering module tree...');
        
        const moduleTree = document.getElementById('moduleTree');
        if (!moduleTree) {
            console.error('❌ moduleTree container not found');
            return;
        }
        
        if (!this.moduleTree || Object.keys(this.moduleTree).length === 0) {
            moduleTree.innerHTML = `
                <div class="text-center p-3 text-warning">
                    <i class="fas fa-info-circle"></i>
                    <p>No modules found</p>
                </div>
            `;
            return;
        }
        
        try {
            moduleTree.innerHTML = '';
            
            // Create simplified tree structure
            for (const [categoryName, categoryData] of Object.entries(this.moduleTree)) {
                const categoryDiv = document.createElement('div');
                categoryDiv.className = 'tree-category p-2 border-bottom';
                categoryDiv.innerHTML = `
                    <div class="fw-bold text-primary">
                        <i class="fas fa-folder"></i> ${categoryName.toUpperCase()}
                        <span class="badge bg-secondary ms-2">${this.getModuleCount(categoryData)}</span>
                    </div>
                `;
                
                categoryDiv.addEventListener('click', () => {
                    console.log(`📁 Category clicked: ${categoryName}`);
                    this.toggleCategory(categoryName);
                });
                
                moduleTree.appendChild(categoryDiv);
            }
            
            console.log('✅ Module tree rendered');
            
        } catch (error) {
            console.error('❌ Failed to render module tree:', error);
            moduleTree.innerHTML = `
                <div class="text-center p-3 text-danger">
                    <p>Error rendering modules</p>
                    <small>${error.message}</small>
                </div>
            `;
        }
    }
    
    getModuleCount(categoryData) {
        if (!categoryData || typeof categoryData !== 'object') return 0;
        
        let count = 0;
        
        // Count direct modules
        if (categoryData.modules && Array.isArray(categoryData.modules)) {
            count += categoryData.modules.length;
        }
        
        // Count modules in subcategories
        if (categoryData.categories) {
            for (const subCategory of Object.values(categoryData.categories)) {
                count += this.getModuleCount(subCategory);
            }
        }
        
        // Count other objects that might be modules
        for (const [key, value] of Object.entries(categoryData)) {
            if (key !== 'modules' && key !== 'categories' && value && typeof value === 'object') {
                if (value.dotted_path) {
                    count += 1; // This is a module
                } else {
                    count += this.getModuleCount(value); // This is a nested category
                }
            }
        }
        
        return count;
    }
    
    toggleCategory(categoryName) {
        console.log(`🔄 Toggle category: ${categoryName}`);
        alert(`Category "${categoryName}" clicked! Module selection would be implemented here.`);
    }
    
    async startAutoOwn() {
        console.log('🤖 Starting Auto-Own...');
        
        const targetInput = document.getElementById('autoOwnTarget');
        const verboseCheckbox = document.getElementById('autoOwnVerbose');
        const debugCheckbox = document.getElementById('autoOwnDebug');
        
        if (!targetInput) {
            console.error('❌ Target input not found');
            alert('Target input not found!');
            return;
        }
        
        const target = targetInput.value.trim();
        if (!target) {
            console.warn('⚠️ No target specified');
            this.addAutoOwnOutput('⚠️ Please enter a target IP address', 'warning');
            return;
        }
        
        const isVerbose = verboseCheckbox ? verboseCheckbox.checked : false;
        const isDebug = debugCheckbox ? debugCheckbox.checked : false;
        
        console.log(`🎯 Auto-Own parameters: target="${target}", verbose=${isVerbose}, debug=${isDebug}`);
        
        try {
            this.updateStatus('Starting Auto-Own...', 'warning');
            
            console.log('📡 Sending Auto-Own request...');
            const response = await fetch('/api/auto-own/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ target, verbose: isVerbose, debug: isDebug })
            });
            
            console.log('📡 Response status:', response.status);
            const result = await response.json();
            console.log('📡 Response data:', result);
            
            if (response.ok && result.status === 'started') {
                console.log('✅ Auto-Own started successfully');
                this.addAutoOwnOutput(`🚀 Auto-Own started for target: ${target}`, 'success');
                this.addAutoOwnOutput(`🔍 Initializing AI agent and scanning target...`, 'info');
                this.updateStatus('Auto-Own Running', 'success');
            } else {
                throw new Error(result.error || 'Unknown error');
            }
            
        } catch (error) {
            console.error('❌ Auto-Own failed:', error);
            this.addAutoOwnOutput(`❌ Failed to start Auto-Own: ${error.message}`, 'error');
            this.updateStatus('Auto-Own Failed', 'danger');
        }
    }
    
    async saveApiKey() {
        alert("--- DEBUG: saveApiKey function has been called! ---");
        console.log('--- saveApiKey function started! ---');
        console.log('🔑 Saving API key...');
        console.log('🔑 Function called at:', new Date().toISOString());
        
        const apiKeyInput = document.getElementById('openaiApiKey');
        if (!apiKeyInput) {
            console.error('❌ API key input not found');
            this.showError('API key input not found!');
            return;
        }
        
        const apiKey = apiKeyInput.value.trim();
        console.log('🔑 API key length:', apiKey.length);
        console.log('🔑 API key starts with:', apiKey.substring(0, 8));
        
        if (!apiKey) {
            console.warn('⚠️ No API key specified');
            this.showError('Please enter an API key');
            return;
        }
        
        const saveBtn = document.getElementById('saveApiKeyBtn');
        
        try {
            // Show saving state
            if (saveBtn) {
                saveBtn.disabled = true;
                saveBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Saving...';
                console.log('🔑 Button state updated to saving...');
            }
            
            console.log('🔑 About to make fetch call...');
            console.log('🔑 Fetch URL: /api/auto-own/set-api-key');
            console.log('🔑 Fetch method: POST');
            console.log('🔑 Content-Type: application/json');
            
            const requestBody = JSON.stringify({ api_key: apiKey });
            console.log('🔑 Request body length:', requestBody.length);
            console.log('🔑 Request body preview:', requestBody.substring(0, 50) + '...');
            
            // Add a unique timestamp to prevent caching
            const timestamp = Date.now();
            const url = `/api/auto-own/set-api-key?t=${timestamp}`;
            console.log('🔑 Final URL with timestamp:', url);
            
            console.log('🔑 Starting fetch request...');
            
            // Send to backend to save in file (where Python reads from)
            const response = await fetch(url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json',
                    'Cache-Control': 'no-cache'
                },
                body: requestBody
            });
            
            console.log('🔑 Fetch completed!');
            console.log('🔑 Response status:', response.status);
            console.log('🔑 Response statusText:', response.statusText);
            console.log('🔑 Response headers:', Object.fromEntries(response.headers.entries()));
            
            if (!response.ok) {
                console.error('🔑 Response not OK, getting error text...');
                const errorText = await response.text();
                console.error('🔑 Backend HTTP error:', response.status, errorText);
                throw new Error(`HTTP ${response.status}: ${errorText}`);
            }
            
            console.log('🔑 Response OK, parsing JSON...');
            const result = await response.json();
            console.log('🔑 Backend JSON result:', result);
            
            if (result.status === 'success') {
                console.log('🔑 Backend save successful!');
                
                // Also save to localStorage as backup
                localStorage.setItem('openai_api_key', apiKey);
                console.log('🔑 Also saved to localStorage');
                
                console.log('✅ API key saved to backend file and localStorage');
                this.updateStatus('API Key Saved to Backend', 'success');
                
                // Clear input for security
                apiKeyInput.value = '';
                console.log('🔑 Input field cleared');
                
                // Show success message
                this.showSuccess('API key saved successfully to backend file!');
                
            } else {
                console.error('❌ Backend save failed with result:', result);
                throw new Error(result.error || 'Failed to save API key to backend');
            }
            
        } catch (error) {
            console.error('❌ Exception in saveApiKey:', error);
            console.error('❌ Error name:', error.name);
            console.error('❌ Error message:', error.message);
            console.error('❌ Error stack:', error.stack);
            
            // Check if it's a network error
            if (error instanceof TypeError && error.message.includes('fetch')) {
                console.error('🌐 Network error detected - server might be down');
                this.showError('Network error: Cannot connect to server. Is the server running?');
            } else {
                console.log('⚠️ Falling back to localStorage only due to error:', error.message);
                
                // Fallback: save to localStorage only
                try {
                    localStorage.setItem('openai_api_key', apiKey);
                    console.log('⚠️ API key saved to localStorage as fallback');
                    this.updateStatus('API Key Saved (localStorage only)', 'warning');
                    this.showError('Failed to save to backend, saved locally only: ' + error.message);
                } catch (storageError) {
                    console.error('❌ Even localStorage save failed:', storageError);
                    this.showError('Failed to save API key: ' + error.message);
                }
            }
        } finally {
            // Restore button state
            if (saveBtn) {
                saveBtn.disabled = false;
                saveBtn.innerHTML = '<i class="fas fa-save"></i> Save';
                console.log('🔑 Button state restored');
            }
            console.log('🔑 saveApiKey function completed at:', new Date().toISOString());
        }
    }
    
    updateStatus(text, type) {
        const statusBadge = document.getElementById('statusBadge');
        if (statusBadge) {
            statusBadge.innerHTML = `<i class="fas fa-circle"></i> <span>${text}</span>`;
            statusBadge.className = `badge bg-${type} holographic`;
            console.log(`🔄 Status updated: ${text} (${type})`);
        }
    }
    
    showSuccess(message) {
        console.log('✅ Success:', message);
        this.addAutoOwnOutput(`✅ Success: ${message}`, 'success');
        this.updateStatus('Success', 'success');
    }
    
    showError(message) {
        console.error('❌ Error:', message);
        this.addAutoOwnOutput(`❌ Error: ${message}`, 'error');
        this.updateStatus('Error', 'danger');
    }
    
    // Auto-Own output methods
    addAutoOwnOutput(line, level) {
        console.log(`📝 Adding Auto-Own output: [${level}] ${line}`);
        
        const outputContainer = document.getElementById('autoOwnOutput');
        if (!outputContainer) {
            console.error('❌ autoOwnOutput container not found');
            return;
        }
        
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
                contentSpan.className = 'text-light';
        }
        
        outputLine.appendChild(contentSpan);
        outputContainer.appendChild(outputLine);
        
        // Auto-scroll to bottom
        outputContainer.scrollTop = outputContainer.scrollHeight;
    }
    
    onAutoOwnComplete(success, error) {
        console.log(`🏁 Auto-Own completed: success=${success}, error=${error}`);
        
        if (success) {
            this.addAutoOwnOutput('🎉 Auto-Own process completed successfully!', 'success');
            this.updateStatus('Auto-Own Complete', 'success');
        } else {
            this.addAutoOwnOutput(`❌ Auto-Own process failed: ${error}`, 'error');
            this.updateStatus('Auto-Own Failed', 'danger');
        }
    }
    
    updateAutoOwnProgress(status, percentage) {
        console.log(`📊 Auto-Own progress: ${status} (${percentage}%)`);
        
        // Update progress in output
        this.addAutoOwnOutput(`📊 Progress: ${status} (${Math.round(percentage)}%)`, 'info');
    }
    
    // Console functionality methods
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
                console.log('🔑 Enter key pressed in console');
                this.sendConsoleCommand();
            }
        });
        
        consoleInput.addEventListener('keydown', (e) => {
            this.handleConsoleKeydown(e);
        });
        
        // Send button
        consoleSendBtn.addEventListener('click', () => {
            console.log('🖱️ Console send button clicked');
            this.sendConsoleCommand();
        });
        
        // Clear button
        clearConsoleBtn.addEventListener('click', () => {
            console.log('🧹 Clear console button clicked');
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
        
        // Initialize console connection after short delay
        setTimeout(() => {
            this.initializeConsole();
        }, 1000);
    }
    
    initializeConsole() {
        console.log('🚀 Initializing console connection...');
        this.updateConsoleStatus('Connecting...', 'warning');
        
        // Try to connect console when the page loads
        if (this.socket && this.socket.connected) {
            this.connectConsole();
        } else {
            console.log('⚠️ Socket not connected yet, will retry when socket connects');
        }
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
            this.addConsoleOutput('Console not connected. Please wait for connection.', 'warning');
            return;
        }
        
        if (!this.socket || !this.socket.connected) {
            console.log('⚠️ Socket not connected, cannot send command');
            this.addConsoleOutput('Connection lost. Please refresh the page.', 'error');
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
}

// Initialize when DOM is ready
console.log('🔧 Debug app script loaded, waiting for DOM...');

document.addEventListener('DOMContentLoaded', () => {
    console.log('🔧 DOM ready, initializing debug app...');
    window.debugApp = new DebugRouterSploitGUI();
});

// Fallback for already loaded DOM
if (document.readyState !== 'loading') {
    console.log('🔧 DOM already loaded, initializing debug app immediately...');
    window.debugApp = new DebugRouterSploitGUI();
}

console.log('✅ Debug app script fully loaded'); 