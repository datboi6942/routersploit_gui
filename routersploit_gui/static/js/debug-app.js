// RouterSploit GUI - Debug Version
// This simplified version focuses on core functionality

console.log('🔧 Debug App Loading...');

class DebugRouterSploitGUI {
    constructor() {
        console.log('🚀 Debug RouterSploit GUI starting...');
        this.modules = {};
        this.moduleTree = {};
        this.socket = null;
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
            
            // Initialize Socket.IO
            this.initSocket();
            
            // Setup button handlers
            this.setupButtons();
            
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
            });
            
            this.socket.on('disconnect', () => {
                console.log('🔌 Socket disconnected');
                this.updateStatus('Disconnected', 'danger');
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
            saveApiBtn.addEventListener('click', (e) => {
                console.log('🔑 Save API key button clicked!');
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
    
    saveApiKey() {
        console.log('🔑 Saving API key...');
        
        const apiKeyInput = document.getElementById('openaiApiKey');
        if (!apiKeyInput) {
            console.error('❌ API key input not found');
            this.showError('API key input not found!');
            return;
        }
        
        const apiKey = apiKeyInput.value.trim();
        if (!apiKey) {
            console.warn('⚠️ No API key specified');
            this.showError('Please enter an API key');
            return;
        }
        
        try {
            localStorage.setItem('openai_api_key', apiKey);
            console.log('✅ API key saved to localStorage');
            this.updateStatus('API Key Saved', 'success');
            
        } catch (error) {
            console.error('❌ Failed to save API key:', error);
            this.showError('Failed to save API key: ' + error.message);
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
    
    showError(message) {
        console.error('💥 Error:', message);
        this.addAutoOwnOutput(`💥 Error: ${message}`, 'error');
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