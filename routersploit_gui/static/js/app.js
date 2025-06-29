// RouterSploit GUI JavaScript

class RouterSploitGUI {
    constructor() {
        this.socket = null;
        this.currentModule = null;
        this.modules = {};
        this.moduleTree = {};
        this.isRunning = false;
        this.selectedPayload = null;
        
        this.init();
    }
    
    init() {
        // Initialize Socket.IO connection
        this.socket = io();
        this.setupSocketHandlers();
        
        // Setup event handlers
        this.setupEventHandlers();
        
        // Load modules
        this.loadModules();
    }
    
    setupSocketHandlers() {
        this.socket.on('connect', () => {
            console.log('Connected to server');
            this.updateStatus('Connected', 'secondary');
        });
        
        this.socket.on('disconnect', () => {
            console.log('Disconnected from server');
            this.updateStatus('Disconnected', 'danger');
        });
        
        this.socket.on('output', (data) => {
            this.addOutput(data.line, data.level);
        });
        
        this.socket.on('complete', (data) => {
            this.onExecutionComplete(data.success, data.error);
        });
        
        this.socket.on('status', (data) => {
            this.isRunning = data.running;
            this.updateUI();
        });
    }
    
    setupEventHandlers() {
        // Stop button
        document.getElementById('stopBtn').addEventListener('click', () => {
            this.stopExecution();
        });
        
        // Clear output button
        document.getElementById('clearOutputBtn').addEventListener('click', () => {
            this.clearOutput();
        });
        
        // Run button
        document.getElementById('runBtn').addEventListener('click', () => {
            this.runModule();
        });
        
        // Apply target button
        document.getElementById('applyTargetBtn').addEventListener('click', () => {
            this.applyQuickTarget();
        });
        
        // Payload selection
        document.getElementById('payloadSelect').addEventListener('change', (e) => {
            this.onPayloadSelect(e.target.value);
        });
        
        // Quick target input (Enter key)
        document.getElementById('quickTarget').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.applyQuickTarget();
            }
        });
    }
    
    async loadModules() {
        try {
            console.log('Loading modules from API...');
            const response = await fetch('/api/modules');
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('Received data from API:', data);
            
            this.moduleTree = data.tree;
            this.modules = data.modules;
            
            console.log('About to render tree with data:', this.moduleTree);
            this.renderModuleTree();
            this.updateModuleCount(data.count);
            
            console.log('Tree rendering completed');
            
        } catch (error) {
            console.error('Failed to load modules:', error);
            this.showError('Failed to load modules: ' + error.message);
            
            // Show error in tree container
            const treeContainer = document.getElementById('moduleTree');
            treeContainer.innerHTML = `
                <div class="text-center p-3 text-danger">
                    <i class="fas fa-exclamation-triangle fa-2x mb-3"></i>
                    <p>Failed to load modules</p>
                    <small>${error.message}</small>
                </div>
            `;
        }
    }
    
    renderModuleTree() {
        const treeContainer = document.getElementById('moduleTree');
        treeContainer.innerHTML = '';
        
        console.log('Rendering module tree, structure:', this.moduleTree);
        
        // Handle the nested structure returned by the API
        // The API returns { categories: { ... } } at the top level
        if (this.moduleTree.categories) {
            this.renderTreeNode(this.moduleTree.categories, treeContainer, '');
        } else {
            // Fallback for flat structure
            this.renderTreeNode(this.moduleTree, treeContainer, '');
        }
        
        // Initialize search functionality
        this.initializeSearch();
    }
    
    renderTreeNode(node, container, parentPath, depth = 0) {
        console.log(`Rendering tree node at depth ${depth}, parentPath: ${parentPath}`, node);
        
        for (const [key, value] of Object.entries(node)) {
            const path = parentPath ? `${parentPath}.${key}` : key;
            console.log(`Processing key: ${key}, value:`, value);
            
            if (value && typeof value === 'object' && value.dotted_path) {
                // This is a direct module (leaf node)
                console.log(`Rendering module: ${key}`);
                this.renderModule(value, container, depth);
            } else if (value && typeof value === 'object' && (value.modules || value.categories)) {
                // This is a category with modules and/or subcategories
                console.log(`Rendering category: ${key} with modules: ${value.modules?.length || 0}, categories: ${Object.keys(value.categories || {}).length}`);
                this.renderCategory(key, value, container, path, depth);
            } else {
                console.log(`Skipping unknown node type for key: ${key}`, value);
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
        const moduleCount = (categoryData.modules ? categoryData.modules.length : 0);
        const categoryCount = (categoryData.categories ? Object.keys(categoryData.categories).length : 0);
        const totalCount = moduleCount + categoryCount;
        
        // Create a unique ID for this category
        const categoryId = `category-${path.replace(/\./g, '-')}`;
        
        const categoryDiv = document.createElement('div');
        categoryDiv.className = 'tree-node category';
        categoryDiv.style.paddingLeft = `${depth * 20}px`;
        
        categoryDiv.innerHTML = `
            <span class="tree-toggle" data-target="${categoryId}">
                <i class="fas fa-chevron-right"></i>
            </span>
            <i class="fas fa-folder"></i> ${key}
            <span class="badge bg-secondary ms-2">${totalCount}</span>
        `;
        
        // Create container for child elements
        const childContainer = document.createElement('div');
        childContainer.className = 'tree-children';
        childContainer.id = categoryId;
        childContainer.style.display = 'none';
        
        // Add click handler for toggle
        const toggleElement = categoryDiv.querySelector('.tree-toggle');
        toggleElement.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCategory(categoryId, toggleElement);
        });
        
        container.appendChild(categoryDiv);
        container.appendChild(childContainer);
        
        // Add modules if any
        if (categoryData.modules && categoryData.modules.length > 0) {
            console.log(`Adding ${categoryData.modules.length} modules to category ${key}`);
            categoryData.modules.forEach((module, index) => {
                console.log(`Adding module ${index + 1}:`, module);
                this.renderModule(module, childContainer, depth + 1);
            });
        }
        
        // Add subcategories if any
        if (categoryData.categories && Object.keys(categoryData.categories).length > 0) {
            console.log(`Recursing into subcategories for ${key}`);
            this.renderTreeNode(categoryData.categories, childContainer, path, depth + 1);
        }
    }
    
    toggleCategory(categoryId, toggleElement) {
        const container = document.getElementById(categoryId);
        const chevron = toggleElement.querySelector('i');
        const categoryNode = toggleElement.closest('.tree-node.category');
        
        if (container.style.display === 'none') {
            // Expand
            container.style.display = 'block';
            chevron.className = 'fas fa-chevron-down';
            categoryNode.classList.add('expanded');
        } else {
            // Collapse
            container.style.display = 'none';
            chevron.className = 'fas fa-chevron-right';
            categoryNode.classList.remove('expanded');
        }
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
        
        if (optionType === 'boolean') {
            const checked = currentValue === true || currentValue === 'True' ? 'checked' : '';
            inputElement = `
                <div class="form-check">
                    <input class="form-check-input" type="checkbox" id="${inputId}" ${checked}>
                    <label class="form-check-label" for="${inputId}">
                        ${optInfo.description || 'Enable this option'}
                    </label>
                </div>
            `;
        } else if (optionType === 'port' || optionType === 'integer') {
            inputElement = `
                <input type="number" class="form-control option-input" id="${inputId}" 
                       value="${currentValue}" placeholder="${optInfo.description || ''}"
                       ${optInfo.required ? 'required' : ''}>
            `;
        } else {
            // Text input (default)
            inputElement = `
                <input type="text" class="form-control option-input" id="${inputId}" 
                       value="${currentValue}" placeholder="${optInfo.description || ''}"
                       ${optInfo.required ? 'required' : ''}>
            `;
        }
        
        const typeBadge = this.getTypeBadge(optionType);
        
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
    
    getTypeBadge(optionType) {
        const badges = {
            'text': '<span class="badge bg-info option-type-badge">TEXT</span>',
            'port': '<span class="badge bg-warning option-type-badge">PORT</span>',
            'integer': '<span class="badge bg-warning option-type-badge">INT</span>',
            'boolean': '<span class="badge bg-success option-type-badge">BOOL</span>',
            'file': '<span class="badge bg-secondary option-type-badge">FILE</span>'
        };
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
            } else {
                this.showError(result.error || 'Failed to start module');
            }
            
        } catch (error) {
            console.error('Failed to run module:', error);
            this.showError('Failed to start module execution');
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
        
        if (success) {
            this.updateStatus('Complete', 'success');
            this.addOutput('Module execution completed successfully', 'success');
        } else {
            this.updateStatus('Error', 'danger');
            this.addOutput(`Module execution failed: ${error || 'Unknown error'}`, 'error');
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
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.routerSploitGUI = new RouterSploitGUI();
}); 