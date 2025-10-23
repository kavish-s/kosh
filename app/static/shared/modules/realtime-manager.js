/**
 * Real-time synchronization functionality for admin dashboard
 */

class RealTimeManager {
    constructor() {
        this.socket = null;
        this.usersTable = null;
        this.policiesTable = null;
        this.auditTable = null;
        this.attributesContainer = null;
    }

    /**
     * Initialize real-time functionality
     */
    initialize() {
        if (typeof io === 'undefined') {
            console.warn('Socket.IO not available');
            return;
        }

        this.socket = io();
        this.cacheDOMElements();
        this.setupSocketEvents();
        this.setupConnectionIndicator();
    }

    /**
     * Cache DOM elements for performance
     */
    cacheDOMElements() {
        this.usersTable = document.querySelector('#users-tbody');
        this.policiesTable = document.querySelector('#policies-table tbody');
        this.filesTable = document.querySelector('#files-tbody');
        this.auditTable = document.querySelector('#audit-tbody');
        this.attributesContainer = document.querySelector('.flex.flex-wrap.gap-3.mt-2');
    }

    /**
     * Setup Socket.IO event handlers
     */
    setupSocketEvents() {
        if (!this.socket) return;

        // Join admin room
        this.socket.emit('join_admin');

        // Connection events
        this.socket.on('joined_admin', (data) => {
            console.log('✅ Connected to admin real-time updates');
        });

        this.socket.on('connect', () => {
            console.log('🔌 Connected to server');
            this.updateConnectionStatus(true);
        });

        this.socket.on('disconnect', () => {
            console.log('🔌 Disconnected from server');
            toastManager.show('Connection lost - trying to reconnect...', 'warning');
            this.updateConnectionStatus(false);
        });

        this.socket.on('reconnect', () => {
            console.log('🔌 Reconnected to server');
            toastManager.show('Reconnected! Real-time updates restored', 'success');
            this.socket.emit('join_admin'); // Rejoin admin room
        });

        // User management events
        this.socket.on('user_added', (data) => {
            console.log('👤 User added:', data);
            this.addUserToTable(data.user, data.attributes);
            this.updateUserCountStatus();
        });

        this.socket.on('user_updated', (data) => {
            console.log('👤 User updated:', data);
            this.updateUserInTable(data.user, data.attributes);
        });

        this.socket.on('user_deleted', (data) => {
            console.log('👤 User deleted:', data);
            this.removeUserFromTable(data.user);
            toastManager.show(`User "${data.user}" deleted`, 'warning');
            this.updateUserCountStatus();
        });

        this.socket.on('users_bulk_deleted', (data) => {
            console.log('👥 Users bulk deleted:', data);
            data.users.forEach(user => this.removeUserFromTable(user));
            toastManager.show(`${data.users.length} users deleted`, 'warning');
            this.updateUserCountStatus();
        });

        this.socket.on('users_bulk_attrs_updated', (data) => {
            console.log('👥 Users bulk attributes updated:', data);
            data.users.forEach(user => this.updateUserInTable(user, data.attributes));
        });

        this.socket.on('user_roles_updated', (data) => {
            console.log('👤 User roles updated:', data);
            this.updateUserRolesInTable(data.user, data.roles);
            toastManager.show(`Roles updated for "${data.user}"`, 'info');
        });

        // Policy management events
        this.socket.on('policy_added', (data) => {
            console.log('📄 Policy added:', data);
            this.addPolicyToTable(data.file, data.policy);
            toastManager.show(`Policy for "${data.file}" added`, 'success');
        });

        this.socket.on('policy_updated', (data) => {
            console.log('📄 Policy updated:', data);
            this.updatePolicyInTable(data.file, data.policy);
            toastManager.show(`Policy for "${data.file}" updated`, 'info');
        });

        this.socket.on('policy_deleted', (data) => {
            console.log('📄 Policy deleted:', data);
            this.removePolicyFromTable(data.file);
            toastManager.show(`Policy for "${data.file}" deleted`, 'warning');
        });

        this.socket.on('policies_bulk_deleted', (data) => {
            console.log('📄 Policies bulk deleted:', data);
            data.files.forEach(file => this.removePolicyFromTable(file));
            toastManager.show(`${data.files.length} policies deleted`, 'warning');
        });

        // File management events
        this.socket.on('file_uploaded', (data) => {
            console.log('📁 File uploaded:', data);
            this.addFileToTable(data.file);
            toastManager.show(`File "${data.file.name}" uploaded`, 'success');
        });

        this.socket.on('file_deleted', (data) => {
            console.log('📁 File deleted:', data);
            this.removeFileFromTable(data.filename);
            toastManager.show(`File "${data.filename}" deleted`, 'warning');
        });

        // Audit log events
        this.socket.on('audit_log_added', (data) => {
            console.log('📋 Audit log added:', data);
            this.addAuditLogToTable(data);
        });

        // Attribute events
        this.socket.on('attribute_added', (data) => {
            console.log('🏷️ Attribute added:', data);
            this.addAttributeToUI(data.attribute);
            toastManager.show(`Attribute "${data.attribute}" added`, 'success');
            this.updateGlobalAttributes(data.attribute, 'add');
        });

        this.socket.on('attribute_removed', (data) => {
            console.log('🏷️ Attribute removed:', data);
            this.removeAttributeFromUI(data.attribute);
            toastManager.show(`Attribute "${data.attribute}" removed`, 'warning');
            this.updateGlobalAttributes(data.attribute, 'remove');
        });
    }

    /**
     * Update connection status indicator
     * @param {boolean} connected - Connection status
     */
    updateConnectionStatus(connected) {
        const indicator = document.getElementById('connection-indicator');
        if (indicator) {
            if (connected) {
                indicator.className = 'w-3 h-3 bg-green-500 rounded-full';
                indicator.title = 'Connected';
            } else {
                indicator.className = 'w-3 h-3 bg-red-500 rounded-full';
                indicator.title = 'Disconnected';
            }
        }
    }

    /**
     * Setup connection status indicator
     */
    setupConnectionIndicator() {
        window.addEventListener('load', () => {
            const navbar = document.querySelector('nav .flex.items-center.space-x-4');
            if (navbar) {
                const indicator = document.createElement('div');
                indicator.className = 'flex items-center space-x-2';
                indicator.innerHTML = `
                    <div id="connection-indicator" class="w-3 h-3 bg-gray-500 rounded-full animate-pulse" title="Connecting..."></div>
                    <span class="text-xs text-notion-text-secondary">Real-time</span>
                `;
                navbar.insertBefore(indicator, navbar.firstChild);
            }
        });
    }

    /**
     * Add user to table (real-time)
     * @param {string} user - Username
     * @param {string|Array} attributes - User attributes
     * @param {Array} roles - User roles
     */
    addUserToTable(user, attributes, roles = []) {
        if (!this.usersTable) return;

        const attributesStr = Array.isArray(attributes) ? attributes.join(', ') : attributes;
        const rolesStr = Array.isArray(roles) ? roles.join(', ') : roles || '';
        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition-colors duration-150';

        let rolesHtml = '';
        if (roles && roles.length > 0) {
            rolesHtml = `
                <div class="flex flex-wrap gap-1">
                    ${roles.map(role => `<span class="inline-flex px-2 py-1 text-xs rounded-full bg-green-500/20 text-green-400">${uiHelpers.escapeHtml(role)}</span>`).join('')}
                </div>
            `;
        } else {
            rolesHtml = '<span class="text-notion-text-secondary text-xs italic">No roles</span>';
        }

        tr.innerHTML = `
            <td class="px-2 py-3">
                <input type="checkbox" name="user_bulk" value="${uiHelpers.escapeHtml(user)}" 
                    aria-label="Select user ${uiHelpers.escapeHtml(user)}">
            </td>
            <td class="px-4 py-3 font-medium text-notion-text">${uiHelpers.escapeHtml(user)}</td>
            <td class="px-4 py-3">${uiHelpers.formatAttributesAsHtml(attributesStr)}</td>
            <td class="px-4 py-3">${rolesHtml}</td>
            <td class="px-4 py-3">
                <div class="flex flex-col sm:flex-row items-start space-y-1 sm:space-y-0 sm:space-x-2">
                    <button type="button" class="btn-action btn-action-edit edit-user-link" 
                        data-user='${uiHelpers.escapeHtml(user)}' data-attrs='${uiHelpers.escapeHtml(attributesStr)}' 
                        aria-label="Edit user ${uiHelpers.escapeHtml(user)}" title="Edit user">
                        <i data-lucide="edit-2" class="w-4 h-4"></i>
                    </button>
                    <button type="button" class="btn-action btn-action-info manage-roles-link" 
                        data-user='${uiHelpers.escapeHtml(user)}' data-roles='${uiHelpers.escapeHtml(rolesStr)}'
                        aria-label="Manage roles for ${uiHelpers.escapeHtml(user)}" title="Manage roles">
                        <i data-lucide="shield" class="w-4 h-4"></i>
                    </button>
                    <button type="button" class="btn-action btn-action-delete delete-user-link" 
                        data-user='${uiHelpers.escapeHtml(user)}' 
                        aria-label="Delete user ${uiHelpers.escapeHtml(user)}" title="Delete user">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        `;

        this.usersTable.insertBefore(tr, this.usersTable.firstChild);
        adminLinks.setup();
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Update user in table (real-time)
     * @param {string} user - Username
     * @param {string|Array} attributes - User attributes
     */
    updateUserInTable(user, attributes) {
        if (!this.usersTable) return;

        const inputs = Array.from(this.usersTable.querySelectorAll('input[name="user_bulk"]'));
        const match = inputs.find(i => i.value === user);
        if (match) {
            const tr = match.closest('tr');
            if (tr) {
                const attributesStr = Array.isArray(attributes) ? attributes.join(', ') : attributes;

                const attributesCell = tr.children[2];
                attributesCell.innerHTML = uiHelpers.formatAttributesAsHtml(attributesStr);

                const editBtn = tr.querySelector('.edit-user-link');
                if (editBtn) {
                    editBtn.setAttribute('data-attrs', attributesStr);
                }

                uiHelpers.refreshTailwindStyles(tr);
            }
        }
    }

    /**
     * Update user roles in table (real-time)
     * @param {string} user - Username
     * @param {Array} roles - User roles
     */
    updateUserRolesInTable(user, roles) {
        if (!this.usersTable) return;

        const inputs = Array.from(this.usersTable.querySelectorAll('input[name="user_bulk"]'));
        const match = inputs.find(i => i.value === user);
        if (match) {
            const tr = match.closest('tr');
            if (tr) {
                const rolesCell = tr.children[3]; // Roles are in the 4th column (index 3)
                if (rolesCell) {
                    const rolesStr = Array.isArray(roles) ? roles.join(', ') : roles || '';
                    let rolesHtml = '';
                    
                    if (roles && roles.length > 0) {
                        rolesHtml = `
                            <div class="flex flex-wrap gap-1">
                                ${roles.map(role => `<span class="inline-flex px-2 py-1 text-xs rounded-full bg-green-500/20 text-green-400">${uiHelpers.escapeHtml(role)}</span>`).join('')}
                            </div>
                        `;
                    } else {
                        rolesHtml = '<span class="text-notion-text-secondary text-xs italic">No roles</span>';
                    }
                    
                    rolesCell.innerHTML = rolesHtml;

                    // Update the manage-roles-link button
                    const manageRolesBtn = tr.querySelector('.manage-roles-link');
                    if (manageRolesBtn) {
                        manageRolesBtn.setAttribute('data-roles', rolesStr);
                    }

                    uiHelpers.refreshTailwindStyles(tr);
                }
            }
        }
    }

    /**
     * Remove user from table (real-time)
     * @param {string} user - Username
     */
    removeUserFromTable(user) {
        if (!this.usersTable) return;

        const inputs = Array.from(this.usersTable.querySelectorAll('input[name="user_bulk"]'));
        const match = inputs.find(i => i.value === user);
        if (match) {
            const tr = match.closest('tr');
            if (tr) tr.remove();
        }
    }

    /**
     * Add policy to table (real-time)
     * @param {string} file - Filename
     * @param {Object} policyObj - Policy object with policy and key properties
     */
    addPolicyToTable(file, policyObj) {
        if (!this.policiesTable) return;

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition-colors duration-150';

        let policyHtml = '';
        if (policyObj.policy) {
            const attrs = policyObj.policy.split(',');
            policyHtml = `
                <div class="flex flex-wrap gap-1">
                    ${attrs.map(attr => `<span class="inline-flex px-2 py-1 text-xs rounded-full bg-notion-accent/20 text-notion-accent">${uiHelpers.escapeHtml(attr.trim())}</span>`).join('')}
                </div>
            `;
        } else {
            policyHtml = '<span class="text-notion-text-secondary italic">No policy set</span>';
        }

        tr.innerHTML = `
            <td class="px-2 py-3">
                <input type="checkbox" name="policy_bulk" value="${uiHelpers.escapeHtml(file)}" 
                    aria-label="Select policy for ${uiHelpers.escapeHtml(file)}" class="rounded border-notion-border bg-notion-input">
            </td>
            <td class="px-4 py-3 font-medium text-notion-text">
                <span class="block max-w-[220px] truncate filename" title="${uiHelpers.escapeHtml(file)}">${uiHelpers.escapeHtml(file)}</span>
            </td>
            <td class="px-4 py-3">${policyHtml}</td>
            <td class="px-4 py-3 text-notion-text-secondary">${uiHelpers.escapeHtml(policyObj.key || 'Auto-generated')}</td>
            <td class="px-4 py-3">
                <div class="flex flex-col sm:flex-row items-start sm:items-center space-y-1 sm:space-y-0 sm:space-x-2">
                    <button type="button" class="btn-action btn-action-edit edit-policy-link" 
                        data-file="${uiHelpers.escapeHtml(file)}" data-policy="${uiHelpers.escapeHtml(policyObj.policy || '')}" 
                        aria-label="Edit policy for ${uiHelpers.escapeHtml(file)}" title="Edit policy">
                        <i data-lucide="edit-2" class="w-4 h-4"></i>
                    </button>
                    <button type="button" class="btn-action btn-action-delete" 
                        onclick="if(confirm('Delete policy?')) deletePolicy('${uiHelpers.escapeHtml(file)}'); return false;" 
                        aria-label="Delete policy for ${uiHelpers.escapeHtml(file)}" title="Delete policy">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        `;

        this.policiesTable.insertBefore(tr, this.policiesTable.firstChild);
        adminLinks.setup();
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Update policy in table (real-time)
     * @param {string} file - Filename
     * @param {Object} policyObj - Policy object with policy and key properties
     */
    updatePolicyInTable(file, policyObj) {
        if (!this.policiesTable) return;

        const inputs = Array.from(this.policiesTable.querySelectorAll('input[name="policy_bulk"]'));
        const match = inputs.find(i => i.value === file);
        if (match) {
            const tr = match.closest('tr');
            if (tr) {
                // Update policy cell (3rd cell)
                const policyCell = tr.children[2];
                let policyHtml = '';
                if (policyObj.policy) {
                    const attrs = policyObj.policy.split(',');
                    policyHtml = `
                        <div class="flex flex-wrap gap-1">
                            ${attrs.map(attr => `<span class="inline-flex px-2 py-1 text-xs rounded-full bg-notion-accent/20 text-notion-accent">${uiHelpers.escapeHtml(attr.trim())}</span>`).join('')}
                        </div>
                    `;
                } else {
                    policyHtml = '<span class="text-notion-text-secondary italic">No policy set</span>';
                }
                policyCell.innerHTML = policyHtml;

                // Update key cell (4th cell)
                const keyCell = tr.children[3];
                keyCell.textContent = policyObj.key || 'Auto-generated';

                // Update edit button data attributes
                const editBtn = tr.querySelector('.edit-policy-link');
                if (editBtn) {
                    editBtn.setAttribute('data-policy', policyObj.policy || '');
                }

                uiHelpers.refreshTailwindStyles(tr);
            }
        }
    }

    /**
     * Remove policy from table (real-time)
     * @param {string} file - Filename
     */
    removePolicyFromTable(file) {
        if (!this.policiesTable) return;

        const inputs = Array.from(this.policiesTable.querySelectorAll('input[name="policy_bulk"]'));
        const match = inputs.find(i => i.value === file);
        if (match) {
            const tr = match.closest('tr');
            if (tr) tr.remove();
        }
    }

    /**
     * Add audit log to table (real-time)
     * @param {Object} logEntry - Log entry data
     */
    addAuditLogToTable(logEntry) {
        if (!this.auditTable) return;

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition';

        tr.innerHTML = `
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.time)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.user)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.action)}</td>
            <td class="px-4 py-2">${uiHelpers.escapeHtml(logEntry.details)}</td>
        `;

        this.auditTable.insertBefore(tr, this.auditTable.firstChild);

        // Limit audit log entries to prevent memory issues (keep latest 100)
        const rows = this.auditTable.querySelectorAll('tr');
        if (rows.length > 100) {
            for (let i = 100; i < rows.length; i++) {
                rows[i].remove();
            }
        }
    }

    /**
     * Add attribute to UI (real-time)
     * @param {string} attribute - Attribute name
     */
    addAttributeToUI(attribute) {
        if (!this.attributesContainer) return;

        const span = document.createElement('span');
        span.className = 'bg-notion-accent/20 text-notion-accent px-3 py-2 rounded-full flex items-center shadow-sm transition-all duration-150 hover:bg-notion-accent/30';

        span.innerHTML = `
            <span class="mr-2">${uiHelpers.escapeHtml(attribute)}</span>
            <button type="button"
                class="ml-1 px-2 py-1 rounded-full bg-notion-card text-notion-text-secondary hover:bg-notion-hover hover:text-white transition"
                onclick="attributeManager.remove('${uiHelpers.escapeHtml(attribute)}')"
                aria-label="Remove attribute ${uiHelpers.escapeHtml(attribute)}">
                &times;
            </button>
        `;

        this.attributesContainer.appendChild(span);
    }

    /**
     * Remove attribute from UI (real-time)
     * @param {string} attribute - Attribute name
     */
    removeAttributeFromUI(attribute) {
        if (!this.attributesContainer) return;

        const spans = this.attributesContainer.querySelectorAll('span');
        spans.forEach(span => {
            const textSpan = span.querySelector('span');
            if (textSpan && textSpan.textContent.trim() === attribute) {
                span.remove();
            }
        });
    }

    /**
     * Update global attributes array
     * @param {string} attribute - Attribute name
     * @param {string} action - 'add' or 'remove'
     */
    updateGlobalAttributes(attribute, action) {
        if (!window.allAttributes) window.allAttributes = [];

        if (action === 'add') {
            if (!window.allAttributes.includes(attribute)) {
                window.allAttributes.push(attribute);
                window.allAttributes.sort();
            }
        } else if (action === 'remove') {
            const index = window.allAttributes.indexOf(attribute);
            if (index > -1) {
                window.allAttributes.splice(index, 1);
            }
        }
    }

    /**
     * Update user count status
     */
    updateUserCountStatus() {
        setTimeout(() => {
            if (userManager) {
                userManager.filter();
            }
        }, 10);
    }

    /**
     * Add file to table (real-time)
     * @param {Object} file - File object with name, size, owner, upload_date
     */
    addFileToTable(file) {
        if (!this.filesTable) return;

        // Remove "No files uploaded yet" row if it exists
        const noFilesRow = this.filesTable.querySelector('tr td[colspan="5"]');
        if (noFilesRow) {
            noFilesRow.closest('tr').remove();
        }

        const tr = document.createElement('tr');
        tr.className = 'hover:bg-notion-hover transition-colors duration-150';
        tr.setAttribute('data-filename', file.name);

        tr.innerHTML = `
            <td class="px-4 py-3 font-medium text-notion-text">
                <span class="block max-w-[220px] truncate filename" title="${uiHelpers.escapeHtml(file.name)}">${uiHelpers.escapeHtml(file.name)}</span>
            </td>
            <td class="px-4 py-3 text-notion-text-secondary">${uiHelpers.escapeHtml(file.size || 'Unknown')}</td>
            <td class="px-4 py-3 text-notion-text-secondary">${uiHelpers.escapeHtml(file.owner || 'Unknown')}</td>
            <td class="px-4 py-3 text-notion-text-secondary">${uiHelpers.escapeHtml(file.upload_date || 'Just now')}</td>
            <td class="px-4 py-3">
                <div class="flex flex-col sm:flex-row items-start sm:items-center space-y-1 sm:space-y-0 sm:space-x-2">
                    <a href="/download/${encodeURIComponent(file.name)}" class="btn-action btn-action-download" 
                       aria-label="Download ${uiHelpers.escapeHtml(file.name)}" title="Download file">
                        <i data-lucide="download" class="w-4 h-4"></i>
                    </a>
                    <button type="button" onclick="if(confirm('Delete file?')) deleteFile('${uiHelpers.escapeHtml(file.name)}'); return false;" 
                            class="btn-action btn-action-delete" 
                            aria-label="Delete ${uiHelpers.escapeHtml(file.name)}" title="Delete file">
                        <i data-lucide="trash-2" class="w-4 h-4"></i>
                    </button>
                </div>
            </td>
        `;

        this.filesTable.insertBefore(tr, this.filesTable.firstChild);
        setTimeout(uiHelpers.reinitializeLucideIcons, 10);
    }

    /**
     * Remove file from table (real-time)
     * @param {string} filename - Name of the file to remove
     */
    removeFileFromTable(filename) {
        if (!this.filesTable) return;

        const fileRow = this.filesTable.querySelector(`tr[data-filename="${CSS.escape(filename)}"]`);
        if (fileRow) {
            fileRow.remove();
        }

        // If no files left, add the "No files uploaded yet" row
        const remainingRows = this.filesTable.querySelectorAll('tr');
        if (remainingRows.length === 0) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td colspan="5" class="px-4 py-8 text-center text-notion-text-secondary">
                    <div class="text-lg mb-2">No files uploaded yet</div>
                    <div class="text-sm">Files will appear here once uploaded</div>
                </td>
            `;
            this.filesTable.appendChild(tr);
        }
    }
}

// Global real-time manager instance
const realTimeManager = new RealTimeManager();
