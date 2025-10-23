/**
 * Attribute management functionality for role managers
 */

class RoleManagerAttributeManager {
    constructor() {
        this.selectedAttributes = new Set();
        this.userSelectElement = null;
        this.init();
    }

    /**
     * Initialize the manager
     */
    init() {
        // Get user select element
        this.userSelectElement = document.getElementById('rm-user-select');
        
        // Listen for user selection changes
        if (this.userSelectElement) {
            this.userSelectElement.addEventListener('change', () => {
                this.loadUserAttributes();
            });
        }
    }

    /**
     * Load and pre-select attributes for the selected user
     */
    loadUserAttributes() {
        const selectedUser = this.userSelectElement?.value;
        if (!selectedUser) {
            // Clear all selections
            this.selectedAttributes.clear();
            this.updateAttributeButtons();
            return;
        }

        // Get user's current attributes from the data embedded in the page
        const usersData = window.roleManagerUsers || {};
        const userData = usersData[selectedUser];
        
        let userAttrs = [];
        if (userData && typeof userData === 'object' && userData.attributes) {
            userAttrs = userData.attributes;
        } else if (Array.isArray(userData)) {
            userAttrs = userData;
        }

        // Pre-select user's current attributes
        this.selectedAttributes = new Set(userAttrs);
        this.updateAttributeButtons();
    }

    /**
     * Toggle an attribute selection
     * @param {HTMLElement} button - The attribute button clicked
     */
    toggleAttribute(button) {
        const attr = button.getAttribute('data-attr');
        if (this.selectedAttributes.has(attr)) {
            this.selectedAttributes.delete(attr);
            button.classList.remove('bg-notion-accent', 'text-white');
            button.classList.add('bg-notion-card', 'text-notion-text');
        } else {
            this.selectedAttributes.add(attr);
            button.classList.remove('bg-notion-card', 'text-notion-text');
            button.classList.add('bg-notion-accent', 'text-white');
        }
    }

    /**
     * Update attribute button states based on selected attributes
     */
    updateAttributeButtons() {
        const buttons = document.querySelectorAll('.rm-attr-btn');
        buttons.forEach(btn => {
            const attr = btn.getAttribute('data-attr');
            if (this.selectedAttributes.has(attr)) {
                btn.classList.remove('bg-notion-card', 'text-notion-text');
                btn.classList.add('bg-notion-accent', 'text-white');
            } else {
                btn.classList.remove('bg-notion-accent', 'text-white');
                btn.classList.add('bg-notion-card', 'text-notion-text');
            }
        });
    }

    /**
     * Add a new attribute
     */
    async add() {
        const attrInput = document.getElementById('rm-new-attr');
        const attr = attrInput.value.trim();
        
        this.clearMessages();

        if (!attr) {
            this.showError('Attribute name is required');
            return;
        }

        // Validate attribute format
        if (!/^[A-Za-z0-9_-]+$/.test(attr)) {
            this.showError('Attribute name can only contain letters, numbers, hyphens, and underscores');
            return;
        }

        try {
            const response = await fetch('/admin/add_attribute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attr })
            });

            const result = await response.json();
            if (result.success) {
                attrInput.value = '';
                this.showSuccess('Attribute added successfully. Reloading...');
                setTimeout(() => window.location.reload(), 1000);
            } else {
                this.showError(result.error || 'Error adding attribute');
            }
        } catch (error) {
            this.showError('Network error');
        }
    }

    /**
     * Remove an attribute
     * @param {string} attr - Attribute to remove
     */
    async remove(attr) {
        if (!confirm(`Remove attribute "${attr}"?\n\nNote: This will fail if any user has this attribute assigned.`)) {
            return;
        }

        this.clearMessages();

        try {
            const response = await fetch('/admin/remove_attribute', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ attr })
            });

            const result = await response.json();
            if (result.success) {
                this.showSuccess('Attribute removed successfully. Reloading...');
                setTimeout(() => window.location.reload(), 1000);
            } else {
                this.showError(result.error || 'Error removing attribute');
            }
        } catch (error) {
            this.showError('Network error');
        }
    }

    /**
     * Assign selected attributes to the selected user
     */
    async assignAttributes() {
        const selectedUser = this.userSelectElement?.value;
        
        this.clearMessages();

        if (!selectedUser) {
            this.showAssignError('Please select a user');
            return;
        }

        const attributes = Array.from(this.selectedAttributes);

        try {
            const response = await fetch('/role_manager/assign_attributes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ 
                    user: selectedUser, 
                    attributes: attributes 
                })
            });

            const result = await response.json();
            if (result.success) {
                this.showAssignSuccess(`Attributes successfully assigned to ${selectedUser}. Reloading...`);
                setTimeout(() => window.location.reload(), 1500);
            } else {
                this.showAssignError(result.error || 'Error assigning attributes');
            }
        } catch (error) {
            this.showAssignError('Network error');
        }
    }

    /**
     * Show error message (for add/remove operations)
     * @param {string} message - Error message
     */
    showError(message) {
        const errorDiv = document.getElementById('rm-attr-error');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }
    }

    /**
     * Show success message (for add/remove operations)
     * @param {string} message - Success message
     */
    showSuccess(message) {
        const errorDiv = document.getElementById('rm-attr-error');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.className = 'text-sm text-green-400 mt-2';
            errorDiv.style.display = 'block';
        }
    }

    /**
     * Show error message (for assign operations)
     * @param {string} message - Error message
     */
    showAssignError(message) {
        const errorDiv = document.getElementById('rm-assign-error');
        if (errorDiv) {
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
        }
    }

    /**
     * Show success message (for assign operations)
     * @param {string} message - Success message
     */
    showAssignSuccess(message) {
        const successDiv = document.getElementById('rm-assign-success');
        if (successDiv) {
            successDiv.textContent = message;
            successDiv.style.display = 'block';
        }
    }

    /**
     * Clear all messages
     */
    clearMessages() {
        const errorDiv = document.getElementById('rm-attr-error');
        if (errorDiv) {
            errorDiv.style.display = 'none';
            errorDiv.textContent = '';
            errorDiv.className = 'text-sm text-red-400 mt-2';
        }

        const assignErrorDiv = document.getElementById('rm-assign-error');
        if (assignErrorDiv) {
            assignErrorDiv.style.display = 'none';
            assignErrorDiv.textContent = '';
        }

        const assignSuccessDiv = document.getElementById('rm-assign-success');
        if (assignSuccessDiv) {
            assignSuccessDiv.style.display = 'none';
            assignSuccessDiv.textContent = '';
        }
    }
}

// Global instance for role manager attribute management
const roleManagerAttributeManager = new RoleManagerAttributeManager();
