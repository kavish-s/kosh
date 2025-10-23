/**
 * Event handlers for admin dashboard links and buttons
 */

class AdminLinks {
    /**
     * Setup event listeners for all admin links and buttons
     */
    setup() {
        this.setupPolicyLinks();
        this.setupUserLinks();
        this.setupAttributeButtons();
    }

    /**
     * Setup policy edit and delete links
     */
    setupPolicyLinks() {
        document.querySelectorAll('.edit-policy-link').forEach(link => {
            link.removeEventListener('click', this.handlePolicyEdit);
            link.addEventListener('click', this.handlePolicyEdit);
        });
    }

    /**
     * Setup user edit and delete links
     */
    setupUserLinks() {
        document.querySelectorAll('.edit-user-link').forEach(link => {
            link.removeEventListener('click', this.handleUserEdit);
            link.addEventListener('click', this.handleUserEdit);
        });

        document.querySelectorAll('.delete-user-link').forEach(link => {
            link.removeEventListener('click', this.handleUserDelete);
            link.addEventListener('click', this.handleUserDelete);
        });

        document.querySelectorAll('.manage-roles-link').forEach(link => {
            link.removeEventListener('click', this.handleManageRoles);
            link.addEventListener('click', this.handleManageRoles);
        });
    }

    /**
     * Setup attribute delete buttons
     */
    setupAttributeButtons() {
        // Handle dynamically created attribute delete buttons
        setTimeout(() => {
            const deleteButtons = document.querySelectorAll('button[onclick*="removeAttribute"]');
            deleteButtons.forEach(btn => {
                btn.removeEventListener('click', this.handleAttributeDelete);
                btn.addEventListener('click', this.handleAttributeDelete);
            });
        }, 100);
    }

    /**
     * Handle policy edit link click
     * @param {Event} e - Click event
     */
    handlePolicyEdit(e) {
        e.preventDefault();
        const file = this.getAttribute('data-file');
        const policy = this.getAttribute('data-policy');
        policyManager.openEditModal(file, policy);
    }

    /**
     * Handle user edit link click
     * @param {Event} e - Click event
     */
    handleUserEdit(e) {
        e.preventDefault();
        const user = this.getAttribute('data-user');
        const attrs = this.getAttribute('data-attrs') || '';
        userManager.openEditModal(user, attrs);
    }

    /**
     * Handle user delete link click
     * @param {Event} e - Click event
     */
    handleUserDelete(e) {
        e.preventDefault();
        const user = this.getAttribute('data-user');
        if (user) {
            userManager.delete(user);
        }
    }

    /**
     * Handle manage roles link click
     * @param {Event} e - Click event
     */
    handleManageRoles(e) {
        e.preventDefault();
        const user = this.getAttribute('data-user');
        const roles = this.getAttribute('data-roles') || '';
        if (user) {
            userManager.openManageRolesModal(user, roles);
        }
    }

    /**
     * Handle attribute delete button click
     * @param {Event} e - Click event
     */
    handleAttributeDelete(e) {
        e.preventDefault();
        e.stopPropagation();
        const onclickAttr = this.getAttribute('onclick');
        const match = onclickAttr.match(/removeAttribute\('([^']+)'\)/);
        if (match) {
            const attrName = match[1];
            attributeManager.remove(attrName);
        }
    }

    /**
     * Initialize on DOM ready
     */
    initialize() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                this.setup();
                // Initialize filters to show counts
                userManager.filter();
                policyManager.filter();
            });
        } else {
            // DOM already ready — run immediately
            this.setup();
            userManager.filter();
            policyManager.filter();
        }
    }
}

// Global admin links instance
const adminLinks = new AdminLinks();
