/**
 * Main initialization script for admin dashboard
 */

class AdminDashboard {
    constructor() {
        this.initialized = false;
    }

    /**
     * Initialize the admin dashboard
     */
    init() {
        if (this.initialized) return;

        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.initializeComponents());
        } else {
            this.initializeComponents();
        }

        this.initialized = true;
    }

    /**
     * Initialize all components
     */
    initializeComponents() {
        try {
            // Initialize UI helpers and keyboard shortcuts
            uiHelpers.setupKeyboardShortcuts();

            // Initialize admin links and event handlers
            adminLinks.initialize();

            // Initialize real-time functionality
            realTimeManager.initialize();

            // Initialize Lucide icons
            this.initializeLucideIcons();

            // Setup global functions for backward compatibility
            this.setupGlobalFunctions();

            // Make global attributes available
            this.initializeGlobalAttributes();

            console.log('✅ Admin Dashboard initialized successfully');
        } catch (error) {
            console.error('❌ Error initializing admin dashboard:', error);
        }
    }

    /**
     * Initialize Lucide icons
     */
    initializeLucideIcons() {
        if (typeof lucide !== 'undefined') {
            lucide.createIcons();
        }
    }

    /**
     * Setup global functions for backward compatibility with existing HTML
     */
    setupGlobalFunctions() {
        // Modal functions
        window.showModal = (html) => modalManager.show(html);
        window.closeModal = (e) => modalManager.close(e);

        // Toast functions
        window.showToast = (message, type) => toastManager.show(message, type);

        // User management functions
        window.filterUsers = () => userManager.filter();
        window.toggleAllUsers = (source) => userManager.toggleAll(source);
        window.bulkDeleteUsers = () => userManager.bulkDelete();
        window.openBulkAttrModal = () => userManager.openBulkAttrModal();
        window.openUserModal = () => userManager.openAddModal();
        window.openEditUserModal = (user, attrs) => userManager.openEditModal(user, attrs);
        window.deleteUser = (user) => userManager.delete(user);
        window.openManageRolesModal = (user, roles) => userManager.openManageRolesModal(user, roles);

        // Policy management functions
        window.filterPolicies = () => policyManager.filter();
        window.toggleAllPolicies = (source) => policyManager.toggleAll(source);
        window.bulkDeletePolicies = () => policyManager.bulkDelete();
        window.openPolicyModal = () => policyManager.openAddModal();
        window.openEditPolicyModal = (file, policy) => policyManager.openEditModal(file, policy);
        window.deletePolicy = (file) => policyManager.delete(file);

        // Attribute management functions
        window.addAttribute = () => attributeManager.add();
        window.removeAttribute = (attr) => attributeManager.remove(attr);

        // Audit log functions
        window.filterAuditLogs = () => auditManager.filter();

        // File management functions
        window.deleteFile = (filename) => fileManager.delete(filename);

        // Utility functions
        window.formatAttributesAsHtml = (attrs) => uiHelpers.formatAttributesAsHtml(attrs);
        window.escapeHtml = (text) => uiHelpers.escapeHtml(text);
        window.refreshTailwindStyles = (element) => uiHelpers.refreshTailwindStyles(element);
        window.reinitializeLucideIcons = () => uiHelpers.reinitializeLucideIcons();

        // Setup admin links
        window.setupAdminLinks = () => adminLinks.setup();

        // Legacy compatibility functions for real-time updates
        window.addUserToTable = (user, attrs) => realTimeManager.addUserToTable(user, attrs);
        window.updateUserInTable = (user, attrs) => realTimeManager.updateUserInTable(user, attrs);
        window.removeUserFromTable = (user) => realTimeManager.removeUserFromTable(user);
        window.addPolicyToTable = (file, policy) => realTimeManager.addPolicyToTable(file, policy);
        window.updatePolicyInTable = (file, policy) => realTimeManager.updatePolicyInTable(file, policy);
        window.removePolicyFromTable = (file) => realTimeManager.removePolicyFromTable(file);
        window.addFileToTable = (file) => realTimeManager.addFileToTable(file);
        window.removeFileFromTable = (filename) => realTimeManager.removeFileFromTable(filename);
        window.addAuditLogToTable = (entry) => realTimeManager.addAuditLogToTable(entry);
        window.addAttributeToUI = (attr) => realTimeManager.addAttributeToUI(attr);
        window.removeAttributeFromUI = (attr) => realTimeManager.removeAttributeFromUI(attr);
        window.updateUserCountStatus = () => realTimeManager.updateUserCountStatus();
    }

    /**
     * Initialize global attributes for modals
     */
    initializeGlobalAttributes() {
        // This will be set by the template, but ensure it exists
        if (!window.allAttributes) {
            window.allAttributes = [];
        }
    }
}

// Initialize admin dashboard
const adminDashboard = new AdminDashboard();
adminDashboard.init();
