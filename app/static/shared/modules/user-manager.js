/**
 * User management functionality for admin dashboard
 */

class UserManager {
    /**
     * Filter users based on search input and attribute filter
     */
    filter() {
        const input = document.getElementById('user-search').value.toLowerCase();
        const attrFilter = document.getElementById('attr-filter').value.toLowerCase();
        const rows = document.querySelectorAll('#users-table tbody tr');
        const totalCount = rows.length;
        let visibleCount = 0;

        rows.forEach(row => {
            const user = row.children[1].textContent.toLowerCase();
            const attrs = row.children[2].textContent.toLowerCase();
            const matchesText = user.includes(input) || attrs.includes(input);
            
            // Compute attribute tokens from the row and from the filter
            const rowAttrs = attrs.split(',').map(s => s.trim()).filter(Boolean);
            const filterTokens = attrFilter.split(',').map(s => s.trim()).filter(Boolean);
            const matchesAttr = filterTokens.length === 0 || filterTokens.every(tok => rowAttrs.includes(tok));
            const shouldShow = (matchesText && matchesAttr);

            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
        });

        // Update no results display
        const noResults = document.getElementById('user-no-results');
        const table = document.getElementById('users-table');
        if (visibleCount === 0) {
            if (table) table.style.display = 'none';
            if (noResults) noResults.style.display = 'block';
        } else {
            if (table) table.style.display = 'table';
            if (noResults) noResults.style.display = 'none';
        }

        // Update status indicator
        const status = document.getElementById('user-count-status');
        if (status) {
            if (input || attrFilter) {
                status.textContent = `Showing ${visibleCount} of ${totalCount} users`;
            } else {
                status.textContent = `Showing all ${totalCount} users`;
            }
        }
    }

    /**
     * Toggle all user checkboxes
     * @param {HTMLInputElement} source - Source checkbox
     */
    toggleAll(source) {
        document.querySelectorAll('input[name="user_bulk"]').forEach(cb => {
            cb.checked = source.checked;
        });
    }

    /**
     * Bulk delete selected users
     */
    async bulkDelete() {
        const selected = Array.from(document.querySelectorAll('input[name="user_bulk"]:checked'))
            .map(cb => cb.value);
        
        if (!selected.length) {
            toastManager.show('Select users to delete.', 'error');
            return;
        }
        
        if (!confirm('Delete selected users?')) return;

        try {
            const response = await fetch('/admin/bulk_delete_users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ users: selected })
            });

            const result = await response.json();
            if (result.success) {
                toastManager.show(`${selected.length} users deleted`, 'success');
                this.filter(); // Update count
            } else {
                toastManager.show('Error deleting users', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }

    /**
     * Open bulk attribute setting modal
     */
    openBulkAttrModal() {
        modalManager.show(`
            <h3 class='text-lg font-bold mb-2'>Bulk Set Attributes</h3>
            <form id='bulk-attr-form'>
                <input type='text' name='attrs' placeholder='Comma separated attributes' 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text' required>
                <button type='submit' class='btn-primary px-4 py-2 rounded text-white'>Set Attributes</button>
            </form>
        `);

        document.getElementById('bulk-attr-form').onsubmit = async (e) => {
            e.preventDefault();
            await this.bulkSetAttributes(e.target);
        };
    }

    /**
     * Bulk set attributes for selected users
     * @param {HTMLFormElement} form - Form element
     */
    async bulkSetAttributes(form) {
        const attrs = form.attrs.value;
        const selected = Array.from(document.querySelectorAll('input[name="user_bulk"]:checked'))
            .map(cb => cb.value);

        if (!selected.length) {
            toastManager.show('Select users to set attributes', 'error');
            return;
        }

        try {
            const response = await fetch('/admin/bulk_set_attrs', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ users: selected, attrs })
            });

            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                const err = data?.error || 'Error setting attributes';
                toastManager.show(err, 'error');
                return;
            }

            const data = await response.json().catch(() => ({}));
            if (data?.success) {
                modalManager.close();
                toastManager.show('Attributes updated', 'success');
            } else {
                toastManager.show('Error setting attributes', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }

    /**
     * Open add user modal
     */
    openAddModal() {
        const allAttributes = window.allAttributes || [];

        let buttons = '';
        allAttributes.forEach(attr => {
            buttons += `
                <button type='button' class='attr-btn px-2 py-1 text-xs rounded-full mr-2 mb-2 
                    bg-notion-card text-notion-text-secondary' 
                    data-attr='${uiHelpers.escapeHtml(attr)}' aria-pressed='false'>
                    ${uiHelpers.escapeHtml(attr)}
                </button>
            `;
        });

        modalManager.show(`
            <h3 class='text-lg font-bold mb-2'>Add User</h3>
            <form id='add-user-form'>
                <input type='text' name='user' placeholder='Username' required 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text'>
                <div class='mb-3'>
                    <label class='block text-sm font-medium text-notion-text mb-2'>Attributes</label>
                    <div id='attr-btn-group'>${buttons}</div>
                </div>
                <button type='submit' class='btn-primary px-4 py-2 rounded text-white'>Add</button>
            </form>
        `);

        // Setup attribute button toggles
        document.querySelectorAll('.attr-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                this.classList.toggle('bg-notion-accent/20');
                this.classList.toggle('text-notion-accent');
                this.classList.toggle('bg-notion-card');
                this.classList.toggle('text-notion-text-secondary');
                this.setAttribute('aria-pressed', 
                    this.classList.contains('bg-notion-accent/20') ? 'true' : 'false');
            });
        });

        document.getElementById('add-user-form').onsubmit = async (e) => {
            e.preventDefault();
            await this.add(e.target);
        };
    }

    /**
     * Add a new user
     * @param {HTMLFormElement} form - Form element
     */
    async add(form) {
        const user = form.user.value.trim();
        const selectedAttrs = Array.from(document.querySelectorAll('.attr-btn.bg-notion-accent\\/20'))
            .map(btn => btn.getAttribute('data-attr'));

        if (!user) {
            toastManager.show('Username required', 'error');
            return;
        }

        try {
            const response = await fetch('/admin/add_user', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ user, attributes: selectedAttrs.join(', ') })
            });

            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                const err = data?.error || 'Error adding user';
                toastManager.show(err, 'error');
                return;
            }

            const data = await response.json().catch(() => ({}));
            if (data?.success) {
                modalManager.close();
                toastManager.show('User added', 'success');
            } else {
                toastManager.show('Error adding user', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }

    /**
     * Open edit user modal
     * @param {string} user - Username
     * @param {string} attrs - Current attributes
     */
    openEditModal(user, attrs) {
        const safeUser = uiHelpers.escapeHtml(user || '');
        const selectedAttrs = (attrs || '').split(',').map(a => a.trim()).filter(Boolean);
        const allAttributes = window.allAttributes || [];

        let buttons = '';
        allAttributes.forEach(attr => {
            const selected = selectedAttrs.includes(attr);
            buttons += `
                <button type='button' class='attr-btn px-2 py-1 text-xs rounded-full mr-2 mb-2 
                    ${selected ? 'bg-notion-accent/20 text-notion-accent' : 'bg-notion-card text-notion-text-secondary'}' 
                    data-attr='${uiHelpers.escapeHtml(attr)}' aria-pressed='${selected}'>
                    ${uiHelpers.escapeHtml(attr)}
                </button>
            `;
        });

        modalManager.show(`
            <h3 class='text-lg font-bold mb-2'>Edit User</h3>
            <form id='edit-user-form'>
                <input type='text' name='user' value='${safeUser}' readonly 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text'>
                <div class='mb-3' id='attr-btn-group'>${buttons}</div>
                <button type='submit' class='btn-primary px-4 py-2 rounded text-white'>Save</button>
            </form>
        `);

        // Setup attribute button toggles
        document.querySelectorAll('.attr-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                this.classList.toggle('bg-notion-accent/20');
                this.classList.toggle('text-notion-accent');
                this.classList.toggle('bg-notion-card');
                this.classList.toggle('text-notion-text-secondary');
                this.setAttribute('aria-pressed', 
                    this.classList.contains('bg-notion-accent/20') ? 'true' : 'false');
            });
        });

        document.getElementById('edit-user-form').onsubmit = async (e) => {
            e.preventDefault();
            await this.edit(user, e.target);
        };
    }

    /**
     * Edit user attributes
     * @param {string} user - Username
     * @param {HTMLFormElement} form - Form element
     */
    async edit(user, form) {
        const selected = Array.from(document.querySelectorAll('.attr-btn.bg-notion-accent\\/20'))
            .map(btn => btn.getAttribute('data-attr'));

        try {
            const response = await fetch(`/admin/edit_user/${encodeURIComponent(user)}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({ attributes: selected.join(', ') })
            });

            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                const err = data?.error || 'Error editing user';
                modalManager.showInlineError(form, err);
                return;
            }

            const data = await response.json().catch(() => ({}));
            if (data?.success) {
                modalManager.close();
                toastManager.show('User updated', 'success');
            } else {
                toastManager.show('Error editing user', 'error');
            }
        } catch (error) {
            modalManager.showInlineError(form, 'Network error');
        }
    }

    /**
     * Delete a user
     * @param {string} user - Username
     */
    async delete(user) {
        if (!confirm('Delete user?')) return;

        try {
            const response = await fetch('/admin/delete_user', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ user })
            });

            const result = await response.json();
            if (result.success) {
                toastManager.show('User deleted', 'success');
                this.filter(); // Update count
            } else {
                toastManager.show('Error deleting user', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }
}

// Global user manager instance
const userManager = new UserManager();
