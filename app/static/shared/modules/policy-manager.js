/**
 * Policy management functionality for admin dashboard
 */

class PolicyManager {
    /**
     * Filter policies based on search input
     */
    filter() {
        const input = document.getElementById('policy-search').value.toLowerCase();
        const rows = document.querySelectorAll('#policies-table tbody tr');
        let visibleCount = 0;

        rows.forEach(row => {
            const file = row.children[1].textContent.toLowerCase();
            const policy = row.children[2].textContent.toLowerCase();
            const shouldShow = file.includes(input) || policy.includes(input);

            row.style.display = shouldShow ? '' : 'none';
            if (shouldShow) visibleCount++;
        });

        // Update no results display
        const noResults = document.getElementById('policy-no-results');
        const table = document.getElementById('policies-table');
        if (visibleCount === 0) {
            if (table) table.style.display = 'none';
            if (noResults) noResults.style.display = 'block';
        } else {
            if (table) table.style.display = 'table';
            if (noResults) noResults.style.display = 'none';
        }
    }

    /**
     * Toggle all policy checkboxes
     * @param {HTMLInputElement} source - Source checkbox
     */
    toggleAll(source) {
        document.querySelectorAll('input[name="policy_bulk"]').forEach(cb => {
            cb.checked = source.checked;
        });
    }

    /**
     * Bulk delete selected policies
     */
    async bulkDelete() {
        const selected = Array.from(document.querySelectorAll('input[name="policy_bulk"]:checked'))
            .map(cb => cb.value);
        
        if (!selected.length) {
            toastManager.show('Select policies to delete.', 'error');
            return;
        }
        
        if (!confirm('Delete selected policies?')) return;

        try {
            const response = await fetch('/admin/bulk_delete_policies', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ files: selected })
            });

            const result = await response.json();
            if (result.success) {
                selected.forEach(file => {
                    const row = document.querySelector(`#policies-table input[value="${file}"]`);
                    if (row) row.closest('tr').remove();
                });
                toastManager.show(`${selected.length} policies deleted`, 'success');
            } else {
                toastManager.show('Error deleting policies', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }

    /**
     * Open add policy modal
     */
    openAddModal() {
        modalManager.show(`
            <h3 class='text-lg font-bold mb-2'>Add Policy</h3>
            <form id='add-policy-form'>
                <input type='text' name='file' placeholder='File name' required 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text'>
                <input type='text' name='policy' placeholder='Comma separated attributes' required 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text'>
                <button type='submit' class='btn-primary px-4 py-2 rounded text-white'>Add</button>
            </form>
        `);

        document.getElementById('add-policy-form').onsubmit = async (e) => {
            e.preventDefault();
            await this.add(e.target);
        };
    }

    /**
     * Add a new policy
     * @param {HTMLFormElement} form - Form element
     */
    async add(form) {
        try {
            const response = await fetch('/admin/add_policy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({ 
                    file: form.file.value, 
                    policy: form.policy.value 
                }).toString()
            });

            if (response.ok) {
                window.location.reload();
            } else {
                toastManager.show('Error adding policy', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }

    /**
     * Open edit policy modal
     * @param {string} file - Filename
     * @param {string} policy - Current policy
     */
    openEditModal(file, policy) {
        const selectedAttrs = (policy || '').split(',').map(a => a.trim()).filter(Boolean);
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
            <h3 class='text-lg font-bold mb-2'>Edit Policy</h3>
            <form id='edit-policy-form'>
                <input type='text' name='file' value='${uiHelpers.escapeHtml(file)}' readonly 
                    class='w-full mb-3 px-3 py-2 rounded border border-notion-border bg-notion-input text-notion-text'>
                <div class='mb-3' id='policy-btn-group'>${buttons}</div>
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

        document.getElementById('edit-policy-form').onsubmit = async (e) => {
            e.preventDefault();
            await this.edit(e.target);
        };
    }

    /**
     * Edit policy
     * @param {HTMLFormElement} form - Form element
     */
    async edit(form) {
        const selected = Array.from(document.querySelectorAll('#policy-btn-group .attr-btn.bg-notion-accent\\/20'))
            .map(btn => btn.getAttribute('data-attr'));

        try {
            const response = await fetch(`/admin/edit_policy/${encodeURIComponent(form.file.value)}`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'X-Requested-With': 'XMLHttpRequest',
                    'Accept': 'application/json'
                },
                body: new URLSearchParams({ policy: selected.join(', ') }).toString()
            });

            if (!response.ok) {
                const data = await response.json().catch(() => ({}));
                const err = data?.error || 'Error editing policy';
                modalManager.showInlineError(form, err);
                return;
            }

            const data = await response.json().catch(() => ({}));
            if (data?.success) {
                modalManager.close();
                toastManager.show('Policy updated', 'success');
            } else {
                const err = data?.error || 'Error editing policy';
                modalManager.showInlineError(form, err);
            }
        } catch (error) {
            modalManager.showInlineError(form, 'Network error');
        }
    }

    /**
     * Delete a policy
     * @param {string} file - Filename
     */
    async delete(file) {
        if (!confirm('Delete policy?')) return;

        try {
            const response = await fetch('/admin/delete_policy', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ file })
            });

            const result = await response.json();
            if (result.success) {
                const row = document.querySelector(`#policies-table input[value="${file}"]`);
                if (row) row.closest('tr').remove();
                toastManager.show('Policy deleted', 'success');
            } else {
                toastManager.show('Error deleting policy', 'error');
            }
        } catch (error) {
            toastManager.show('Network error', 'error');
        }
    }
}

// Global policy manager instance
const policyManager = new PolicyManager();
