/**
 * Audit log functionality for admin dashboard
 */

class AuditManager {
    /**
     * Filter audit logs by date range
     */
    filter() {
        const from = document.getElementById('audit-from').value;
        const to = document.getElementById('audit-to').value;
        const rows = document.querySelectorAll('#audit-tbody tr');
        let shown = 0;

        rows.forEach(row => {
            const timeCell = row.children[0];
            if (!timeCell) return;
            
            const timeStr = timeCell.textContent.trim();
            // Parse as YYYY-MM-DD HH:MM:SS
            const date = new Date(timeStr.replace(' ', 'T'));
            let show = true;

            if (from) {
                const fromDate = new Date(from);
                if (date < fromDate) show = false;
            }
            
            if (to) {
                // To date is inclusive, so add 1 day
                const toDate = new Date(to);
                toDate.setDate(toDate.getDate() + 1);
                if (date >= toDate) show = false;
            }

            row.style.display = show ? '' : 'none';
            if (show) shown++;
        });

        const noResults = document.getElementById('log-no-results');
        if (noResults) {
            noResults.style.display = shown ? 'none' : 'block';
        }
    }

    /**
     * Clear date filters
     */
    clearFilters() {
        const fromInput = document.getElementById('audit-from');
        const toInput = document.getElementById('audit-to');
        
        if (fromInput) fromInput.value = '';
        if (toInput) toInput.value = '';
        
        this.filter();
    }

    /**
     * Download audit logs with optional date filtering
     */
    async downloadLogs() {
        try {
            const fromDate = document.getElementById('audit-from')?.value || '';
            const toDate = document.getElementById('audit-to')?.value || '';
            
            // Build query parameters
            const params = new URLSearchParams();
            if (fromDate) params.append('from', fromDate);
            if (toDate) params.append('to', toDate);
            
            const url = `/admin/download_audit_logs${params.toString() ? '?' + params.toString() : ''}`;
            
            // Show loading indicator
            const originalContent = event?.target?.innerHTML;
            if (event?.target) {
                event.target.disabled = true;
                event.target.innerHTML = '<i data-lucide="loader" class="w-4 h-4 animate-spin"></i><span>Downloading...</span>';
                lucide.createIcons();
            }
            
            // Fetch the file
            const response = await fetch(url);
            
            if (!response.ok) {
                throw new Error('Failed to download audit logs');
            }
            
            // Get the blob
            const blob = await response.blob();
            
            // Create a download link
            const downloadUrl = window.URL.createObjectURL(blob);
            const link = document.createElement('a');
            link.href = downloadUrl;
            
            // Extract filename from Content-Disposition header or use default
            const contentDisposition = response.headers.get('Content-Disposition');
            let filename = 'audit_logs.json';
            if (contentDisposition) {
                const filenameMatch = contentDisposition.match(/filename="?(.+)"?/i);
                if (filenameMatch) {
                    filename = filenameMatch[1];
                }
            }
            
            link.download = filename;
            document.body.appendChild(link);
            link.click();
            
            // Cleanup
            document.body.removeChild(link);
            window.URL.revokeObjectURL(downloadUrl);
            
            // Show success message
            if (typeof showToast === 'function') {
                const dateRangeMsg = (fromDate || toDate) 
                    ? ` (${fromDate || 'beginning'} to ${toDate || 'now'})` 
                    : '';
                showToast(`Audit logs downloaded successfully${dateRangeMsg}`, 'success');
            }
            
        } catch (error) {
            console.error('Error downloading audit logs:', error);
            if (typeof showToast === 'function') {
                showToast('Failed to download audit logs', 'error');
            } else {
                alert('Failed to download audit logs');
            }
        } finally {
            // Restore button state
            if (event?.target) {
                event.target.disabled = false;
                if (originalContent) {
                    event.target.innerHTML = originalContent;
                    lucide.createIcons();
                }
            }
        }
    }
}

// Global audit manager instance
const auditManager = new AuditManager();

// Global function for backward compatibility
function downloadAuditLogs() {
    auditManager.downloadLogs();
}
