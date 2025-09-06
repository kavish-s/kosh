/**
 * Upload Manager
 * Handles file upload functionality with drag & drop, progress tracking, and validation
 */

class UploadManager {
    constructor(notificationManager) {
        this.notification = notificationManager;
        this.currentXhr = null;
        this.elements = {};
        this.init();
    }

    init() {
        this.cacheElements();
        this.bindEvents();
        this.setupDragAndDrop();
        this.setupAttributeButtons();
        this.updateUploadButtonState();
    }

    cacheElements() {
        this.elements = {
            fileInput: document.getElementById('file-input'),
            uploadZone: document.getElementById('upload-zone'),
            fileList: document.getElementById('file-list'),
            uploadBtn: document.getElementById('upload-btn'),
            policyInput: document.getElementById('policy'),
            progressContainer: document.getElementById('progress-container'),
            progressBar: document.getElementById('progress-bar'),
            progressPercent: document.getElementById('progress-percent'),
            progressTime: document.getElementById('progress-time'),
            cancelBtn: document.getElementById('cancel-upload'),
            uploadForm: document.getElementById('upload-form')
        };
    }

    bindEvents() {
        this.elements.fileInput?.addEventListener('change', (e) => {
            this.renderFileList(e.target.files);
            this.updateUploadButtonState();
        });

        this.elements.policyInput?.addEventListener('input', () => {
            this.updateUploadButtonState();
            this.syncAttributeButtons();
        });

        this.elements.uploadForm?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.handleUpload();
        });

        this.elements.cancelBtn?.addEventListener('click', () => {
            this.cancelUpload();
        });
    }

    setupDragAndDrop() {
        let dragCounter = 0;
        
        this.elements.uploadZone?.addEventListener('dragenter', (e) => {
            e.preventDefault();
            dragCounter++;
            this.elements.uploadZone.classList.add('dragover');
        });
        
        this.elements.uploadZone?.addEventListener('dragover', (e) => {
            e.preventDefault();
        });
        
        this.elements.uploadZone?.addEventListener('dragleave', (e) => {
            e.preventDefault();
            dragCounter--;
            if (dragCounter === 0) {
                this.elements.uploadZone.classList.remove('dragover');
            }
        });
        
        this.elements.uploadZone?.addEventListener('drop', (e) => {
            e.preventDefault();
            dragCounter = 0;
            this.elements.uploadZone.classList.remove('dragover');
            
            if (e.dataTransfer?.files?.length > 0) {
                this.setFiles(e.dataTransfer.files);
            }
        });
    }

    setupAttributeButtons() {
        document.querySelectorAll('.attr-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const attr = btn.getAttribute('data-attr');
                this.toggleAttribute(attr);
            });
        });
    }

    toggleAttribute(attr) {
        let current = this.elements.policyInput.value.split(',').map(a => a.trim()).filter(Boolean);
        
        if (current.includes(attr)) {
            current = current.filter(a => a !== attr);
        } else {
            current.push(attr);
        }
        
        this.elements.policyInput.value = current.join(', ');
        this.elements.policyInput.dispatchEvent(new Event('input'));
    }

    syncAttributeButtons() {
        const currentAttrs = this.elements.policyInput.value.split(',').map(a => a.trim()).filter(Boolean);
        
        document.querySelectorAll('.attr-btn').forEach(btn => {
            const attr = btn.getAttribute('data-attr');
            if (currentAttrs.includes(attr)) {
                btn.classList.add('bg-notion-accent/20', 'text-notion-accent');
                btn.classList.remove('bg-notion-card', 'text-notion-text-secondary');
                btn.setAttribute('aria-pressed', 'true');
            } else {
                btn.classList.remove('bg-notion-accent/20', 'text-notion-accent');
                btn.classList.add('bg-notion-card', 'text-notion-text-secondary');
                btn.setAttribute('aria-pressed', 'false');
            }
        });
    }

    setFiles(files) {
        try {
            const dt = new DataTransfer();
            for (let i = 0; i < files.length; i++) {
                dt.items.add(files[i]);
            }
            this.elements.fileInput.files = dt.files;
        } catch (err) {
            this.elements.fileInput.files = files;
        }
        
        this.renderFileList(this.elements.fileInput.files);
        this.updateUploadButtonState();
    }

    formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let i = 0;
        let size = bytes;
        while (size >= 1024 && i < units.length - 1) {
            size /= 1024;
            i++;
        }
        return `${size.toFixed(2)} ${units[i]}`;
    }

    validateFiles(files) {
        let totalSize = 0;
        const invalidFiles = [];

        for (let i = 0; i < files.length; i++) {
            totalSize += files[i].size;
        }

        return {
            valid: true,
            errors: invalidFiles,
            totalSize: totalSize
        };
    }

    renderFileList(files) {
        if (!this.elements.fileList) return;
        
        this.elements.fileList.innerHTML = '';
        
        if (!files || files.length === 0) {
            this.elements.fileList.innerHTML = '<div class="text-notion-text-secondary text-sm">No files selected</div>';
            return;
        }

        const validation = this.validateFiles(files);
        
        if (!validation.valid) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'text-red-400 text-sm mb-2';
            errorDiv.innerHTML = `<strong>File validation errors:</strong><br>${validation.errors.join('<br>')}`;
            this.elements.fileList.appendChild(errorDiv);
        }

        const frag = document.createDocumentFragment();
        
        for (let i = 0; i < files.length; i++) {
            const item = this.createFileListItem(files[i], i);
            frag.appendChild(item);
        }
        
        const summary = this.createFileListSummary(files, validation);
        this.elements.fileList.appendChild(frag);
        this.elements.fileList.appendChild(summary);
        
        lucide.createIcons();
    }

    createFileListItem(file, index) {
        const item = document.createElement('div');
        item.className = 'mb-2 flex items-center justify-between p-2 rounded border border-notion-border bg-notion-bg/30 hover:bg-notion-hover transition-colors';
        
        item.innerHTML = `
            <div class="flex items-center min-w-0">
                <div class="w-4 h-4 mr-2 flex-shrink-0">📄</div>
                <div class="truncate text-notion-text" style="max-width: 50%;" title="${file.name}">${file.name}</div>
            </div>
            <div class="flex items-center space-x-2">
                <div class="text-notion-text-secondary text-xs">${this.formatSize(file.size)}</div>
                <button type="button" class="ml-2 p-1 rounded-full bg-red-500/10 text-red-400 hover:bg-red-500/20 hover:text-red-300 transition-colors flex-shrink-0" 
                        title="Remove ${file.name}" aria-label="Remove ${file.name}">
                    <i data-lucide="x" class="w-3 h-3"></i>
                </button>
            </div>
        `;
        
        const removeBtn = item.querySelector('button');
        removeBtn.addEventListener('click', () => this.removeFileFromList(index));
        
        return item;
    }

    createFileListSummary(files, validation) {
        const summary = document.createElement('div');
        summary.className = 'text-notion-text-secondary text-sm mt-2 p-2 bg-notion-input rounded';
        
        summary.innerHTML = `
            <div class="flex items-center justify-between">
                <div>
                    <strong>${files.length} file(s) selected</strong><br>
                    Total size: ${this.formatSize(validation.totalSize)}<br>
                    ${validation.valid ? '✅ Ready to upload' : '❌ Please fix errors above'}
                </div>
                <button type="button" id="clear-all-files" class="btn-secondary px-3 py-1 rounded text-xs font-medium text-notion-text hover:text-white flex items-center space-x-1">
                    <i data-lucide="trash-2" class="w-3 h-3"></i>
                    <span>Clear All</span>
                </button>
            </div>
        `;
        
        const clearAllBtn = summary.querySelector('#clear-all-files');
        clearAllBtn?.addEventListener('click', () => {
            if (confirm('Are you sure you want to remove all selected files?')) {
                this.clearAllFiles();
            }
        });
        
        return summary;
    }

    removeFileFromList(indexToRemove) {
        if (!this.elements.fileInput.files || indexToRemove < 0 || indexToRemove >= this.elements.fileInput.files.length) return;
        
        const dt = new DataTransfer();
        for (let i = 0; i < this.elements.fileInput.files.length; i++) {
            if (i !== indexToRemove) {
                dt.items.add(this.elements.fileInput.files[i]);
            }
        }
        
        this.elements.fileInput.files = dt.files;
        this.renderFileList(this.elements.fileInput.files);
        this.updateUploadButtonState();
        
        this.notification.show('File removed from upload queue', 'success');
    }

    clearAllFiles() {
        const dt = new DataTransfer();
        this.elements.fileInput.files = dt.files;
        this.renderFileList(this.elements.fileInput.files);
        this.updateUploadButtonState();
        this.notification.show('All files cleared from upload queue', 'success');
    }

    updateUploadButtonState() {
        if (!this.elements.uploadBtn) return;
        
        const hasFiles = this.elements.fileInput.files && this.elements.fileInput.files.length > 0;
        const policyOk = this.elements.policyInput.value && this.elements.policyInput.value.trim().length > 0;
        const filesValid = hasFiles ? this.validateFiles(this.elements.fileInput.files).valid : false;
        
        if (hasFiles && policyOk && filesValid) {
            this.elements.uploadBtn.disabled = false;
            this.elements.uploadBtn.setAttribute('aria-disabled', 'false');
            this.elements.uploadBtn.classList.remove('opacity-60');
        } else {
            this.elements.uploadBtn.disabled = true;
            this.elements.uploadBtn.setAttribute('aria-disabled', 'true');
            this.elements.uploadBtn.classList.add('opacity-60');
        }
    }

    async handleUpload() {
        if (!this.elements.fileInput.files || this.elements.fileInput.files.length === 0) return;
        if (!this.elements.policyInput.value || this.elements.policyInput.value.trim().length === 0) return;

        const formData = new FormData();
        for (let i = 0; i < this.elements.fileInput.files.length; i++) {
            formData.append('file', this.elements.fileInput.files[i]);
        }
        formData.append('policy', this.elements.policyInput.value.trim());

        // Add CSRF token if present
        const csrfToken = document.querySelector('input[name="csrf_token"]');
        if (csrfToken) {
            formData.append('csrf_token', csrfToken.value);
        }

        this.startUpload(formData);
    }

    startUpload(formData) {
        const xhr = new XMLHttpRequest();
        this.currentXhr = xhr;
        
        xhr.open('POST', this.elements.uploadForm.getAttribute('action') || '/upload', true);

        this.showProgress();
        this.disableForm();

        let startTime = null;
        
        xhr.upload.addEventListener('progress', (evt) => {
            this.updateProgress(evt, startTime);
            if (!startTime) startTime = Date.now();
        });

        xhr.onload = () => this.handleUploadComplete(xhr);
        xhr.onerror = () => this.handleUploadError();
        xhr.ontimeout = () => this.handleUploadTimeout();

        xhr.send(formData);
    }

    showProgress() {
        if (this.elements.progressContainer) {
            this.elements.progressContainer.style.display = 'block';
            this.elements.progressBar.style.width = '0%';
            this.elements.progressBar.setAttribute('aria-valuenow', '0');
            this.elements.progressPercent.textContent = '0%';
            this.elements.progressTime.textContent = 'Starting...';
        }
    }

    updateProgress(evt, startTime) {
        if (!evt.lengthComputable) return;
        
        const percent = Math.round((evt.loaded / evt.total) * 100);
        this.elements.progressBar.style.width = percent + '%';
        this.elements.progressBar.setAttribute('aria-valuenow', String(percent));
        this.elements.progressPercent.textContent = percent + '%';
        
        if (startTime) {
            const elapsed = (Date.now() - startTime) / 1000;
            const speed = evt.loaded / Math.max(elapsed, 0.001);
            const remaining = evt.total - evt.loaded;
            const eta = speed > 0 ? (remaining / speed) : 0;
            this.elements.progressTime.textContent = eta > 1 ? `~${Math.ceil(eta)}s left` : 'Almost done';
        }
    }

    disableForm() {
        if (this.elements.cancelBtn) {
            this.elements.cancelBtn.disabled = false;
            this.elements.cancelBtn.setAttribute('aria-disabled', 'false');
        }
        
        if (this.elements.uploadBtn) {
            this.elements.uploadBtn.disabled = true;
            this.elements.uploadBtn.setAttribute('aria-disabled', 'true');
            this.elements.uploadBtn.innerHTML = '<div class="loading-spinner inline-block mr-2"></div><span>Uploading...</span>';
        }
        
        if (this.elements.fileInput) this.elements.fileInput.disabled = true;
        if (this.elements.policyInput) this.elements.policyInput.disabled = true;
    }

    enableForm() {
        if (this.elements.fileInput) this.elements.fileInput.disabled = false;
        if (this.elements.policyInput) this.elements.policyInput.disabled = false;
        
        if (this.elements.uploadBtn) {
            this.elements.uploadBtn.innerHTML = '<i data-lucide="upload" class="w-4 h-4"></i><span>Upload file</span>';
            lucide.createIcons();
        }
        
        this.updateUploadButtonState();
    }

    handleUploadComplete(xhr) {
        if (this.elements.progressBar) {
            this.elements.progressBar.style.width = '100%';
            this.elements.progressBar.setAttribute('aria-valuenow', '100');
            this.elements.progressPercent.textContent = '100%';
            this.elements.progressTime.textContent = 'Processing...';
        }
        
        if (this.elements.cancelBtn) {
            this.elements.cancelBtn.disabled = true;
            this.elements.cancelBtn.setAttribute('aria-disabled', 'true');
        }

        setTimeout(() => {
            let json = null;
            try { 
                json = JSON.parse(xhr.responseText); 
            } catch (err) { 
                console.error('Failed to parse server response:', err);
            }
            
            if (xhr.status === 200 && json && json.success) {
                this.handleUploadSuccess();
            } else {
                this.handleUploadFailure(xhr, json);
            }
        }, 900);
    }

    handleUploadSuccess() {
        this.notification.show('Files uploaded successfully!', 'success');
        
        if (this.elements.progressTime) {
            this.elements.progressTime.textContent = 'Upload complete!';
        }
        
        setTimeout(() => {
            this.resetForm();
        }, 1500);
    }

    handleUploadFailure(xhr, json) {
        this.enableForm();
        let errorMessage = null;
        if (json) {
            errorMessage = json.error || json.message || null;
        }
        if (!errorMessage) {
            errorMessage = (xhr.status >= 500) ? 'Server error occurred. Please try again.' :
                (xhr.status >= 400) ? 'Upload failed. Please check your files and try again.' :
                'Upload finished but status unclear.';
        }
        this.notification.show(errorMessage, 'error');
        if (this.elements.progressTime) {
            this.elements.progressTime.textContent = 'Upload failed';
        }
        setTimeout(() => {
            if (this.elements.progressContainer) {
                this.elements.progressContainer.style.display = 'none';
            }
        }, 2000);
    }

    handleUploadError() {
        this.handleUploadFailure({ status: 0 }, null);
        this.notification.show('Network error occurred. Please check your connection and try again.', 'error');
    }

    handleUploadTimeout() {
        this.handleUploadFailure({ status: 0 }, null);
        this.notification.show('Upload timed out. Please try again.', 'error');
    }

    cancelUpload() {
        if (this.currentXhr) {
            this.currentXhr.abort();
            
            if (this.elements.progressTime) {
                this.elements.progressTime.textContent = 'Upload cancelled.';
            }
            
            this.enableForm();
            this.notification.show('Upload cancelled.', 'error');
            
            setTimeout(() => {
                if (this.elements.progressContainer) {
                    this.elements.progressContainer.style.display = 'none';
                }
            }, 900);
        }
    }

    resetForm() {
        const dt = new DataTransfer();
        this.elements.fileInput.files = dt.files;
        this.renderFileList(this.elements.fileInput.files);
        this.updateUploadButtonState();
        
        if (this.elements.progressContainer) {
            this.elements.progressContainer.style.display = 'none';
        }
        
        this.enableForm();
        
        if (this.elements.policyInput) {
            this.elements.policyInput.value = '';
        }
        
        this.syncAttributeButtons();
    }
}
