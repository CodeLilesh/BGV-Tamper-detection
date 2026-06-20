// ============================================
// BGV Document Verification — Frontend App
// ============================================

(function () {
    'use strict';

    // --- State ---
    let selectedDocType = 'aadhaar';
    let selectedFile = null;

    // --- DOM Elements ---
    const docTypeBtns = document.querySelectorAll('.doc-type-btn');
    const fileDropZone = document.getElementById('file-drop-zone');
    const fileInput = document.getElementById('file-input');
    const dropZoneContent = document.getElementById('drop-zone-content');
    const filePreview = document.getElementById('file-preview');
    const fileNameEl = document.getElementById('file-name');
    const fileSizeEl = document.getElementById('file-size');
    const fileRemoveBtn = document.getElementById('file-remove');
    const passwordGroup = document.getElementById('password-group');
    const passwordInput = document.getElementById('pdf-password');
    const passwordToggle = document.getElementById('password-toggle');
    const candidateNameInput = document.getElementById('candidate-name');
    const candidateDobInput = document.getElementById('candidate-dob');
    const verifyForm = document.getElementById('verify-form');
    const verifyBtn = document.getElementById('verify-btn');
    const uploadSection = document.getElementById('upload-section');
    const resultsSection = document.getElementById('results-section');
    const backBtn = document.getElementById('back-btn');

    // Results
    const verdictCard = document.getElementById('verdict-card');
    const verdictIcon = document.getElementById('verdict-icon');
    const verdictLabel = document.getElementById('verdict-label');
    const verdictDesc = document.getElementById('verdict-desc');
    const confidenceCircle = document.getElementById('confidence-circle');
    const confidenceNumber = document.getElementById('confidence-number');
    const pipelineName = document.getElementById('pipeline-name');
    const checksGrid = document.getElementById('checks-grid');
    const flagsContainer = document.getElementById('flags-container');
    const flagsList = document.getElementById('flags-list');
    const rawJson = document.getElementById('raw-json');

    // --- Doc Type Selector ---
    docTypeBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            docTypeBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            selectedDocType = btn.dataset.type;

            // Show/hide password field
            if (selectedDocType === 'aadhaar') {
                passwordGroup.classList.remove('hidden-field');
            } else {
                passwordGroup.classList.add('hidden-field');
            }
        });
    });

    // --- File Upload ---
    fileDropZone.addEventListener('click', (e) => {
        if (!e.target.closest('.file-remove') && !selectedFile) {
            fileInput.click();
        }
    });

    fileDropZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        fileDropZone.classList.add('drag-over');
    });

    fileDropZone.addEventListener('dragleave', () => {
        fileDropZone.classList.remove('drag-over');
    });

    fileDropZone.addEventListener('drop', (e) => {
        e.preventDefault();
        fileDropZone.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    fileRemoveBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        removeFile();
    });

    function handleFileSelect(file) {
        const validTypes = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg'];
        if (!validTypes.includes(file.type)) {
            showToast('❌', 'Invalid file type. Please upload PDF, JPG, or PNG.');
            return;
        }
        if (file.size > 10 * 1024 * 1024) {
            showToast('❌', 'File too large. Maximum size is 10MB.');
            return;
        }

        selectedFile = file;
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = formatFileSize(file.size);
        dropZoneContent.classList.add('hidden');
        filePreview.classList.remove('hidden');
        fileDropZone.classList.add('has-file');
    }

    function removeFile() {
        selectedFile = null;
        fileInput.value = '';
        dropZoneContent.classList.remove('hidden');
        filePreview.classList.add('hidden');
        fileDropZone.classList.remove('has-file');
    }

    function formatFileSize(bytes) {
        if (bytes < 1024) return bytes + ' B';
        if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
        return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    }

    // --- Password Toggle ---
    passwordToggle.addEventListener('click', () => {
        const isPassword = passwordInput.type === 'password';
        passwordInput.type = isPassword ? 'text' : 'password';
        passwordToggle.querySelector('.eye-open').classList.toggle('hidden', !isPassword);
        passwordToggle.querySelector('.eye-closed').classList.toggle('hidden', isPassword);
    });

    // --- Form Submit ---
    verifyForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        if (!selectedFile) {
            showToast('📄', 'Please upload a document first.');
            return;
        }

        if (selectedDocType === 'aadhaar' && !passwordInput.value.trim()) {
            showToast('🔒', 'Please enter the PDF password for Aadhaar document.');
            return;
        }

        // Show loading
        const btnText = verifyBtn.querySelector('.btn-text');
        const btnLoading = verifyBtn.querySelector('.btn-loading');
        btnText.classList.add('hidden');
        btnLoading.classList.remove('hidden');
        verifyBtn.disabled = true;

        try {
            const formData = new FormData();
            formData.append('document', selectedFile);
            formData.append('docType', selectedDocType);
            if (selectedDocType === 'aadhaar') {
                formData.append('password', passwordInput.value.trim());
            }
            if (candidateNameInput.value.trim()) {
                formData.append('candidateName', candidateNameInput.value.trim());
            }
            if (candidateDobInput.value) {
                formData.append('candidateDob', candidateDobInput.value);
            }

            const response = await fetch('/api/verify', {
                method: 'POST',
                body: formData,
            });

            const result = await response.json();

            if (!response.ok) {
                throw new Error(result.error || 'Verification failed');
            }

            displayResults(result);
        } catch (err) {
            showToast('❌', err.message || 'An error occurred during verification.');
        } finally {
            btnText.classList.remove('hidden');
            btnLoading.classList.add('hidden');
            verifyBtn.disabled = false;
        }
    });

    // --- Display Results ---
    function displayResults(result) {
        uploadSection.classList.add('hidden');
        resultsSection.classList.remove('hidden');

        // Verdict
        const verdict = (result.verdict || 'UNKNOWN').toUpperCase();
        verdictCard.className = 'verdict-card';

        if (verdict === 'VERIFIED') {
            verdictCard.classList.add('verdict-verified');
            verdictIcon.textContent = '✅';
            verdictLabel.textContent = 'VERIFIED';
            verdictDesc.textContent = 'Document passed all verification checks';
        } else if (verdict === 'SUSPICIOUS') {
            verdictCard.classList.add('verdict-suspicious');
            verdictIcon.textContent = '⚠️';
            verdictLabel.textContent = 'SUSPICIOUS';
            verdictDesc.textContent = 'Document has some inconsistencies — review recommended';
        } else {
            verdictCard.classList.add('verdict-rejected');
            verdictIcon.textContent = '❌';
            verdictLabel.textContent = 'REJECTED';
            verdictDesc.textContent = result.verdictReason || 'Document failed verification checks';
        }

        // Confidence Ring
        const confidence = result.confidenceScore || 0;
        const circumference = 2 * Math.PI * 52; // r=52
        const offset = circumference - (confidence / 100) * circumference;

        // Update gradient color based on verdict
        const ringGrad = document.getElementById('ring-grad');
        if (verdict === 'VERIFIED') {
            ringGrad.innerHTML = '<stop stop-color="#22C55E"/><stop offset="1" stop-color="#16A34A"/>';
        } else if (verdict === 'SUSPICIOUS') {
            ringGrad.innerHTML = '<stop stop-color="#F59E0B"/><stop offset="1" stop-color="#D97706"/>';
        } else {
            ringGrad.innerHTML = '<stop stop-color="#EF4444"/><stop offset="1" stop-color="#DC2626"/>';
        }

        // Animate confidence
        animateNumber(confidenceNumber, 0, confidence, 1000);
        setTimeout(() => {
            confidenceCircle.style.transition = 'stroke-dashoffset 1s ease';
            confidenceCircle.style.strokeDashoffset = offset;
        }, 100);

        // Pipeline badge
        const pipelineMap = {
            aadhaar: '📘 Aadhaar Pipeline',
            passport: '📗 Passport Pipeline',
            other: '📕 Tamper Detection Engine',
        };
        pipelineName.textContent = pipelineMap[result.pipeline] || result.pipeline;

        // Checks
        checksGrid.innerHTML = '';
        if (result.checks && result.checks.length > 0) {
            result.checks.forEach(check => {
                const statusClass = check.passed ? 'pass' : (check.warning ? 'warn' : 'fail');
                const statusIcon = check.passed ? '✓' : (check.warning ? '!' : '✗');
                const el = document.createElement('div');
                el.className = 'check-item';
                el.innerHTML = `
                    <div class="check-status ${statusClass}">${statusIcon}</div>
                    <span class="check-name">${escapeHtml(check.name)}</span>
                    <span class="check-detail">${escapeHtml(check.detail || '')}</span>
                `;
                checksGrid.appendChild(el);
            });
        }

        // Flags
        if (result.flags && result.flags.length > 0) {
            flagsContainer.classList.remove('hidden');
            flagsList.innerHTML = '';
            result.flags.forEach(flag => {
                const severity = (flag.severity || 'medium').toLowerCase();
                const el = document.createElement('div');
                el.className = `flag-item severity-${severity}`;
                el.innerHTML = `
                    <span class="flag-module">${escapeHtml(flag.module)}</span>
                    <div class="flag-content">
                        <p class="flag-desc">${escapeHtml(flag.description)}</p>
                        <span class="flag-severity">${escapeHtml(flag.severity)} severity</span>
                    </div>
                `;
                flagsList.appendChild(el);
            });
        } else {
            flagsContainer.classList.add('hidden');
        }

        // Raw JSON
        rawJson.textContent = JSON.stringify(result, null, 2);
    }

    function animateNumber(el, from, to, duration) {
        const start = performance.now();
        const range = to - from;

        function update(now) {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease out cubic
            el.textContent = Math.round(from + range * eased);
            if (progress < 1) requestAnimationFrame(update);
        }

        requestAnimationFrame(update);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Back Button ---
    backBtn.addEventListener('click', () => {
        resultsSection.classList.add('hidden');
        uploadSection.classList.remove('hidden');
        // Reset confidence ring
        confidenceCircle.style.transition = 'none';
        confidenceCircle.style.strokeDashoffset = 327;
    });

    // --- Toast ---
    function showToast(icon, message) {
        // Remove existing toast
        const existing = document.querySelector('.toast');
        if (existing) existing.remove();

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `<span class="toast-icon">${icon}</span>${escapeHtml(message)}`;
        document.body.appendChild(toast);

        requestAnimationFrame(() => {
            toast.classList.add('show');
        });

        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 400);
        }, 4000);
    }
})();
