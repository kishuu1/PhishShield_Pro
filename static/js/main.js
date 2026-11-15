/**
 * PhishShield Pro — Interactive Client-Side Logic
 */

document.addEventListener('DOMContentLoaded', function () {
    // 1. Auto-dismiss flash messages after 6 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function (alert) {
        setTimeout(function () {
            try {
                const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
                bsAlert.close();
            } catch (e) {
                alert.style.display = 'none';
            }
        }, 6000);
    });

    // 2. Scan form submission loading feedback
    const scanForm = document.getElementById('urlScanForm');
    if (scanForm) {
        scanForm.addEventListener('submit', function (e) {
            const submitBtn = document.getElementById('scanSubmitBtn');
            const urlInput = document.getElementById('urlInput');

            if (!urlInput || !urlInput.value.trim()) {
                e.preventDefault();
                urlInput.focus();
                return;
            }

            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.innerHTML = `
                    <span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>
                    Analyzing Heuristics...
                `;
            }
        });
    }

    // 3. Tooltip initialization
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (el) {
        return new bootstrap.Tooltip(el);
    });

    // 4. Modal dynamic population (for delete & edit modals)
    const deleteModal = document.getElementById('deleteConfirmModal');
    if (deleteModal) {
        deleteModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const targetUrl = button.getAttribute('data-action-url');
            const itemName = button.getAttribute('data-item-name') || 'this item';
            
            const form = deleteModal.querySelector('#deleteConfirmForm');
            const targetLabel = deleteModal.querySelector('#deleteTargetName');
            
            if (form && targetUrl) {
                form.setAttribute('action', targetUrl);
            }
            if (targetLabel) {
                targetLabel.textContent = itemName;
            }
        });
    }

    // 5. Threat Intelligence Edit Modal Population
    const editIndicatorModal = document.getElementById('editIndicatorModal');
    if (editIndicatorModal) {
        editIndicatorModal.addEventListener('show.bs.modal', function (event) {
            const button = event.relatedTarget;
            const actionUrl = button.getAttribute('data-action-url');
            const indicator = button.getAttribute('data-indicator');
            const type = button.getAttribute('data-type');
            const severity = button.getAttribute('data-severity');
            const desc = button.getAttribute('data-description');

            const form = editIndicatorModal.querySelector('#editIndicatorForm');
            if (form && actionUrl) form.action = actionUrl;

            const inputInd = editIndicatorModal.querySelector('#edit_indicator');
            const inputType = editIndicatorModal.querySelector('#edit_indicator_type');
            const inputSev = editIndicatorModal.querySelector('#edit_severity');
            const inputDesc = editIndicatorModal.querySelector('#edit_description');

            if (inputInd) inputInd.value = indicator || '';
            if (inputType) inputType.value = type || 'domain';
            if (inputSev) inputSev.value = severity || 'medium';
            if (inputDesc) inputDesc.value = desc || '';
        });
    }

    // 6. Mobile sidebar toggle
    const sidebarToggleBtn = document.getElementById('sidebarToggleBtn');
    const sidebar = document.querySelector('.sidebar');
    if (sidebarToggleBtn && sidebar) {
        sidebarToggleBtn.addEventListener('click', function () {
            sidebar.classList.toggle('show');
        });
    }
});

// Configure Global Chart.js dark theme styling if available
if (typeof Chart !== 'undefined') {
    Chart.defaults.color = '#9aa3c7';
    Chart.defaults.borderColor = '#21295c';
    Chart.defaults.font.family = "'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
    Chart.defaults.plugins.legend.labels.usePointStyle = true;
    Chart.defaults.plugins.legend.labels.padding = 16;
}

