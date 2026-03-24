// Bug Report Generator - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Auto-resize textareas
    const textareas = document.querySelectorAll('textarea');
    textareas.forEach(textarea => {
        textarea.addEventListener('input', autoResize);
        autoResize.call(textarea);
    });
    
    // Form validation
    const form = document.querySelector('form');
    if (form) {
        form.addEventListener('submit', validateForm);
    }
    
    // Copy report ID functionality
    const reportIdElement = document.querySelector('.report-id');
    if (reportIdElement) {
        reportIdElement.addEventListener('click', copyReportId);
    }
});

function autoResize() {
    this.style.height = 'auto';
    this.style.height = this.scrollHeight + 'px';
}

function validateForm(e) {
    const title = document.querySelector('[name="report_title"]');
    const vulnTitle = document.querySelector('[name="vulnerability_title"]');
    const description = document.querySelector('[name="vulnerability_description"]');
    const steps = document.querySelector('[name="steps"]');
    
    let errors = [];
    
    if (title && title.value.trim().length < 5) {
        errors.push('Report title must be at least 5 characters');
        title.classList.add('is-invalid');
    }
    
    if (vulnTitle && vulnTitle.value.trim().length < 5) {
        errors.push('Vulnerability title must be at least 5 characters');
        vulnTitle.classList.add('is-invalid');
    }
    
    if (description && description.value.trim().length < 20) {
        errors.push('Description must be at least 20 characters');
        description.classList.add('is-invalid');
    }
    
    if (steps && steps.value.trim().length < 10) {
        errors.push('Steps to reproduce must be at least 10 characters');
        steps.classList.add('is-invalid');
    }
    
    if (errors.length > 0) {
        e.preventDefault();
        showAlert(errors.join('\n'), 'danger');
        return false;
    }
    
    showAlert('Generating report...', 'info');
    return true;
}

function showAlert(message, type) {
    const alertDiv = document.createElement('div');
    alertDiv.className = `alert alert-${type} alert-dismissible fade show`;
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    const container = document.querySelector('.container');
    if (container) {
        container.insertBefore(alertDiv, container.firstChild);
        
        setTimeout(() => {
            alertDiv.remove();
        }, 5000);
    }
}

function copyReportId(e) {
    const text = e.target.textContent;
    navigator.clipboard.writeText(text).then(() => {
        showAlert('Report ID copied to clipboard!', 'success');
    });
}

// Download tracking
function trackDownload(format) {
    console.log(`Downloading report in ${format} format`);
    // You can add analytics here
}