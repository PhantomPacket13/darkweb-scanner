/**
 * Main JavaScript file for the Onion Scanner application
 */

document.addEventListener('DOMContentLoaded', function() {
    // Enable Bootstrap tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Enable Bootstrap popovers
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    const popoverList = popoverTriggerList.map(function(popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Form validation
    const scanForm = document.getElementById('scan-form');
    if (scanForm) {
        scanForm.addEventListener('submit', function(event) {
            const urlInput = document.getElementById('onion_url');
            if (!urlInput.value.trim()) {
                event.preventDefault();
                event.stopPropagation();
                
                // Show error message
                const errorDiv = document.createElement('div');
                errorDiv.className = 'alert alert-danger mt-2';
                errorDiv.textContent = 'Please enter a valid .onion URL';
                
                // Remove any existing error messages
                const existingError = urlInput.parentNode.querySelector('.alert');
                if (existingError) {
                    existingError.remove();
                }
                
                urlInput.parentNode.appendChild(errorDiv);
                urlInput.focus();
            }
        });
    }
    
    // Add URL protocol if missing
    const urlInput = document.getElementById('onion_url');
    if (urlInput) {
        urlInput.addEventListener('blur', function() {
            const url = urlInput.value.trim();
            if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
                urlInput.value = 'http://' + url;
            }
        });
    }
});

/**
 * Format a security score with appropriate color class
 * 
 * @param {number} score - The security score (0-100)
 * @returns {string} HTML string with formatted score
 */
function formatSecurityScore(score) {
    let colorClass = '';
    let label = '';
    
    if (score >= 90) {
        colorClass = 'text-success';
        label = 'Excellent';
    } else if (score >= 70) {
        colorClass = 'text-info';
        label = 'Good';
    } else if (score >= 50) {
        colorClass = 'text-warning';
        label = 'Fair';
    } else {
        colorClass = 'text-danger';
        label = 'Poor';
    }
    
    return `<span class="${colorClass}"><strong>${score}</strong> - ${label}</span>`;
}

/**
 * Convert a severity string to a Bootstrap color class
 * 
 * @param {string} severity - The severity level ('high', 'medium', 'low', 'info')
 * @returns {string} The corresponding Bootstrap color class
 */
function getSeverityColorClass(severity) {
    switch (severity.toLowerCase()) {
        case 'high':
            return 'danger';
        case 'medium':
            return 'warning';
        case 'low':
            return 'info';
        case 'info':
        default:
            return 'secondary';
    }
}

/**
 * Toggle the visibility of a section
 * 
 * @param {string} sectionId - The ID of the section to toggle
 */
function toggleSection(sectionId) {
    const section = document.getElementById(sectionId);
    if (section) {
        section.classList.toggle('d-none');
        
        // Toggle the icon
        const icon = document.querySelector(`[data-toggle-section="${sectionId}"] i`);
        if (icon) {
            icon.classList.toggle('fa-chevron-down');
            icon.classList.toggle('fa-chevron-up');
        }
    }
}
