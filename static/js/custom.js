// Custom JavaScript for Web Security Scanner

// Auto-refresh functionality
function autoRefresh() {
    // Auto-refresh every 5 minutes if no activity
    let lastActivity = Date.now();
    
    document.addEventListener('click', () => {
        lastActivity = Date.now();
    });
    
    setInterval(() => {
        if (Date.now() - lastActivity > 300000) { // 5 minutes
            location.reload();
        }
    }, 60000); // Check every minute
}

// Enhanced form validation
function validateUrl(url) {
    const pattern = /^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/;
    return pattern.test(url);
}

// Add loading animation
function showLoading() {
    const button = document.querySelector('button[type="submit"]');
    if (button) {
        button.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Analyse en cours...';
        button.disabled = true;
    }
}

// Remove loading animation
function hideLoading() {
    const button = document.querySelector('button[type="submit"]');
    if (button) {
        button.innerHTML = '<i class="bi bi-search"></i> Lancer l\'analyse';
        button.disabled = false;
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Auto-refresh functionality
    autoRefresh();
    
    // Enhanced form handling
    const form = document.getElementById('scanForm');
    if (form) {
        form.addEventListener('submit', function(e) {
            const target = document.getElementById('target').value;
            if (!validateUrl(target)) {
                e.preventDefault();
                alert('Veuillez entrer une URL valide (ex: example.com ou https://example.com)');
                return false;
            }
            showLoading();
        });
    }
    
    // Add smooth scrolling
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            document.querySelector(this.getAttribute('href')).scrollIntoView({
                behavior: 'smooth'
            });
        });
    });
});
