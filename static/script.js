// UPI Scam Detector Frontend JavaScript

class ScamDetectorUI {
    constructor() {
        this.form = document.getElementById('scamCheckForm');
        this.messageText = document.getElementById('messageText');
        this.checkBtn = document.getElementById('checkBtn');
        this.clearBtn = document.getElementById('clearBtn');
        this.resultsSection = document.getElementById('resultsSection');
        this.resultContent = document.getElementById('resultContent');
        this.loadingSpinner = document.getElementById('loadingSpinner');
        
        this.initializeEventListeners();
    }
    
    initializeEventListeners() {
        // Form submission
        this.form.addEventListener('submit', (e) => {
            e.preventDefault();
            this.checkForScam();
        });
        
        // Clear button
        this.clearBtn.addEventListener('click', () => {
            this.clearResults();
        });
        
        // Sample message clicks
        document.querySelectorAll('.sample-message').forEach(element => {
            element.addEventListener('click', () => {
                const sampleText = element.getAttribute('data-sample');
                this.messageText.value = sampleText;
                this.messageText.focus();
                // Automatically check the sample message
                setTimeout(() => this.checkForScam(), 100);
            });
            
            // Add keyboard support
            element.setAttribute('tabindex', '0');
            element.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                    e.preventDefault();
                    element.click();
                }
            });
        });
        
        // Auto-resize textarea
        this.messageText.addEventListener('input', () => {
            this.autoResizeTextarea();
        });
    }
    
    autoResizeTextarea() {
        this.messageText.style.height = 'auto';
        this.messageText.style.height = Math.max(100, this.messageText.scrollHeight) + 'px';
    }
    
    async checkForScam() {
        const text = this.messageText.value.trim();
        
        if (!text) {
            this.showError('Please enter a message to check');
            return;
        }
        
        this.showLoading(true);
        this.setFormDisabled(true);
        
        try {
            const response = await fetch('/check', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ text: text })
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to check message');
            }
            
            this.displayResults(data);
            
        } catch (error) {
            console.error('Error checking message:', error);
            this.showError(`Error: ${error.message}`);
        } finally {
            this.showLoading(false);
            this.setFormDisabled(false);
        }
    }
    
    displayResults(data) {
        const isScam = data.is_scam;
        const confidence = Math.round(data.confidence_score * 100);
        
        // Create result HTML
        let resultHTML = `
            <div class="result-enter">
                ${this.createAlertBox(isScam, confidence)}
                ${this.createDetailsSection(data)}
                ${this.createMatchedPatternsSection(data)}
            </div>
        `;
        
        this.resultContent.innerHTML = resultHTML;
        this.resultsSection.style.display = 'block';
        
        // Scroll to results
        this.resultsSection.scrollIntoView({ 
            behavior: 'smooth', 
            block: 'start' 
        });
    }
    
    createAlertBox(isScam, confidence) {
        const alertClass = isScam ? 'alert-scam' : 'alert-safe';
        const icon = isScam ? 'alert-triangle' : 'shield-check';
        const title = isScam ? 'Potential Scam Detected!' : 'Message Appears Safe';
        const description = isScam 
            ? 'This message contains patterns commonly found in scam messages.' 
            : 'No suspicious patterns were detected in this message.';
        
        return `
            <div class="alert ${alertClass} d-flex align-items-center mb-4">
                <i data-feather="${icon}" class="me-3"></i>
                <div class="flex-grow-1">
                    <h5 class="alert-heading mb-1">${title}</h5>
                    <p class="mb-0">${description}</p>
                </div>
                <div class="text-end">
                    <div class="badge result-badge ${isScam ? 'bg-danger' : 'bg-success'}">
                        ${confidence}% Confidence
                    </div>
                </div>
            </div>
        `;
    }
    
    createDetailsSection(data) {
        const confidenceClass = this.getConfidenceClass(data.confidence_score);
        const confidencePercent = Math.round(data.confidence_score * 100);
        
        return `
            <div class="row mb-4">
                <div class="col-md-6">
                    <h6>Confidence Score</h6>
                    <div class="confidence-bar mb-2">
                        <div class="confidence-fill ${confidenceClass}" style="width: ${confidencePercent}%"></div>
                    </div>
                    <small class="text-muted">${confidencePercent}% confidence</small>
                </div>
                <div class="col-md-6">
                    <h6>Detection Summary</h6>
                    <ul class="list-unstyled mb-0">
                        <li><strong>Scam Status:</strong> ${data.is_scam ? 'Detected' : 'Not Detected'}</li>
                        <li><strong>Patterns Found:</strong> ${data.matched_patterns.length}</li>
                        <li><strong>Categories:</strong> ${data.categories.length}</li>
                    </ul>
                </div>
            </div>
        `;
    }
    
    createMatchedPatternsSection(data) {
        if (data.matched_keywords.length === 0 && data.categories.length === 0) {
            return `
                <div class="alert alert-info">
                    <i data-feather="info" class="me-2"></i>
                    No suspicious patterns detected in this message.
                </div>
            `;
        }
        
        let html = '<div class="row">';
        
        // Matched Keywords
        if (data.matched_keywords.length > 0) {
            html += `
                <div class="col-md-6 mb-3">
                    <h6>Matched Keywords</h6>
                    <div class="mb-2">
                        ${data.matched_keywords.map(keyword => 
                            `<span class="keyword-badge">${this.escapeHtml(keyword)}</span>`
                        ).join('')}
                    </div>
                    <small class="text-muted">${data.matched_keywords.length} suspicious keyword(s) found</small>
                </div>
            `;
        }
        
        // Categories
        if (data.categories.length > 0) {
            html += `
                <div class="col-md-6 mb-3">
                    <h6>Scam Categories</h6>
                    <div class="mb-2">
                        ${data.categories.map(category => 
                            `<span class="category-badge">${this.formatCategory(category)}</span>`
                        ).join('')}
                    </div>
                    <small class="text-muted">${data.categories.length} category(ies) identified</small>
                </div>
            `;
        }
        
        html += '</div>';
        
        // Technical Details (collapsible)
        if (data.matched_patterns.length > 0) {
            html += `
                <div class="mt-3">
                    <div class="accordion" id="technicalDetails">
                        <div class="accordion-item">
                            <h2 class="accordion-header">
                                <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#technicalDetailsBody">
                                    <i data-feather="code" class="me-2"></i>
                                    Technical Details
                                </button>
                            </h2>
                            <div id="technicalDetailsBody" class="accordion-collapse collapse" data-bs-parent="#technicalDetails">
                                <div class="accordion-body">
                                    <h6>Matched Patterns</h6>
                                    <ul class="list-group list-group-flush">
                                        ${data.matched_patterns.map(pattern => 
                                            `<li class="list-group-item"><code>${this.escapeHtml(pattern)}</code></li>`
                                        ).join('')}
                                    </ul>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
        
        return html;
    }
    
    getConfidenceClass(score) {
        if (score < 0.3) return 'confidence-low';
        if (score < 0.7) return 'confidence-medium';
        return 'confidence-high';
    }
    
    formatCategory(category) {
        return category
            .replace(/_/g, ' ')
            .replace(/\b\w/g, l => l.toUpperCase());
    }
    
    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
    
    showLoading(show) {
        if (show) {
            this.loadingSpinner.style.display = 'block';
            this.resultsSection.style.display = 'none';
        } else {
            this.loadingSpinner.style.display = 'none';
        }
    }
    
    setFormDisabled(disabled) {
        this.messageText.disabled = disabled;
        this.checkBtn.disabled = disabled;
        this.clearBtn.disabled = disabled;
        
        if (disabled) {
            this.form.classList.add('loading-fade');
        } else {
            this.form.classList.remove('loading-fade');
        }
    }
    
    showError(message) {
        this.resultContent.innerHTML = `
            <div class="alert alert-danger d-flex align-items-center">
                <i data-feather="alert-circle" class="me-3"></i>
                <div>
                    <strong>Error:</strong> ${this.escapeHtml(message)}
                </div>
            </div>
        `;
        this.resultsSection.style.display = 'block';
        
        // Re-initialize feather icons for the new content
        feather.replace();
    }
    
    clearResults() {
        this.messageText.value = '';
        this.resultsSection.style.display = 'none';
        this.resultContent.innerHTML = '';
        this.messageText.focus();
        this.autoResizeTextarea();
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ScamDetectorUI();
    
    // Add some initial functionality for better UX
    const messageText = document.getElementById('messageText');
    if (messageText) {
        messageText.focus();
    }
    
    // Re-initialize feather icons after any dynamic content changes
    const observer = new MutationObserver(() => {
        feather.replace();
    });
    
    observer.observe(document.body, {
        childList: true,
        subtree: true
    });
});

// Global error handler for unhandled promise rejections
window.addEventListener('unhandledrejection', (event) => {
    console.error('Unhandled promise rejection:', event.reason);
    event.preventDefault();
});
