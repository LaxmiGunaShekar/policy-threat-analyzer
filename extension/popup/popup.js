document.addEventListener('DOMContentLoaded', () => {
    
    // Check backend health
    checkBackendHealth();

    // Attach click handler to scan button
    document.getElementById('scan-btn').addEventListener('click', () => {
        // Send message to the content script in the active tab
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            if (tabs[0]) {
                chrome.tabs.sendMessage(tabs[0].id, {action: "scan_now"}, (response) => {
                    // Close the popup once the scan starts in the page
                    window.close();
                });
            }
        });
    });
});

async function checkBackendHealth() {
    const statusSpan = document.getElementById('status-indicator');
    
    try {
        const response = await fetch('http://localhost:8000/health');
        if (response.ok) {
            statusSpan.textContent = 'Online';
            statusSpan.className = 'online';
        } else {
            throw new Error('Not OK');
        }
    } catch (error) {
        statusSpan.textContent = 'Offline';
        statusSpan.className = 'offline';
        document.getElementById('scan-btn').disabled = true;
        document.getElementById('scan-btn').textContent = 'Backend Offline';
        document.getElementById('scan-btn').style.backgroundColor = '#6c757d';
    }
}
