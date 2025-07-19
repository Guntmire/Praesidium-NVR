let cameras = [];
let storagePools = [];
let editingCameraId = null;

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    initializeTabs();
    initializeModal();
    initializeButtons();
    loadInitialData();
    startAutoRefresh();
});

function initializeTabs() {
    document.getElementById('dashboardTab').addEventListener('click', () => showTab('dashboard'));
    document.getElementById('camerasTab').addEventListener('click', () => showTab('cameras'));
    document.getElementById('storageTab').addEventListener('click', () => showTab('storage'));
}

function initializeModal() {
    document.getElementById('closeModal').addEventListener('click', closeCameraModal);
    document.getElementById('cancelButton').addEventListener('click', closeCameraModal);
    document.getElementById('cameraForm').addEventListener('submit', handleCameraSubmit);
    
    document.getElementById('cameraModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeCameraModal();
        }
    });
}

function initializeButtons() {
    document.getElementById('addCameraBtn').addEventListener('click', showAddCameraModal);
    document.getElementById('refreshStorageBtn').addEventListener('click', refreshStorage);
    document.getElementById('refreshMetricsBtn').addEventListener('click', refreshMetrics);
    document.getElementById('refreshStatusBtn').addEventListener('click', refreshStatus);
}

function loadInitialData() {
    refreshMetrics();
    refreshStatus();
    refreshStorage();
}

function startAutoRefresh() {
    setInterval(refreshMetrics, 10000);
    setInterval(refreshStatus, 30000);
    setInterval(refreshStorage, 60000);
}

function showTab(tabName) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    document.getElementById(tabName + 'Tab').classList.add('active');
    document.getElementById(tabName).classList.add('active');
    
    if (tabName === 'cameras') {
        loadCameras();
    } else if (tabName === 'storage') {
        refreshStorage();
    }
}

// Continue with rest of JavaScript functions...