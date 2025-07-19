let cameras = [];
let storagePools = [];
let editingCameraId = null;

async function loadCameras() {
    try {
        const response = await fetch('/api/nvr/cameras');
        cameras = await response.json();
        renderCameras();
    } catch (error) {
        console.error('Error loading cameras:', error);
        document.getElementById('cameraList').innerHTML = '<div class="empty-state">Error loading cameras</div>';
    }
}

function renderCameras() {
    const container = document.getElementById('cameraList');

    if (cameras.length === 0) {
        container.innerHTML = '<div class="empty-state">No cameras configured. Click "Add Camera" to get started.</div>';
        return;
    }

    let html = '';
    cameras.forEach(camera => {
        html += `
            <div class='camera-card'>
                <div class='camera-header'>
                    <div class='camera-name'>${camera.name}</div>
                    <div class='camera-actions'>
                        <button class='btn-success' onclick='startCamera("${camera.id}")'>Start</button>
                        <button class='btn-danger' onclick='stopCamera("${camera.id}")'>Stop</button>
                        <button onclick='editCamera("${camera.id}")'>Edit</button>
                        <button class='btn-danger' onclick='deleteCamera("${camera.id}")'>Delete</button>
                    </div>
                </div>
                <div>
                    <strong>RTSP URL:</strong> ${camera.rtspUrl}<br>
                    <strong>Status:</strong> ${camera.enabled ? 'Enabled' : 'Disabled'}<br>
                    <strong>Recording Days:</strong> ${camera.recordingDays}<br>
                    <strong>Encryption:</strong> ${camera.encryptStorage ? 'Enabled' : 'Disabled'}
                </div>
            </div>
        `;
    });

    container.innerHTML = html;
}

function showAddCameraModal() {
    editingCameraId = null;
    document.getElementById('modalTitle').textContent = 'Add Camera';
    document.getElementById('cameraForm').reset();
    document.getElementById('enabled').checked = true;
    document.getElementById('encryptStorage').checked = true;
    document.getElementById('recordingDays').value = 30;
    populateStoragePoolSelect();
    document.getElementById('cameraModal').style.display = 'block';
}

function editCamera(cameraId) {
    const camera = cameras.find(c => c.id === cameraId);
    if (!camera) return;

    editingCameraId = cameraId;
    document.getElementById('modalTitle').textContent = 'Edit Camera';
    document.getElementById('cameraName').value = camera.name;
    document.getElementById('rtspUrl').value = camera.rtspUrl;
    document.getElementById('username').value = camera.username || '';
    document.getElementById('password').value = camera.password || '';
    document.getElementById('recordingDays').value = camera.recordingDays;
    document.getElementById('enabled').checked = camera.enabled;
    document.getElementById('encryptStorage').checked = camera.encryptStorage;
    populateStoragePoolSelect();
    document.getElementById('storagePool').value = camera.storagePoolId;
    document.getElementById('cameraModal').style.display = 'block';
}

function populateStoragePoolSelect() {
    const select = document.getElementById('storagePool');
    select.innerHTML = '';
    storagePools.forEach(pool => {
        const option = document.createElement('option');
        option.value = pool.id;
        option.textContent = pool.name;
        select.appendChild(option);
    });
}

function closeCameraModal() {
    document.getElementById('cameraModal').style.display = 'none';
    editingCameraId = null;
}

document.getElementById('cameraForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const cameraData = {
        name: document.getElementById('cameraName').value,
        rtspUrl: document.getElementById('rtspUrl').value,
        username: document.getElementById('username').value,
        password: document.getElementById('password').value,
        storagePoolId: document.getElementById('storagePool').value,
        recordingDays: parseInt(document.getElementById('recordingDays').value),
        enabled: document.getElementById('enabled').checked,
        encryptStorage: document.getElementById('encryptStorage').checked
    };

    try {
        let response;
        if (editingCameraId) {
            response = await fetch(`/api/nvr/cameras/${editingCameraId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cameraData)
            });
        } else {
            response = await fetch('/api/nvr/cameras', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(cameraData)
            });
        }

        if (response.ok) {
            closeCameraModal();
            loadCameras();
            alert(editingCameraId ? 'Camera updated successfully' : 'Camera added successfully');
        } else {
            const error = await response.json();
            alert('Error: ' + error.error);
        }
    } catch (error) {
        console.error('Error saving camera:', error);
        alert('Error saving camera');
    }
});

async function deleteCamera(cameraId) {
    if (!confirm('Are you sure you want to delete this camera?')) return;

    try {
        const response = await fetch(`/api/nvr/cameras/${cameraId}`, {
            method: 'DELETE'
        });

        if (response.ok) {
            loadCameras();
            alert('Camera deleted successfully');
        } else {
            const error = await response.json();
            alert('Error: ' + error.error);
        }
    } catch (error) {
        console.error('Error deleting camera:', error);
        alert('Error deleting camera');
    }
}

async function startCamera(cameraId) {
    try {
        const response = await fetch(`/api/nvr/camera/${cameraId}/start`, {
            method: 'POST'
        });

        if (response.ok) {
            alert('Camera started successfully');
        } else {
            const error = await response.json();
            alert('Error: ' + error.error);
        }
    } catch (error) {
        console.error('Error starting camera:', error);
        alert('Error starting camera');
    }
}

async function stopCamera(cameraId) {
    try {
        const response = await fetch(`/api/nvr/camera/${cameraId}/stop`, {
            method: 'POST'
        });

        if (response.ok) {
            alert('Camera stopped successfully');
        } else {
            const error = await response.json();
            alert('Error: ' + error.error);
        }
    } catch (error) {
        console.error('Error stopping camera:', error);
        alert('Error stopping camera');
    }
}

document.getElementById('cameraModal').addEventListener('click', function(e) {
    if (e.target === this) {
        closeCameraModal();
    }
});

async function loadStoragePools() {
    try {
        const response = await fetch('/api/nvr/storage/pools');
        storagePools = await response.json();
    } catch (error) {
        console.error('Error loading storage pools:', error);
    }
}

document.addEventListener('DOMContentLoaded', async function() {
    await loadStoragePools();
    loadCameras();
});
