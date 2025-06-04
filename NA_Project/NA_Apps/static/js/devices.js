// CSRF Token handling
function getCsrfToken() {
    return document.querySelector('[name=csrfmiddlewaretoken]').value;
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing Bootstrap components...');
    
    // Add Device Button
    const addSingleDeviceBtn = document.getElementById('addSingleDeviceBtn');
    if (addSingleDeviceBtn) {
        addSingleDeviceBtn.addEventListener('click', function() {
            const deviceModal = new bootstrap.Modal(document.getElementById('deviceModal'));
            // Reset form
            document.getElementById('deviceForm').reset();
            document.getElementById('device_id').value = '';
            deviceModal.show();
        });
    }

    // Edit Device Buttons
    document.querySelectorAll('.edit-device-btn').forEach(button => {
        button.addEventListener('click', async function() {
            const deviceId = this.getAttribute('data-id');
            try {
                const response = await fetch(`/device/${deviceId}/json/`);
                if (!response.ok) throw new Error('Network response was not ok');
                const data = await response.json();
                
                // Fill form with device data
                document.getElementById('device_id').value = deviceId;
                document.getElementById('ip_address').value = data.ip_address || '';
                document.getElementById('hostname').value = data.hostname || '';
                document.getElementById('username').value = data.username || '';
                document.getElementById('password').value = data.password || '';
                document.getElementById('api_port').value = data.api_port || '8728';
                document.getElementById('ssh_port').value = data.ssh_port || '22';
                document.getElementById('vendor').value = data.vendor || 'mikrotik';
                document.getElementById('device_category').value = data.device_category || '';
                document.getElementById('segment').value = data.segmentation || '';

                // Show modal
                const deviceModal = new bootstrap.Modal(document.getElementById('deviceModal'));
                deviceModal.show();
            } catch (error) {
                console.error('Error:', error);
                alert('Error loading device data');
            }
        });
    });

    // Save Device Button
    const saveDeviceBtn = document.getElementById('saveDeviceBtn');
    if (saveDeviceBtn) {
        saveDeviceBtn.addEventListener('click', async function() {
            const deviceId = document.getElementById('device_id').value;
            const data = {
                ip_address: document.getElementById('ip_address').value,
                hostname: document.getElementById('hostname').value,
                username: document.getElementById('username').value,
                password: document.getElementById('password').value,
                api_port: document.getElementById('api_port').value,
                ssh_port: document.getElementById('ssh_port').value,
                vendor: document.getElementById('vendor').value,
                device_category: document.getElementById('device_category').value,
                segmentation: document.getElementById('segment').value
            };

            try {
                const url = deviceId ? `/device/${deviceId}/save/` : '/device/add/';
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify(data)
                });

                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();

                if (result.status === 'success') {
                    window.location.reload();
                } else {
                    alert(result.message || 'Error saving device');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Error saving device');
            }
        });
    }

    // Delete Mode Toggle
    const toggleDeleteMode = document.getElementById('toggleDeleteMode');
    if (toggleDeleteMode) {
        toggleDeleteMode.addEventListener('click', function() {
            const selectCols = document.querySelectorAll('.select-col');
            const bulkDeleteBar = document.getElementById('bulkDeleteBar');
            
            selectCols.forEach(col => col.classList.toggle('d-none'));
            bulkDeleteBar.classList.toggle('d-none');
        });
    }

    // Select All Checkbox
    const selectAll = document.getElementById('selectAll');
    if (selectAll) {
        selectAll.addEventListener('change', function() {
            document.querySelectorAll('.device-cb').forEach(cb => {
                cb.checked = this.checked;
            });
        });
    }

    // Bulk Delete Button
    const bulkDeleteBtn = document.getElementById('bulkDeleteBtn');
    if (bulkDeleteBtn) {
        bulkDeleteBtn.addEventListener('click', async function() {
            const selectedDevices = Array.from(document.querySelectorAll('.device-cb:checked')).map(cb => cb.value);
            
            if (selectedDevices.length === 0) {
                alert('Please select devices to delete');
                return;
            }

            if (!confirm(`Are you sure you want to delete ${selectedDevices.length} device(s)?`)) {
                return;
            }

            try {
                const response = await fetch('/devices/bulk-delete/', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': getCsrfToken()
                    },
                    body: JSON.stringify({ devices: selectedDevices })
                });

                if (!response.ok) throw new Error('Network response was not ok');
                const result = await response.json();

                if (result.status === 'success') {
                    window.location.reload();
                } else {
                    alert(result.message || 'Error deleting devices');
                }
            } catch (error) {
                console.error('Error:', error);
                alert('Error deleting devices');
            }
        });
    }

    // Filter Form
    const applyFilters = document.getElementById('applyFilters');
    if (applyFilters) {
        applyFilters.addEventListener('click', function() {
            document.getElementById('filterForm').submit();
        });
    }
}); 