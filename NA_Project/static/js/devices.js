// devices.js - JavaScript for device management functionality
(function () {
  // Improved CSRF token extraction to ensure it's always available
  function getCsrfToken() {
    // First try to get from a csrfmiddlewaretoken input field (common in Django forms)
    let token = document.querySelector('[name=csrfmiddlewaretoken]')?.value;
    
    // If not found, try to get it from cookies (Django sets a csrftoken cookie)
    if (!token) {
      const tokenCookie = document.cookie.split('; ').find(row => row.startsWith('csrftoken='));
      if (tokenCookie) {
        token = tokenCookie.split('=')[1];
      }
    }
    
    return token;
  }
  
  const csrf = getCsrfToken();
  let modal;
  let dropdown;
  const $form = $('#deviceForm');
  const $bulkBar = $('#bulkDeleteBar');

  /* ---------- FORM HELPERS ---------- */
  function fillForm(d) {
    $('#device_id').val(d.id || '');
    $('#ip_address').val(d.ip_address || '');
    $('#hostname').val(d.hostname || '');
    $('#username').val(d.username || '');
    $('#password').val(''); // never pre-fill password
    $('#vendor').val(d.vendor || 'mikrotik');
    $('#segment').val(d.segmentation?.id || '');
    $('#device_category').val(d.device_category || '');
    $('#api_port').val(d.api_port || 8728);
    $('#ssh_port').val(d.ssh_port || 22);
    
    // Log the segmentation data for debugging
    console.log('Filling form with segmentation:', d.segmentation);
  }

  function payload() {
    const segmentSelect = $('#segment');
    const segmentId = segmentSelect.val();
    const segmentType = segmentSelect.find('option:selected').data('type');
    
    const data = {
        ip_address: $('#ip_address').val(),
        hostname: $('#hostname').val(),
        username: $('#username').val(),
        password: $('#password').val(),
        vendor: $('#vendor').val(),
        api_port: parseInt($('#api_port').val()) || 8728,
        ssh_port: parseInt($('#ssh_port').val()) || 22,
        device_category: $('#device_category').val(),
        segmentation_id: segmentId,
        segmentation_type: segmentType
    };
    
    console.log('Saving device data:', data);
    return JSON.stringify(data);
  }

  function toast(msg, type = 'success') {
    const cls = (type === 'success') ? 'bg-success' : 'bg-danger';
    $('<div class="toast align-items-center text-white ' + cls + ' border-0 position-fixed bottom-0 end-0 m-3" role="alert" data-bs-delay="3000">' +
      '<div class="d-flex"><div class="toast-body">' + msg +
      '</div><button class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button></div></div>')
      .appendTo('body').toast('show').on('hidden.bs.toast', function () { $(this).remove(); });
  }

  /* ---------- INITIALIZATION ---------- */
  function initPage() {
    console.log('Initializing page...'); // Debug log
    
    // Initialize Bootstrap components
    const modalElement = document.getElementById('deviceModal');
    if (modalElement) {
      modal = new bootstrap.Modal(modalElement);
    }

    const dropdownElement = document.querySelector('.dropdown-toggle');
    if (dropdownElement) {
      dropdown = new bootstrap.Dropdown(dropdownElement);
      console.log('Dropdown initialized');
      
      // Add click listener to dropdown button
      dropdownElement.addEventListener('click', function(e) {
        console.log('Dropdown button clicked');
        e.preventDefault();
        dropdown.toggle();
      });
    }

    /* ---------- FILTERS ---------- */
    $(document).on('click', '#applyFilters', function(e) {
      e.preventDefault();
      const deviceCategory = $('#deviceCategoryFilter').val();
      const segment = $('#segmentFilter').val();
      
      // Show loading state
      const $tableBody = $('.table tbody');
      $tableBody.html('<tr><td colspan="10" class="text-center py-4"><i class="fas fa-spinner fa-spin me-2"></i>Loading...</td></tr>');
      
      $.ajax({
        url: '/devices/filter/',
        method: 'POST',
        headers: { 'X-CSRFToken': csrf },
        contentType: 'application/json',
        data: JSON.stringify({
          device_category: deviceCategory,
          segment: segment
        }),
        success: function(response) {
          $tableBody.html(response.html);
        },
        error: function(xhr, status, error) {
          toast('Error applying filters: ' + error, 'error');
          // Reload the page as fallback
          location.reload();
        }
      });
    });

    /* ---------- ADD DEVICE ---------- */
    // Handle single device add
    $(document).on('click', '#addSingleDeviceBtn', function(e) {
      e.preventDefault();
      console.log('Single Add Device clicked'); // Debug log
      
      // Hide dropdown
      if (dropdown) {
        dropdown.hide();
      }
      
      // Reset form and show modal
      $form[0].reset();
      $form.removeClass('was-validated');
      $('#device_id').val('');
      $('#deleteDeviceBtn').addClass('d-none');
      $('#deviceModalLabel').text('Add Device');
      
      if (modal) {
        modal.show();
      }
    });

    /* ---------- EDIT DEVICE ---------- */
    $(document).on('click', '.edit-device-btn', function(e) {
      e.preventDefault();
      const id = $(this).data('id');
      console.log('Edit button clicked for device ID:', id); // Debug log
      
      $.ajax({
        url: `/device/${id}/json/`,
        method: 'GET',
        success: function(d) {
          console.log('Device data received:', d); // Debug log
          fillForm(d);
          $('#deleteDeviceBtn').removeClass('d-none');
          $('#deviceModalLabel').text('Edit Device');
          modal.show();
        },
        error: function(xhr, status, error) {
          console.error('Error loading device:', error); // Debug log
          toast('Failed to load device: ' + error, 'error');
        }
      });
    });

    /* ---------- SAVE DEVICE ---------- */
    $(document).on('click', '#saveDeviceBtn', function(e) {
      e.preventDefault();
      if (!$form[0].checkValidity()) { 
        $form.addClass('was-validated'); 
        return; 
      }
      
      const id = $('#device_id').val();
      const url = id ? `/device/${id}/save/` : '/device/add/';
      
      // Show loading state
      const $btn = $(this);
      const originalText = $btn.html();
      $btn.prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-1"></i>Saving...');
      
      $.ajax({
        url: url,
        type: 'POST',
        headers: { 'X-CSRFToken': csrf },
        data: payload(),
        contentType: 'application/json',
        success: function(response) {
          toast(response.message || 'Device saved successfully');
          location.reload();
        },
        error: function(xhr) {
          const errorMsg = xhr.responseJSON?.error || 'Error saving device';
          toast(errorMsg, 'error');
          console.error('Save error:', errorMsg);
          
          // Reset button state
          $btn.prop('disabled', false).html(originalText);
        }
      });
    });

    /* ---------- DELETE MODE (BULK) ---------- */
    $(document).on('click', '#toggleDeleteMode', function(e) {
      e.preventDefault();
      console.log('Toggle delete mode clicked'); // Debug log
      
      // Toggle visibility of checkboxes
      $('.select-col').toggleClass('d-none');
      
      // Toggle visibility of bulk delete bar
      $('#bulkDeleteBar').toggleClass('d-none');
      
      // Reset checkboxes
      $('#selectAll,.device-cb').prop('checked', false);
      
      // Toggle button text and state
      $(this).toggleClass('active')
        .html($(this).hasClass('active') ? 
          '<i class="fas fa-times me-1"></i>Cancel' : 
          '<i class="fas fa-trash me-1"></i>Delete Mode');
    });

    /* ---------- SELECT ALL ---------- */
    $(document).on('change', '#selectAll', function() {
      $('.device-cb').prop('checked', this.checked);
    });

    /* ---------- BULK DELETE ---------- */
    $(document).on('click', '#bulkDeleteBtn', function(e) {
      e.preventDefault();
      const ids = $('.device-cb:checked').map((_, el) => el.value).get();
      
      if (!ids.length) {
        toast('No devices selected', 'error');
        return;
      }
      
      if (!confirm(`Delete ${ids.length} devices?`)) return;
      
      $.ajax({
        url: '/devices/bulk-delete/',
        type: 'POST',
        headers: { 'X-CSRFToken': csrf },
        data: JSON.stringify({ device_ids: ids }),
        contentType: 'application/json',
        success: function() {
          location.reload();
        },
        error: function() {
          toast('Bulk delete failed', 'error');
        }
      });
    });

    // Add segment change handler
    $(document).on('change', '#segment', function() {
        const $selected = $(this).find('option:selected');
        console.log('Segment changed to:', {
            id: $(this).val(),
            type: $selected.data('type'),
            text: $selected.text()
        });
    });
  }

  // Initialize everything when document is ready
  $(document).ready(function() {
    console.log('Document ready, initializing...'); // Debug log
    initPage();
  });
})();
