from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User
import json
from .models import Device, Segmentation, Log


class DeviceViewTests(TestCase):
    """Tests for the devices view and associated device operations"""
    
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='testuser', password='12345')
        
        # Create segmentations
        self.segmentation1 = Segmentation.objects.create(
            name="Fiber Optic", segmentation_type="distribution")
        self.segmentation2 = Segmentation.objects.create(
            name="Wireless", segmentation_type="access")
        
        # Create test devices
        self.device1 = Device.objects.create(
            hostname="router1",
            ip_address="192.168.1.1",
            username="admin",
            password="password",
            device_category="router_end_point",
            segmentation=self.segmentation1
        )
        
        self.device2 = Device.objects.create(
            hostname="router2",
            ip_address="192.168.1.2",
            username="admin",
            password="password",
            device_category="router_failover",
            segmentation=self.segmentation2
        )
        
        self.device3 = Device.objects.create(
            hostname="radio1",
            ip_address="192.168.1.3",
            username="admin",
            password="password",
            device_category="radio_bts",
            segmentation=self.segmentation1
        )
        
        # Initialize the test client
        self.client = Client()
        
        # Log in the test user
        self.client.login(username='testuser', password='12345')
    
    def test_devices_view_no_filters(self):
        """Test devices view with no filters applied"""
        response = self.client.get(reverse('devices'))
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['all_device']), 3)
    
    def test_devices_view_with_segmentation_filter(self):
        """Test devices view with segmentation filter"""
        response = self.client.get(
            reverse('devices'),
            {'segmentation__segmentation_type': 'distribution'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['all_device']), 2)
        for device in response.context['all_device']:
            self.assertEqual(device.segmentation.segmentation_type, 'distribution')
    
    def test_devices_view_with_category_filter(self):
        """Test devices view with device category filter"""
        response = self.client.get(
            reverse('devices'),
            {'device_category': 'radio_bts'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['all_device']), 1)
        self.assertEqual(response.context['all_device'][0].device_category, 'radio_bts')
    
    def test_devices_view_with_all_segmentation_filter(self):
        """Test devices view with 'all' segmentation filter"""
        response = self.client.get(
            reverse('devices'),
            {'segmentation_type': 'all'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['all_device']), 3)
    
    def test_edit_device(self):
        """Test editing a device"""
        # Prepare updated device data
        updated_data = {
            'hostname': 'updated_router',
            'ip_address': '192.168.1.10',
            'username': 'newadmin',
            'password': 'newpassword',
            'device_category': 'router_bridging',
            'segmentation_id': self.segmentation2.id
        }
        
        # Send request to update device
        response = self.client.post(
            reverse('device_save', args=[self.device1.id]),
            data=json.dumps(updated_data),
            content_type='application/json'
        )
        
        # Check response
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        
        # Verify device was updated in database
        updated_device = Device.objects.get(id=self.device1.id)
        self.assertEqual(updated_device.hostname, 'updated_router')
        self.assertEqual(updated_device.ip_address, '192.168.1.10')
        self.assertEqual(updated_device.username, 'newadmin')
        self.assertEqual(updated_device.device_category, 'router_bridging')
        self.assertEqual(updated_device.segmentation.id, self.segmentation2.id)


class LogViewTests(TestCase):
    """Tests for the logs view and operations"""
    
    def setUp(self):
        # Create a test user
        self.user = User.objects.create_user(username='testuser', password='12345')
        
        # Create a test device
        self.device = Device.objects.create(
            hostname="router1",
            ip_address="192.168.1.1",
            username="admin",
            password="password"
        )
        
        # Create some test logs
        Log.objects.create(
            target=self.device.ip_address,
            action="Configure",
            status="Success",
            messages="Test log 1",
            command="test command 1",
            output="test output 1"
        )
        
        Log.objects.create(
            target=self.device.ip_address,
            action="Verify",
            status="Error",
            messages="Test log 2",
            command="test command 2",
            output="test output 2"
        )
        
        Log.objects.create(
            target="192.168.1.2",  # Device doesn't exist
            action="Configure",
            status="Success",
            messages="Test log 3"
        )
        
        # Initialize the test client
        self.client = Client()
        
        # Log in the test user
        self.client.login(username='testuser', password='12345')
    
    def test_logs_view(self):
        """Test logs view with no filters"""
        response = self.client.get(reverse('logs'))
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['logs']), 3)
        self.assertEqual(response.context['success_count'], 2)
        self.assertEqual(response.context['failed_count'], 1)
    
    def test_logs_with_hostname_filter(self):
        """Test logs view with hostname filter"""
        response = self.client.get(
            reverse('logs'),
            {'hostname': 'router1'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['logs']), 2)
        for log in response.context['logs']:
            self.assertEqual(log.target, self.device.ip_address)
    
    def test_logs_with_status_filter(self):
        """Test logs view with status filter"""
        response = self.client.get(
            reverse('logs'),
            {'status': 'error'}
        )
        
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.context['logs']), 1)
        self.assertEqual(response.context['logs'][0].status.lower(), 'error')
    
    def test_clear_logs(self):
        """Test clearing all logs"""
        # Verify logs exist before clearing
        self.assertEqual(Log.objects.count(), 3)
        
        # Clear logs
        response = self.client.post(reverse('clear_logs'))
        
        # Check redirect
        self.assertEqual(response.status_code, 302)
        
        # Verify logs were cleared
        self.assertEqual(Log.objects.count(), 0)
