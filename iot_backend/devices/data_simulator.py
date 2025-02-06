import random
import time
from datetime import datetime
from django.core.management.base import BaseCommand
from your_app.models import DeviceData, Device  # Import your models

class Command(BaseCommand):
    help = 'Simulate random active device data'

    # Simulate data for temperature or humidity
    def simulate_device_data(self, device, data_type):
        if data_type == "temperature":
            value = random.uniform(20.0, 30.0)
        elif data_type == "humidity":
            value = random.uniform(40.0, 60.0)
        else:
            raise ValueError("Invalid data type")
        
        timestamp = datetime.now()
        # Save data to the database
        DeviceData.objects.create(device=device, data_type=data_type, value=value, timestamp=timestamp)
        self.stdout.write(f"INSERT INTO device_data (device_id, type, value, timestamp) VALUES ({device.id}, '{data_type}', {value:.2f}, '{timestamp}');")

    # Simulate motion data
    def simulate_motion_data(self, device):
        motion_value = random.choice([0, 1])  # 0 = no motion, 1 = motion detected
        timestamp = datetime.now()
        # Save data to the database
        DeviceData.objects.create(device=device, data_type="motion", value=motion_value, timestamp=timestamp)
        self.stdout.write(f"INSERT INTO device_data (device_id, type, value, timestamp) VALUES ({device.id}, 'motion', {motion_value}, '{timestamp}');")

    def handle(self, *args, **kwargs):
        devices = Device.objects.all()  # Fetch devices from the database
        for _ in range(10):  # Simulate 10 iterations
            active_device_count = random.randint(1, len(devices))  # Randomly select active devices
            active_devices = random.sample(list(devices), active_device_count)  # Pick random active devices
            
            for device in active_devices:
                if device.type in ["temperature", "humidity"]:
                    self.simulate_device_data(device, device.type)
                elif device.type == "motion":
                    self.simulate_motion_data(device)
            
            time.sleep(60)  # Wait for 1 minute before the next iteration
