import threading
import time
import random
from datetime import datetime, timedelta
from django.utils.timezone import localtime
from django.contrib.auth import get_user_model, authenticate
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.forms import SetPasswordForm, PasswordResetForm
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.models import User
from django.core.mail import send_mail
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from .serializers import RegisterSerializer, UserSerializer, DeviceSerializer, DeviceDataSerializer
from .models import Device, DeviceData
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class PasswordResetRequestView(APIView):
    def post(self, request):
        try:
            email = request.data.get('email')
            logger.info(f"Processing password reset request")

            if not email:
                return Response({
                    'detail': 'Email is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                user = User.objects.get(email=email)
            except User.DoesNotExist:
                logger.info(f"Password reset requested for non-existent email")
                return Response({
                    'detail': 'If your email is registered, you will receive a reset link.'
                }, status=status.HTTP_200_OK)

            # Generate token and encode user id
            uid = urlsafe_base64_encode(force_bytes(user.pk))
            token = default_token_generator.make_token(user)

            # Build reset URL
            reset_url = f"http://localhost:4200/password-reset/{uid}/{token}"

            # Prepare email context
            context = {
                'user': user,
                'reset_url': reset_url,
                'uid': uid,
                'token': token,
            }

            try:
                # Render email template
                html_content = render_to_string('devices/emails/password_reset_email.html', context)
                text_content = f"Reset your password at: {reset_url}"

                # Create email message
                subject = "Password Reset Request"
                from_email = 'noreply@example.com'
                
                email_message = EmailMultiAlternatives(
                    subject=subject,
                    body=text_content,
                    from_email=from_email,
                    to=[email]
                )
                email_message.attach_alternative(html_content, "text/html")
                
                # Send email
                email_message.send()
                logger.info("Password reset email sent successfully")
                
                return Response({
                    'detail': 'Password reset email sent successfully'
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                logger.error(f"Email sending failed: {str(e)}")
                return Response({
                    'detail': 'Failed to send password reset email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        except Exception as e:
            logger.error(f"Unexpected error in password reset request: {str(e)}")
            return Response({
                'detail': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class PasswordResetConfirmView(APIView):
    def post(self, request):
        try:
            uidb64 = request.data.get('uidb64')
            token = request.data.get('token')
            new_password = request.data.get('new_password')

            if not all([uidb64, token, new_password]):
                return Response({
                    'detail': 'Missing required fields'
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                uid = urlsafe_base64_decode(uidb64).decode()
                user = User.objects.get(pk=uid)
            except (TypeError, ValueError, OverflowError, User.DoesNotExist):
                return Response({
                    'detail': 'Invalid reset link'
                }, status=status.HTTP_400_BAD_REQUEST)

            if not default_token_generator.check_token(user, token):
                return Response({
                    'detail': 'Invalid or expired reset link'
                }, status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()
            
            logger.info("Password reset successful")
            return Response({
                'detail': 'Password reset successful'
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Error in password reset confirm: {str(e)}")
            return Response({
                'detail': 'Error processing request'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            return Response({'user': UserSerializer(user).data}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)

        if user is not None:
            refresh = RefreshToken.for_user(user)
            user_serializer = UserSerializer(user)
            return Response({
                'refresh': str(refresh),
                'access': str(refresh.access_token),
                'user': user_serializer.data
            }, status=status.HTTP_200_OK)
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class DeviceListCreateView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        devices = Device.objects.all()
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def post(self, request):
        device_name = request.data.get('name')
        if Device.objects.filter(name=device_name).exists():
            return Response({"error": f"Device with name '{device_name}' already exists."}, status=status.HTTP_409_CONFLICT)

        serializer = DeviceSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



class DeviceDetailUpdateDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Device.objects.get(pk=pk)
        except Device.DoesNotExist:
            return None

    def get(self, request, pk):
        devices = Device.objects.filter(customerid=pk)
        if not devices:
            return Response({'detail': 'No devices found for this customer.'}, status=status.HTTP_404_NOT_FOUND)
        serializer = DeviceSerializer(devices, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request, pk):
        device = self.get_object(pk)
        if device is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)

        serializer = DeviceSerializer(device, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk):
        device = self.get_object(pk)
        if device is None:
            return Response({'detail': 'Not found.'}, status=status.HTTP_404_NOT_FOUND)
        device.delete()
        return Response({'detail': 'Device deleted successfully.'}, status=status.HTTP_204_NO_CONTENT)

    @staticmethod
    def generate_random_data(sensor_type):
        """Generate random sensor data based on sensor type."""
        if sensor_type.lower() == 'temperature sensor':
            return round(random.uniform(20, 30), 2)
        elif sensor_type.lower() == 'humidity sensor':
            return round(random.uniform(40, 60), 2)
        elif sensor_type.lower() == 'motion sensor':
            return random.randint(0, 1)
        return None

    @staticmethod
    def generate_sensor_data(device):
        """Continuously generate sensor data for an active device."""
        while Device.objects.filter(id=device.id, status="active").exists():
            sensor_value = DeviceDetailUpdateDeleteView.generate_random_data(device.type)

            # Save the sensor data to the database
            DeviceData.objects.create(
                device=device,
                data_type=device.type,
                customerid=device.customerid,
                value=sensor_value
            )

            # Update the device's last reading value
            device.last_reading = {'value': sensor_value}
            device.save()

            # Wait for 10 seconds before generating the next reading
            time.sleep(1800)

    def patch(self, request, pk):
        device = self.get_object(pk)
        if not device:
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)

        status_value = request.data.get('status')
        if status_value not in ['active', 'inactive']:
            return Response({'error': 'Invalid status value'}, status=status.HTTP_400_BAD_REQUEST)

        device.status = status_value

        if status_value == 'active':
            device.save()  # Save the status change before starting the thread
            thread = threading.Thread(target=self.generate_sensor_data, args=(device,))
            thread.daemon = True
            thread.start()
        else:
            device.save()

        serializer = DeviceSerializer(device)
        return Response(serializer.data, status=status.HTTP_200_OK)

class DeviceDataAPI(APIView):
    def get(self, request, device_id):
        """Fetch all DeviceData for a specific Device ID."""
        frequency = request.query_params.get('frequency', None)  # Get the frequency from query params
        try:
            device = Device.objects.get(id=device_id)
            # Filter DeviceData based on frequency (if provided)
            device_data = DeviceData.objects.filter(device=device)

            if frequency:
                # Add filtering logic for frequency (e.g., daily, weekly, monthly)
                current_time = localtime()  # Get the current time in the local timezone

                if frequency == 'daily':
                    start_of_day = current_time.replace(hour=0, minute=0, second=0, microsecond=0)
                    end_of_day = current_time.replace(hour=23, minute=59, second=59, microsecond=999999)
                    device_data = device_data.filter(timestamp__range=(start_of_day, end_of_day))
                    
                elif frequency == 'weekly':
                    one_week_ago = current_time - timedelta(weeks=1)
                    device_data = device_data.filter(timestamp__gte=one_week_ago)
                    
                elif frequency == 'monthly':
                    one_month_ago = current_time - timedelta(days=30)
                    device_data = device_data.filter(timestamp__gte=one_month_ago)

                elif frequency == 'yearly':
                    start_of_year = current_time.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)
                    end_of_year = current_time.replace(month=12, day=31, hour=23, minute=59, second=59, microsecond=999999)
                    device_data = device_data.filter(timestamp__range=(start_of_year, end_of_year))

            serializer = DeviceDataSerializer(device_data, many=True)
            return Response(serializer.data, status=status.HTTP_200_OK)
        
        except Device.DoesNotExist:
            logger.error(f"Device with ID {device_id} not found.")
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Unexpected error while fetching device data: {e}")
            return Response({'error': f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self, request, device_id):
        """Create new DeviceData for a specific Device ID."""
        try:
            device = Device.objects.get(id=device_id)
            data = request.data
            data['device'] = device.id  # Add the device ID to the request data
            serializer = DeviceDataSerializer(data=data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        except Device.DoesNotExist:
            logger.error(f"Device with ID {device_id} not found.")
            return Response({'error': 'Device not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Unexpected error while creating device data: {e}")
            return Response({'error': f"An unexpected error occurred: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
