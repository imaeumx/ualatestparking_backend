from django.db import models


class UserRegistration(models.Model):
    """
    Model for storing user registration information.
    Handles both student and guest user accounts.
    """
    # Personal Information
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=150)

    # Authentication Credentials
    username = models.CharField(max_length=100, unique=True)
    password = models.TextField()  # DES encrypted password string

    # User Classification (Student ID | Level - Strand/Course, or Guest purpose)
    identifier = models.TextField(blank=True, null=True)
    role = models.CharField(max_length=20, default='student')  # 'student' or 'guest'

    def __str__(self):
        return f"{self.username} - {self.role}"


class VehicleApplication(models.Model):
    """
    Model for vehicle parking sticker applications.
    Tracks application status, approval, and sticker validity.
    """
    # Application Details
    applicant_username = models.CharField(max_length=100)  # Links to UserRegistration
    owner_name = models.TextField()  # DES encrypted owner name
    plate_number = models.TextField()  # DES encrypted plate number
    vehicle_type = models.CharField(max_length=50)  # '2-Wheels', '4-Wheels', 'Service'

    # Application Status
    status = models.CharField(max_length=20, default='Pending')  # 'Pending', 'Approved', 'Rejected'
    is_seen = models.BooleanField(default=True)  # Whether user has seen status update

    # Sticker Information (Set upon approval)
    sticker_id = models.CharField(max_length=20, blank=True, null=True)  # Format: UA-001, UA-002, etc.
    expiration_date = models.DateField(blank=True, null=True)  # Sticker expires 1 year from approval

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    role = models.CharField(max_length=20, blank=True, null=True)  # User's role at time of application
    identifier = models.TextField(blank=True, null=True)  # User's identifier at time of application

    def __str__(self):
        return f"{self.plate_number} ({self.status})"
    
