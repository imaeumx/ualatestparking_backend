from django.db import models

class UserRegistration(models.Model):
    # Basic Info
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(max_length=150)
    
    # Credentials
    username = models.CharField(max_length=100, unique=True)
    password = models.TextField() # Stores the DES encrypted string
    
    # The 'identifier' string from your frontend (ID | Level - Strand)
    identifier = models.TextField(blank=True, null=True)
    role = models.CharField(max_length=20, default='student')

    def __str__(self):
        return f"{self.username} - {self.role}"

class VehicleApplication(models.Model):
    # Links the vehicle to the user
    applicant_username = models.CharField(max_length=100)
    owner_name = models.TextField() # Encrypted
    plate_number = models.TextField() # Encrypted
    is_seen = models.BooleanField(default=True)
    vehicle_type = models.CharField(max_length=50)
    sticker_id = models.CharField(max_length=20, blank=True, null=True)
    status = models.CharField(max_length=20, default='Pending')
    created_at = models.DateTimeField(auto_now_add=True)
    role = models.CharField(max_length=20, blank=True, null=True)
    identifier = models.TextField(blank=True, null=True)

    def __str__(self):
        return f"{self.plate_number} ({self.status})"
    
