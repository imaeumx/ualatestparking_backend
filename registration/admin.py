from django.contrib import admin
from .models import UserRegistration, VehicleApplication, ParkingReservation

admin.site.register(UserRegistration)
admin.site.register(VehicleApplication)
admin.site.register(ParkingReservation)