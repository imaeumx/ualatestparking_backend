from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('registration', '0008_alter_vehicleapplication_plate_number_unique'),
    ]

    operations = [
        migrations.AddField(
            model_name='vehicleapplication',
            name='admin_notes',
            field=models.TextField(blank=True, null=True),
        ),
    ]
