from datetime import timedelta

from django.core.management.base import BaseCommand
from django.db import transaction
from django.utils import timezone

from registration.models import ParkingReservation


class Command(BaseCommand):
    help = "Cancel approved reservations that are older than a configured age threshold."

    def add_arguments(self, parser):
        parser.add_argument(
            "--older-than-hours",
            type=int,
            default=24,
            help="Cancel approved reservations older than this many hours (default: 24).",
        )
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Preview stale reservations without updating records.",
        )

    def handle(self, *args, **options):
        older_than_hours = max(1, int(options["older_than_hours"]))
        dry_run = bool(options["dry_run"])
        cutoff = timezone.now() - timedelta(hours=older_than_hours)

        stale_qs = ParkingReservation.objects.filter(
            status="approved",
            reserved_for_datetime__lt=cutoff,
        ).order_by("reserved_for_datetime", "id")

        stale_count = stale_qs.count()
        self.stdout.write(
            self.style.WARNING(
                f"Found {stale_count} approved reservation(s) older than {older_than_hours} hour(s)."
            )
        )

        if stale_count == 0:
            self.stdout.write(self.style.SUCCESS("No stale approved reservations to clean up."))
            return

        for reservation in stale_qs[:20]:
            self.stdout.write(
                f"- id={reservation.id} user={reservation.applicant_username} "
                f"reserved_for={reservation.reserved_for_datetime.isoformat()} spots={reservation.reserved_spots}"
            )

        if dry_run:
            self.stdout.write(self.style.SUCCESS("Dry run complete. No records were updated."))
            return

        admin_note = (
            f"Auto-cancelled by cleanup_stale_reservations: older than {older_than_hours} hours."
        )
        with transaction.atomic():
            stale_qs.update(status="cancelled", admin_notes=admin_note)

        self.stdout.write(
            self.style.SUCCESS(
                f"Cancelled {stale_count} stale approved reservation(s) older than {older_than_hours} hour(s)."
            )
        )
