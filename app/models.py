from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta


class Athlete(models.Model):
    """Extends Django's User model to store athlete-specific information."""

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    sport_discipline = models.CharField(max_length=100)
    team_affiliation = models.CharField(max_length=200, blank=True, null=True)
    date_of_birth = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return f"{self.user.first_name} {self.user.last_name}"
    
    def get_latest_certificate(self):
        try:
            return self.certificates.order_by('-issue_date').first()
        except:
            return None
    
    def is_certified(self):
        """Boolean check for valid certification."""
        return self.get_latest_certificate() is not None


# models.py - Update MedicalCertificate model

class MedicalCertificate(models.Model):
    """Stores medical certificate image uploads for each athlete."""
    
    athlete = models.ForeignKey(Athlete, on_delete=models.CASCADE, related_name='certificates')
    certificate_image = models.ImageField(upload_to='certificates/%Y/%m/')
    issue_date = models.DateField()
    expiry_date = models.DateField()
    uploaded_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"{self.athlete.user.username}-({self.issue_date})"
    
    def is_expired(self):
        """Check if certificate is past expiry date."""
        return self.expiry_date < timezone.now().date()
    
    def is_expiring_soon(self, days=30):
        """Alert if expiring within specified days (default 30)."""
        expiry_threshold = timezone.now().date() + timedelta(days=days)
        return not self.is_expired() and self.expiry_date <= expiry_threshold
    
    def get_days_until_expiry(self):
        """Calculate days remaining until expiry."""
        from datetime import date
        today = date.today()
        delta = self.expiry_date - today
        return delta.days
    
    def get_status(self):
        """Return certificate status: 'valid', 'expiring', or 'expired'."""
        if self.is_expired():
            return 'expired'
        elif self.is_expiring_soon():
            return 'expiring'
        else:
            return 'valid'
    
    class Meta:
        ordering = ['-issue_date']
        verbose_name_plural = 'Medical Certificates'