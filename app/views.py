import email
from django.contrib import messages

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import HttpResponse
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q

from .models import Athlete, MedicalCertificate


def index(request):
    """Home page - redirect to dashboard if logged in, else to login."""
    if request.user.is_authenticated:
        return redirect('dashboard')
    return redirect('login')


def login(request):
    """User login page."""
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('dashboard')
        else:
            context = {'error': 'Invalid username or password.'}
            return render(request, 'app/login.html', context)
    
    return render(request, 'app/login.html')


@login_required(login_url='login')
def athlete_list(request):
    """Display list of all athletes (staff only)."""
    if not request.user.is_staff:
        return redirect('dashboard')
    
    athletes = Athlete.objects.all()
    
    # Search filter
    search = request.GET.get('search')
    if search:
        from django.db.models import Q
        athletes = athletes.filter(
            Q(user__username__icontains=search) |
            Q(user__first_name__icontains=search) |
            Q(user__last_name__icontains=search) |
            Q(sport_discipline__icontains=search)
        )
    
    # Sport filter
    sport = request.GET.get('sport')
    if sport:
        athletes = athletes.filter(sport_discipline=sport)
    
    sports = Athlete.objects.values_list('sport_discipline', flat=True).distinct()
    
    context = {
        'athletes': athletes,
        'sports': sports,
        'search': search,
        'sport': sport,
    }
    
    return render(request, 'app/athlete_list.html', context)


@login_required(login_url='login')
def certificate_list(request):
    """Display list of medical certificates for logged-in athlete."""
    athlete = get_object_or_404(Athlete, user=request.user)
    certificates = MedicalCertificate.objects.filter(athlete=athlete).order_by('-issue_date')
    
    # Filter by type
    cert_type = request.GET.get('type')
    if cert_type:
        certificates = certificates.all()
    
    # Filter by status
    status_filter = request.GET.get('status')
    if status_filter == 'expired':
        certificates = certificates.filter(expiry_date__lt=timezone.now().date())
    elif status_filter == 'expiring':
        expiry_threshold = timezone.now().date() + timedelta(days=30)
        certificates = certificates.filter(
            expiry_date__lte=expiry_threshold,
            expiry_date__gte=timezone.now().date()
        )
    elif status_filter == 'valid':
        certificates = certificates.filter(expiry_date__gte=timezone.now().date())
    
    context = {
        'athlete': athlete,
        'certificates': certificates,
        'status_filter': status_filter,
        'cert_type': cert_type,
    }
    
    return render(request, 'app/certificate_list.html', context)


@login_required(login_url='login')
def dashboard(request):
    """Main dashboard showing certification status and alerts."""
    try:
        athlete = Athlete.objects.get(user=request.user)
    except Athlete.DoesNotExist:
        # Create default athlete profile if missing
        athlete = Athlete.objects.create(
            user=request.user,
            sport_discipline='',
            date_of_birth='2000-01-01'
        )
    
    latest_cert = athlete.get_latest_certificate()
    all_certs = athlete.certificates.all()  # Empty queryset is fine
    
    expiry_threshold = timezone.now().date() + timedelta(days=30)
    expiring_soon = all_certs.filter(
        expiry_date__lte=expiry_threshold,
        expiry_date__gte=timezone.now().date()
    )
    
    expired = all_certs.filter(expiry_date__lt=timezone.now().date())
    
    context = {
        'athlete': athlete,
        'latest_certificate': latest_cert,
        'is_certified': athlete.is_certified(),
        'expiring_soon': expiring_soon,
        'expired': expired,
        'total_certificates': all_certs.count(),
    }
    
    return render(request, 'app/dashboard.html', context)

@login_required(login_url='login')
def profile(request):
    """Display and edit user profile."""
    try:
        athlete = Athlete.objects.get(user=request.user)
    except Athlete.DoesNotExist:
        # Create athlete profile if it doesn't exist
        athlete = Athlete.objects.create(
            user=request.user,
            sport_discipline='',
            date_of_birth='2000-01-01'
        )
    
    if request.method == 'POST':
        # Update profile
        athlete.sport_discipline = request.POST.get('sport_discipline', athlete.sport_discipline)
        athlete.team_affiliation = request.POST.get('team_affiliation', athlete.team_affiliation)
        
        # Update user info
        request.user.first_name = request.POST.get('first_name', request.user.first_name)
        request.user.last_name = request.POST.get('last_name', request.user.last_name)
        request.user.email = request.POST.get('email', request.user.email)
        
        athlete.save()
        request.user.save()
        
        context = {
            'athlete': athlete,
            'success': 'Profile updated successfully.'
        }
        return render(request, 'app/profile.html', context)
    
    certificates = athlete.certificates.all()
    
    context = {
        'athlete': athlete,
        'user': request.user,
        'certificates': certificates,
        'latest_certificate': athlete.get_latest_certificate(),
    }
    
    return render(request, 'app/profile.html', context)


@login_required(login_url='login')
def certificate_upload(request):
    """Upload a new medical certificate."""
    athlete = get_object_or_404(Athlete, user=request.user)
    
    if request.method == 'POST':
        
        issue_date = request.POST.get('issue_date')
        expiry_date = request.POST.get('expiry_date')
        
      
        certificate_image = request.FILES.get('certificate_image')
        
        if not certificate_image:
            context = {
                'athlete': athlete,
                'certificate_types': MedicalCertificate.CERTIFICATE_TYPES,
                'error': 'Certificate image is required.'
            }
            return render(request, 'app/certificate_upload.html', context)
        
        certificate = MedicalCertificate.objects.create(
            athlete=athlete,
            
            issue_date=issue_date,
            expiry_date=expiry_date,
            
            
            certificate_image=certificate_image,
        )
        
        context = {'success': 'Certificate uploaded successfully.'}
        return render(request, 'app/certificate_upload.html', context)
    
    context = {
        'athlete': athlete,
        
    }
    
    return render(request, 'app/certificate_upload.html', context)


# views.py - Update certificate_detail function

@login_required(login_url='login')
def certificate_detail(request, pk):
    athlete, created = Athlete.objects.get_or_create(
        user=request.user,
        defaults={'sport_discipline': '', 'date_of_birth': '2000-01-01'}
    )
    certificate = get_object_or_404(MedicalCertificate, id=pk, athlete=athlete)
    
    # Handle delete on same page
    if request.method == 'POST':
        certificate.delete()
        return redirect('certificate_list')
    
    return render(request, 'app/certificate_detail.html', {
        'certificate': certificate,

    })


def logout(request):
    """Logout the user and redirect to login."""
    auth_logout(request)
    return redirect('login')

# views.py - Update signup function with ONLY those fields

def signup(request):
    """User registration page with athlete profile fields."""
    if request.method == 'POST':
        username = request.POST.get('username')
        first_name = request.POST.get('first_name', '').strip()
        last_name = request.POST.get('last_name', '').strip()
        sport_discipline = request.POST.get('sport_discipline')
        password = request.POST.get('password')
        password_confirm = request.POST.get('password_confirm')
        team_affiliation = request.POST.get('team_affiliation', '')
        date_of_birth = request.POST.get('date_of_birth', '')
        
        # Validation
        if password != password_confirm:
            return render(request, 'app/signup.html', {
                'error': 'Passwords do not match.',
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'sport_discipline': sport_discipline,
                'team_affiliation': team_affiliation,
                'date_of_birth': date_of_birth,
            })
        
        if len(password) < 8:
            return render(request, 'app/signup.html', {
                'error': 'Password must be at least 6 characters.',
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'sport_discipline': sport_discipline,
                'team_affiliation': team_affiliation,
                'date_of_birth': date_of_birth,
            })
        
        if User.objects.filter(username=username).exists():
            return render(request, 'app/signup.html', {
                'error': 'Username already exists.',
                'first_name': first_name,
                'last_name': last_name,
                'sport_discipline': sport_discipline,
                'team_affiliation': team_affiliation,
                'date_of_birth': date_of_birth,
            })
        
        if not sport_discipline:
            return render(request, 'app/signup.html', {
                'error': 'Sport discipline is required.',
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'team_affiliation': team_affiliation,
                'date_of_birth': date_of_birth,
            })
        
        if not date_of_birth:
            return render(request, 'app/signup.html', {
                'error': 'Date of birth is required.',
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'sport_discipline': sport_discipline,
                'team_affiliation': team_affiliation,
            })
        
        # Create user
        user = User.objects.create_user(
            username=username,
            password=password,
            first_name=first_name,
            last_name=last_name,
        )
        
        # Create athlete profile with all fields
        Athlete.objects.create(
            user=user,
            sport_discipline=sport_discipline,
            team_affiliation=team_affiliation,
            date_of_birth=date_of_birth
        )
        
        # Auto login
        auth_login(request, user)
        return redirect('dashboard')
    
    return render(request, 'app/signup.html')


@login_required(login_url='login')
def admin_management(request):
    if not request.user.is_staff:
        return redirect('dashboard')
    
    # Show ALL users (staff + non-staff + superusers)
    users = User.objects.all().order_by('username')
    
    # Filters (same as athlete_list)
    search = request.GET.get('search')
    if search:
        users = users.filter(
            Q(username__icontains=search) |
            Q(first_name__icontains=search) |
            Q(last_name__icontains=search) |
            Q(email__icontains=search)
        )
    
    is_staff_filter = request.GET.get('is_staff')
    if is_staff_filter == 'true':
        users = users.filter(is_staff=True)
    elif is_staff_filter == 'false':
        users = users.filter(is_staff=False)
    
    # Toggle logic (only changes is_staff)
    if request.method == 'POST':
        user_id = request.POST.get('user_id')
        action = request.POST.get('action')
        if user_id:
            try:
                target_user = User.objects.get(id=user_id)
                if target_user != request.user:
                    target_user.is_staff = (action == 'grant')
                    target_user.save()
                    status = "granted" if action == 'grant' else "revoked"
                    messages.success(request, f"{status.title()} staff access for {target_user.username}")
                return redirect('admin_management')
            except User.DoesNotExist:
                messages.error(request, "User not found")
    
    context = {
        'users': users,
        'search': search,
        'is_staff_filter': is_staff_filter,
    }
    return render(request, 'app/admin_management.html', context)
