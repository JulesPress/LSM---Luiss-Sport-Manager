from django.urls import path

from . import views

urlpatterns = [
    path("dashboard/", views.dashboard, name="dashboard"),
    path("login/", views.login, name="login"),
    path("athletes/", views.athlete_list, name="athlete_list"),
    path("admin_management/", views.admin_management, name="admin_management"),
    path("certificates/", views.certificate_list, name="certificate_list"),
    path("profile/", views.profile, name="profile"),
    path("logout/", views.logout, name="logout"),
    path("certificates/upload/", views.certificate_upload, name="certificate_upload"),
    path("certificates/<int:pk>/", views.certificate_detail, name="certificate_detail"),
    path("signup/", views.signup, name="signup"),
]

