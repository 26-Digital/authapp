# authentication/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterView.as_view(), name='register'),
    path('login/', views.LoginView.as_view(), name='login'),
    path('teacher/', views.TeacherView.as_view(), name='teacher'),
    path('registration-officer/', views.RegistrationOfficerView.as_view(), name='registration-officer'),
    # Add more URL patterns for other roles
]