import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import User
from .serializers import UserSerializer

class RegisterView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            refresh = RefreshToken.for_user(user)
            response = Response({
                'roles': [role.name for role in user.roles.all()],
            }, status=status.HTTP_201_CREATED)
            set_cookies(response, refresh)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def get_token_data(self, user):
        data = super().get_token_data(user)
        roles = [role.name for role in user.roles.all()]
        data['roles'] = roles
        return data

    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh_token = response.data['refresh']
        set_cookies(response, RefreshToken(refresh_token))
        return response

class TeacherView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Perform actions or retrieve data for teachers
        return Response({'message': 'Teacher view'})

class RegistrationOfficerView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # Perform actions or retrieve data for registration officers
        return Response({'message': 'Registration officer view'})

def set_cookies(response, refresh):
    access_token = str(refresh.access_token)
    response.set_cookie('access_token', access_token, httponly=True, samesite='Lax')
    response.set_cookie('refresh_token', str(refresh), httponly=True, samesite='Lax')
    response.data = {
        'roles': response.data.get('roles', []),
    }