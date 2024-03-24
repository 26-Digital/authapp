import jwt
from django.conf import settings
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Role
from .serializers import UserSerializer, RoleSerializer

class RoleListView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        roles = Role.objects.all()
        serializer = RoleSerializer(roles, many=True) # Serialize multiple objects
        return Response(serializer.data)
    
    def post(self, request):
        serializer = RoleSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class RoleDetailView(APIView):
    permission_classes = [AllowAny]

    def get_role(self, pk):
        try:
            return Role.objects.get(pk=pk)
        except:
            return Response(status=status.HTTP_404_NOT_FOUND)
    
    def get(self, request, pk):
        role = self.get_role(pk)
        serializer = RoleSerializer(role)
        return Response(serializer.data)


    def put(self, request, pk):
        role = self.get_role(pk)
        serializer = RoleSerializer(role, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def delete(self, request, pk):
        role = self.get_role(pk)
        role.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

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

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        # user = request.user
        user = User.objects.get(id=request.user.id)
        serializer = UserSerializer(user)
        return Response(serializer.data)
    def put(self, request):
        user = User.objects.get(id=request.user.id)
        user_data = UserSerializer(instance=user, data=request.data)

        if not user_data.is_valid():
            return Response({'message': 'Invalied data'}, status=400)
        
        user_data.save()
        return Response(user_data.data)
    
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            refresh_token = request.COOKIES.get('refresh_token')
            token = RefreshToken(refresh_token)
            token.blacklist()  # Blacklist the refresh token
        except Exception:
            pass  # Handle exceptions if needed

        # Clear the authentication cookies
        response = Response({'message': 'Logout successful'})
        response.delete_cookie('access_token')
        response.delete_cookie('refresh_token')

        return response

class LoginView(TokenObtainPairView):
    permission_classes = [AllowAny]

    def get_user(self, access_token):
        # Decode the access token to get the user ID
        from rest_framework_simplejwt.tokens import AccessToken
        token = AccessToken(access_token)
        user_id = token.payload['user_id']

        # Retrieve the user instance from the database
        user = User.objects.get(pk=user_id)
        return user
 
    def post(self, request, *args, **kwargs):
        response = super().post(request, *args, **kwargs)
        refresh_token = response.data['refresh']
        set_cookies(response, RefreshToken(refresh_token))
        
        # Get the authenticated user instance
        user = self.get_user(response.data['access'])

        if user is not None:
            roles = [role.name for role in user.roles.all()]
            response.data['roles'] = roles

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
"""    response.data = {
        'roles': response.data.get('roles', []),
    }"""