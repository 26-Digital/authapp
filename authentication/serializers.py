from rest_framework import serializers
from .models import User, Role

class UserSerializer(serializers.ModelSerializer):
    roles = serializers.PrimaryKeyRelatedField(queryset=Role.objects.all(), many=True, required=False)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'roles']
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        roles = validated_data.pop('roles', [])
        user = User.objects.create_user(**validated_data)
        for role in roles:
            user.roles.add(role)
        return user