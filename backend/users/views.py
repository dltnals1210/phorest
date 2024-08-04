from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages

import os
import requests

from .models import User
from galleries.models import Gallery
from .serializers import UserCreateSerializer, UserDetailSerializer, UserPutSerializer
from galleries.serializers import GallerySmallSerializer

from rest_framework import status
from rest_framework.exceptions import ParseError, AuthenticationFailed, NotAuthenticated
from rest_framework.renderers import JSONRenderer

from rest_framework.exceptions import NotFound
from rest_framework.permissions import IsAuthenticated

from django.contrib.auth import login as auth_login
from django.shortcuts import render, redirect
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt

from allauth.socialaccount.providers.google.views import GoogleOAuth2Adapter
from dj_rest_auth.registration.views import SocialLoginView
from allauth.socialaccount.providers.oauth2.client import OAuth2Client
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.contrib.sites.shortcuts import get_current_site
from dj_rest_auth import views
from dj_rest_auth.serializers import JWTSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.decorators import api_view, renderer_classes

SITE_DOMAIN = 'http://localhost:8000' # 프론트엔드랑 합쳐서 테스트할 땐, 프론트엔드 주소 넣어야 할거예요 아마도..? http://localhost:3000
GOOGLE_CLIENT_ID = '456462903282-doodv1eep7mmjcdupus05bkkie53j58e.apps.googleusercontent.com'
GOOGLE_CLIENT_SECRET = '' # 노션 -> api 명세서 -> 구글 로그인 페이지에 있는 코드 넣어주세요!
GOOGLE_REDIRECT_URI = SITE_DOMAIN + "/api/v1/auth/login/google/callback"
GOOGLE_STATE = os.environ.get('GOOGLE_STATE')

# Create your views here.
class Users(APIView):
    
    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save(login_path=User.COMMON)
            return Response({"user_id":user.id})
        else:
            return Response({"detail":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

class UserLogin(APIView):

    def post(self, request):
        email = request.data.get("email")
        password = request.data.get("password")
        if not email:
            raise ParseError("이메일을 입력하세요.")
        username = User.objects.get(email=email).username
        if not password:
            raise ParseError("비밀번호를 입력하세요.")
        user = authenticate(request, username=username, password=password)
        if not user:
            raise AuthenticationFailed("사용자 검증에 실패했습니다.")
        login(request, user)
        return Response({"username": user.username})
        
class UserLogout(APIView):

    def post(self, request):
        if not request.user.is_authenticated:
            raise NotAuthenticated("로그인 되어있지 않습니다.")
        logout(request)
        return Response({"detail":"로그아웃"})

class UserDetail(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        serializer = UserDetailSerializer(request.user)
        return Response(serializer.data)
    
    def put(self, request):
        user = request.user
        serializer = UserPutSerializer(user, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"detail": "성공!"})
        else:
            return Response({"detail":serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
        
class MyGalleries(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        page = int(request.query_params.get("page", "1"))
        size = 3
        my_gallery = Gallery.objects.filter(user=request.user)[(page-1)*size:page*size]
        serializer = GallerySmallSerializer(my_gallery, many=True)
        return Response(serializer.data)

class LikeGalleries(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        page = int(request.query_params.get("page", "1"))
        size = 3
        like_gallery = Gallery.objects.filter(like_users=request.user)[(page-1)*size:page*size]
        serializer = GallerySmallSerializer(like_gallery, many=True)
        return Response(serializer.data)

class AlertException(Exception):
    pass

class TokenException(Exception):
    pass

@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def google_login(request):
    try:
        scope = 'https://www.googleapis.com/auth/userinfo.email'
        return redirect(
            f'https://accounts.google.com/o/oauth2/v2/auth?client_id={GOOGLE_CLIENT_ID}&response_type=code&'
            f'redirect_uri={GOOGLE_REDIRECT_URI}&scope={scope}'
        )
    except Exception as e:
        print(e)
        messages.error(request, e)
        return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


@api_view(('GET',))
@renderer_classes((JSONRenderer,))
def google_callback(request):
    try:
        token_id = request.META.get('HTTP_AUTHORIZATION')
        profile_request = requests.get(f'https://www.googleapis.com/oauth2/v3/tokeninfo?id_token={token_id}')
        profile_json = profile_request.json()

        nickname = profile_json.get('name', None)
        email = profile_json.get('email', None)
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            user = None
        if user is not None:
            if user.login_path != User.GOOGLE:
                AlertException(f'{user.login_path}로 로그인 해주세요')
        else:
            user = User(email=email, login_path=User.GOOGLE, username=nickname)
            user.set_unusable_password()
            user.save()
        messages.success(request, f'{user.email} 구글 로그인 성공')
        login(request, user, backend="django.contrib.auth.backends.ModelBackend",)

        token = RefreshToken.for_user(user)
        data = {
            'user': user,
            'access_token': str(token.access_token),
            'refresh_token': str(token),
        }
        serializer = JWTSerializer(data)
        return Response({'message': '로그인 성공', **serializer.data}, status=status.HTTP_200_OK)
    except AlertException as e:
        print(e)
        messages.error(request, e)
        # 유저에게 알림
        return Response({'message': str(e)}, status=status.HTTP_406_NOT_ACCEPTABLE)
    except TokenException as e:
        print(e)
        # 개발 단계에서 확인
        return Response({'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GoogleLogin(SocialLoginView):
    authentication_classes = []
    adapter_class = GoogleOAuth2Adapter
    callback_url = "http://localhost:3000"
    client_class = OAuth2Client


@csrf_exempt
def google_token():
    if 'code' not in rest_framework.request.body.decode():
        from rest_framework_simplejwt.settings import api_settings as jwt_settings
        from rest_framework_simplejwt.views import TokenRefreshView

        class RefreshAuth(TokenRefreshView):
            def post(self, *args, **kwargs):
                self.request.data._mutable = True
                self.request.data['refresh'] = self.request.data.get('refresh_token')
                self.request.data._mutable = False
                response = super().post(self.request, *args, **kwargs)
                response.data['refresh_token'] = response.data['refresh']
                response.data['access_token'] = response.data['access']
                return response

        return RefreshAuth
    else:
        return GoogleLogin