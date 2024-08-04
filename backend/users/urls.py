from django.urls import path
from . import views
from dj_rest_auth.registration.views import RegisterView
from rest_framework import routers

urlpatterns = [
    path("", views.Users.as_view()),
    path('my-profile/', views.UserDetail.as_view()),
    path("my-galleries/", views.MyGalleries.as_view()),
    path('like-galleries/', views.LikeGalleries.as_view()),
    
    # 구글 소셜로그인
    path('google-login/', views.google_login, name='google_login'),
    path('google-callback/', views.google_callback, name='google_callback'),
    # path('google/login/finish/', GoogleLogin.as_view(), name='google_login_todjango'),
]