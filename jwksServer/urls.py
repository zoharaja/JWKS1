from django.contrib import admin
from django.urls import path
from project1.views import get_keys, get_jwt

urlpatterns = [
    # URL pattern for the auth endpoint, it will handle 'expired' as a query parameter
    path('auth', get_jwt, name='serve_jwt'),

    # URL pattern for the JWKS endpoint
    path('.well-known/jwks.json', get_keys, name='serve_rsa_public_keys'),
]