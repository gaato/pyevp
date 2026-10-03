"""Minimal Django issuer for your own email domains (development only).

Users are Django's own; each may get tokens for the address on their account.
Configure it with environment variables::

    pyevp issuer keygen --kid 2026-10 --out signing-key.json
    export EVP_ISSUER=https://issuer.example
    export EVP_PUBLIC_URL=https://issuer.example     # where this app is reachable
    export EVP_EMAIL_DOMAINS=example.com
    export EVP_SIGNING_KEY=signing-key.json          # without it, a new key per start
    export DJANGO_SECRET_KEY=...
    uv run manage.py migrate
    uv run manage.py createsuperuser                 # with an @example.com address
    uv run manage.py runserver 8000                  # behind an HTTPS proxy

and publish ``_email-verification.example.com TXT "iss=issuer.example"``.
Check the result with ``pyevp discover example.com``.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

BASE_DIR = Path(__file__).resolve().parent

EVP_ISSUER = os.environ.get("EVP_ISSUER", "https://issuer.example")
EVP_PUBLIC_URL = os.environ.get("EVP_PUBLIC_URL", EVP_ISSUER).rstrip("/")
EVP_EMAIL_DOMAINS = os.environ.get("EVP_EMAIL_DOMAINS", "example.com").split(",")
EVP_SIGNING_KEY = os.environ.get("EVP_SIGNING_KEY")

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-only-not-secret")
DEBUG = True
ALLOWED_HOSTS = [urlsplit(EVP_ISSUER).hostname, urlsplit(EVP_PUBLIC_URL).hostname, "testserver"]
ROOT_URLCONF = "urls"

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "pyevp.contrib.django",  # the session cookie checks
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "pyevp.contrib.django.issuer.LoginStatusMiddleware",
]

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
            ],
        },
    }
]

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

# Chrome sends the issuer's cookies with its FedCM accounts request and the issuance
# request, both cross-site from the relying party: the cookie needs SameSite=None.
SESSION_COOKIE_SAMESITE = "None"
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
# The HTTPS proxy in front of runserver.
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [EVP_PUBLIC_URL]

LOGIN_REDIRECT_URL = "/"
USE_TZ = True
