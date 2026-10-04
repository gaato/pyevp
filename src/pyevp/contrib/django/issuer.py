"""Running an EVP issuer in Django.

:class:`IssuerSite` serves everything Chrome needs from an issuer, with the
logged-in Django user deciding which addresses get tokens::

    # urls.py, on the issuer's origin
    from pyevp.contrib.django.issuer import IssuerSite

    class Site(IssuerSite):
        def user_emails(self, request):
            ...                       # addresses whose mail the user receives

    evp = Site(issuer)                # a pyevp.issuer.Issuer
    urlpatterns = [path("", include(evp.urls)), ...]

Subclass it to say which addresses a user may get tokens for
(:meth:`IssuerSite.user_emails`, required) and, optionally, to choose the issuer
per request (:meth:`IssuerSite.get_issuer`).  Each endpoint is also a view of
its own, for mounting it somewhere else::

    path("fedcm/accounts", AccountsView.as_view(site=evp))

The session cookie must be ``SameSite=None; Secure``, because Chrome's requests
to the issuer are cross-site; a system check warns otherwise.  Add
:class:`LoginStatusMiddleware` so that Chrome knows when users are signed in.
"""

from __future__ import annotations

import weakref
from collections.abc import Callable, Sequence
from typing import Any, ClassVar

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse
from django.shortcuts import resolve_url
from django.urls import URLPattern, get_resolver, path
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from pyevp._drive import is_async
from pyevp.issuer import (
    METADATA_PATH,
    WEB_IDENTITY_PATH,
    Issuer,
    IssuerResponse,
    login_status_headers,
    web_identity_response,
)

__all__ = [
    "AccountsView",
    "IssuanceView",
    "IssuerSite",
    "JWKSView",
    "LoginStatusMiddleware",
    "MetadataView",
    "WebIdentityView",
]

_sites: weakref.WeakSet[IssuerSite] = weakref.WeakSet()


def _route(path: str, declared: str | None) -> str:
    """The issuer's ``path`` as a route, which must be ``declared`` if that is set."""
    route = path.removeprefix("/")
    if declared is not None and declared != route:
        raise ImproperlyConfigured(f"the issuer's {path} is not served at /{declared}")
    return route


def _overrides(cls: type, name: str) -> bool:
    return getattr(cls, name) is not getattr(IssuerSite, name)


class IssuerSite:
    """The issuer's endpoints, bound to one :class:`~pyevp.issuer.Issuer` or chosen per request.

    :param issuer: the issuer to serve.  Leave it out and override :meth:`get_issuer`
        when it depends on the request, e.g. on the host.
    :param login_url: where Chrome sends users who are not signed in; defaults to
        ``settings.LOGIN_URL``.  A path is taken relative to the issuer's origin.

    :attr:`urls` must be included at the root of the issuer's origin.  The issuance and JWKS
    endpoints are served where the issuer's ``issuance_endpoint`` and ``jwks_uri`` say.
    Without an issuer, :attr:`issuance_path` and :attr:`jwks_path` must say where, for every
    issuer :meth:`get_issuer` returns.
    """

    issuance_path: ClassVar[str | None] = None
    """Where issuance requests are routed, without the leading ``/``; the issuer's by default."""
    jwks_path: ClassVar[str | None] = None
    """Where the JWKS is served, as for :attr:`issuance_path`."""
    accounts_path: ClassVar[str] = "fedcm/accounts"
    """Where the FedCM accounts endpoint is served."""

    def __init__(self, issuer: Issuer | None = None, *, login_url: str | None = None) -> None:
        if issuer is None:
            if self.issuance_path is None or self.jwks_path is None:
                raise ImproperlyConfigured(
                    "without an Issuer, set issuance_path and jwks_path on the IssuerSite"
                )
            self._issuance_route, self._jwks_route = self.issuance_path, self.jwks_path
        else:
            self._issuance_route = _route(issuer.issuance_path, self.issuance_path)
            self._jwks_route = _route(issuer.jwks_path, self.jwks_path)
            guard = issuer.replay_guard
            if is_async(getattr(guard, "mark_used", None)):
                raise ImproperlyConfigured(
                    "IssuerSite's views are synchronous; use a synchronous replay guard "
                    "such as pyevp.contrib.django.EVPReplayGuard"
                )
        self.issuer = issuer
        self.login_url = login_url
        if not _overrides(type(self), "user_emails"):
            raise ImproperlyConfigured(
                "subclass IssuerSite and override user_emails() with the addresses whose "
                "mail the signed-in user receives"
            )
        _sites.add(self)

    # --- hooks ---

    def get_issuer(self, request: HttpRequest) -> Issuer:
        """The issuer answering ``request``."""
        if self.issuer is None:
            raise ImproperlyConfigured("pass an Issuer to IssuerSite or override get_issuer")
        return self.issuer

    def user_emails(self, request: HttpRequest) -> Sequence[str]:
        """Addresses the signed-in user may get tokens for; empty without a session.

        Override this.  A token tells relying parties that the user controls the address, so
        return only addresses whose mail the user actually receives, for example the
        verified addresses of django-allauth, or what your mail server delivers to the
        user's mailbox.  A user model's email field is not that unless your sign-up flow
        verified it, which is why there is no default.

        Return addresses with ASCII domains (A-labels); the issuer compares them with the
        requested address case-insensitively and ignores any it could not issue for.
        """
        raise NotImplementedError

    def get_login_url(self, request: HttpRequest) -> str:
        url = resolve_url(self.login_url or settings.LOGIN_URL)
        return self.get_issuer(request).issuer + url if url.startswith("/") else url

    # --- URLs ---

    @property
    def urls(self) -> list[URLPattern]:
        return [
            path(METADATA_PATH.lstrip("/"), MetadataView.as_view(site=self)),
            path(self._jwks_route, JWKSView.as_view(site=self)),
            path(self._issuance_route, IssuanceView.as_view(site=self)),
            path(self.accounts_path, AccountsView.as_view(site=self)),
            path(WEB_IDENTITY_PATH.lstrip("/"), WebIdentityView.as_view(site=self)),
        ]


class _IssuerView(View):
    site: IssuerSite | None = None

    def _site(self) -> IssuerSite:
        if self.site is None:
            raise ImproperlyConfigured(f"{type(self).__name__}.as_view() needs site=")
        return self.site


class MetadataView(_IssuerView):
    """``/.well-known/email-verification``."""

    def get(self, request: HttpRequest) -> HttpResponse:
        return _to_http(self._site().get_issuer(request).metadata_response())


class JWKSView(_IssuerView):
    """The issuer's ``jwks_uri``."""

    def get(self, request: HttpRequest) -> HttpResponse:
        return _to_http(self._site().get_issuer(request).jwks_response())


class IssuanceView(_IssuerView):
    """The issuer's ``issuance_endpoint``: an EVT for a user who controls the address.

    Every method is answered by :meth:`Issuer.issuance_response
    <pyevp.issuer.Issuer.issuance_response>`.  Exempt from CSRF protection and from
    ``ATOMIC_REQUESTS``; use a synchronous replay guard such as
    :class:`~pyevp.contrib.django.EVPReplayGuard`.  Put per-IP rate limiting in front of it.
    """

    @classmethod
    def as_view(cls, **initkwargs: Any) -> Callable[..., HttpResponse]:
        view = super().as_view(**initkwargs)
        # A forged cross-site POST cannot pass: Sec-Fetch-Dest: email-verification can only
        # come from the browser itself, and a JSON body needs a CORS preflight.
        view = csrf_exempt(view)
        # The replay guard must commit its record on its own; see EVPReplayGuard.
        view._non_atomic_requests = set(settings.DATABASES)
        return view

    def dispatch(self, request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
        site = self._site()
        response = site.get_issuer(request).issuance_response(
            method=request.method or "",
            # Django has joined repeated header lines with commas, which the issuer accepts.
            headers=request.headers.items(),
            # Read by the issuer only as far as needed, without DATA_UPLOAD_MAX_MEMORY_SIZE.
            body=request.read,
            user_emails=lambda: site.user_emails(request),
        )
        return _to_http(response)


class AccountsView(_IssuerView):
    """The FedCM accounts endpoint Chrome checks before asking for a token."""

    def get(self, request: HttpRequest) -> HttpResponse:
        site = self._site()
        response = site.get_issuer(request).accounts_response(
            headers=request.headers.items(), user_emails=lambda: site.user_emails(request)
        )
        return _to_http(response)


class WebIdentityView(_IssuerView):
    """``/.well-known/web-identity``, which Chrome reads on the issuer's registrable domain."""

    def get(self, request: HttpRequest) -> HttpResponse:
        site = self._site()
        response = web_identity_response(
            accounts_endpoint=f"{site.get_issuer(request).issuer}/{site.accounts_path}",
            login_url=site.get_login_url(request),
        )
        return _to_http(response)


class LoginStatusMiddleware:
    """Tells Chrome whether the user is signed in (FedCM Login Status API).

    Adds ``Set-Login: logged-in`` or ``logged-out`` to page responses, so that
    Chrome does not skip the issuer for a signed-in user.  Place it after
    ``AuthenticationMiddleware``.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)
        user = getattr(request, "user", None)
        if (
            user is not None
            and request.headers.get("Sec-Fetch-Dest") == "document"
            and "Set-Login" not in response
        ):
            for name, value in login_status_headers(signed_in=user.is_authenticated).items():
                response[name] = value
        return response


def _to_http(result: IssuerResponse) -> HttpResponse:
    return HttpResponse(result.body, status=result.status, headers=result.headers)


_PER_RESPONSE = (
    " If your session middleware sets the cookie's attributes per response instead, "
    "add this check to SILENCED_SYSTEM_CHECKS."
)


def check_session_cookie(**kwargs: Any) -> list[checks.CheckMessage]:
    """Warn when settings would break an :class:`IssuerSite`.

    Chrome's cross-site requests would lack the session (``pyevp.W001``, ``pyevp.W002``).
    Registered as a deployment check (``manage.py check --deploy``).  It reads the settings,
    so it cannot see attributes a middleware sets per response.
    """
    if getattr(settings, "ROOT_URLCONF", None):
        get_resolver().url_patterns  # noqa: B018  (importing the URLconf creates the sites)
    if not _sites:
        return []
    warnings = []
    if settings.SESSION_COOKIE_SAMESITE != "None":
        warnings.append(
            checks.Warning(
                "SESSION_COOKIE_SAMESITE is not 'None'.",
                hint="Chrome's FedCM and issuance requests to the issuer are cross-site; "
                "without SameSite=None they carry no session and every request fails."
                + _PER_RESPONSE,
                id="pyevp.W001",
            )
        )
    if not settings.SESSION_COOKIE_SECURE:
        warnings.append(
            checks.Warning(
                "SESSION_COOKIE_SECURE is off.",
                hint="Browsers drop SameSite=None cookies that are not Secure." + _PER_RESPONSE,
                id="pyevp.W002",
            )
        )
    return warnings
