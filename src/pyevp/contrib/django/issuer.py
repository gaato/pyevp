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
from urllib.parse import urlsplit

from django.conf import settings
from django.core import checks
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import resolve_url
from django.urls import URLPattern, get_resolver, path
from django.views import View
from django.views.decorators.csrf import csrf_exempt

from pyevp.issuer import (
    FEDCM_FETCH_DEST,
    MAX_REQUEST_BODY,
    IssuanceError,
    IssuanceErrorCode,
    Issuer,
    IssuerResponse,
    accounts_document,
    is_valid_email,
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


def _overrides(cls: type, name: str) -> bool:
    return getattr(cls, name) is not getattr(IssuerSite, name)


class IssuerSite:
    """The issuer's endpoints, bound to one :class:`~pyevp.issuer.Issuer` or chosen per request.

    :param issuer: the issuer to serve.  Leave it out and override :meth:`get_issuer`
        when it depends on the request, e.g. on the host.
    :param login_url: where Chrome sends users who are not signed in; defaults to
        ``settings.LOGIN_URL``.  A path is taken relative to the issuer's origin.

    :attr:`urls` must be included at the root of the issuer's origin, and the paths
    below must match the issuer's ``issuance_endpoint`` and ``jwks_uri``.
    """

    metadata_path: ClassVar[str] = ".well-known/email-verification"
    jwks_path: ClassVar[str] = "email-verification/jwks"
    issuance_path: ClassVar[str] = "email-verification/issuance"
    accounts_path: ClassVar[str] = "fedcm/accounts"
    web_identity_path: ClassVar[str] = ".well-known/web-identity"

    def __init__(self, issuer: Issuer | None = None, *, login_url: str | None = None) -> None:
        if issuer is not None:
            for url, route in (
                (issuer.issuance_endpoint, self.issuance_path),
                (issuer.jwks_uri, self.jwks_path),
            ):
                if urlsplit(url).path != "/" + route:
                    raise ImproperlyConfigured(f"{url} is not served at /{route}")
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
        """
        raise NotImplementedError

    def owns(self, request: HttpRequest, email: str) -> bool:
        """Whether the signed-in user controls ``email``, compared case-insensitively.

        Addresses EVP cannot carry are ignored: lowercasing a non-ASCII one can turn it into
        someone else's (``\\u212aate@`` with a KELVIN SIGN becomes ``kate@``).
        """
        return email.lower() in {e.lower() for e in self.user_emails(request) if is_valid_email(e)}

    def get_login_url(self, request: HttpRequest) -> str:
        url = resolve_url(self.login_url or settings.LOGIN_URL)
        return self.get_issuer(request).issuer + url if url.startswith("/") else url

    # --- URLs ---

    @property
    def urls(self) -> list[URLPattern]:
        return [
            path(self.metadata_path, MetadataView.as_view(site=self)),
            path(self.jwks_path, JWKSView.as_view(site=self)),
            path(self.issuance_path, IssuanceView.as_view(site=self)),
            path(self.accounts_path, AccountsView.as_view(site=self)),
            path(self.web_identity_path, WebIdentityView.as_view(site=self)),
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

    Exempt from CSRF protection and from ``ATOMIC_REQUESTS``; use a synchronous
    replay guard such as :class:`~pyevp.contrib.django.EVPReplayGuard`.
    Put per-IP rate limiting in front of it.
    """

    http_method_names = ["post"]  # noqa: RUF012

    @classmethod
    def as_view(cls, **initkwargs: Any) -> Callable[..., HttpResponse]:
        view = super().as_view(**initkwargs)
        # A forged cross-site POST cannot pass: Sec-Fetch-Dest: email-verification can only
        # come from the browser itself, and a JSON body needs a CORS preflight.
        view = csrf_exempt(view)
        # The replay guard must commit its record on its own; see EVPReplayGuard.
        view._non_atomic_requests = set(settings.DATABASES)
        return view

    def post(self, request: HttpRequest) -> HttpResponse:
        site = self._site()
        issuer = site.get_issuer(request)
        try:
            body = _read_body(request)
            parsed = issuer.parse_request(
                method=request.method or "", headers=request.headers.items(), body=body
            )
            # One answer for every way this can fail, so responses do not reveal accounts.
            if not site.owns(request, parsed.email):
                raise IssuanceError.authentication_required()
            result = issuer.success_response(issuer.issue(parsed))
        except IssuanceError as exc:
            result = exc.to_response()
        return _to_http(result)

    def http_method_not_allowed(self, request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
        error = IssuanceError(IssuanceErrorCode.INVALID_REQUEST, f"method {request.method}")
        return _to_http(error.to_response())


class AccountsView(_IssuerView):
    """The FedCM accounts endpoint Chrome checks before asking for a token."""

    def get(self, request: HttpRequest) -> HttpResponse:
        if request.headers.get("Sec-Fetch-Dest") != FEDCM_FETCH_DEST:
            return JsonResponse({"error": "not a FedCM request"}, status=400)
        emails = [e for e in self._site().user_emails(request) if is_valid_email(e)]
        if not emails:
            return JsonResponse({"accounts": []}, status=401)
        return JsonResponse(accounts_document(emails))


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
            response["Set-Login"] = "logged-in" if user.is_authenticated else "logged-out"
        return response


def _read_body(request: HttpRequest) -> bytes:
    # Do not read a body the issuer will refuse anyway; it refuses it from Content-Length.
    length = request.META.get("CONTENT_LENGTH") or "0"
    if not length.isascii() or not length.isdigit() or len(length) > 9:
        return b""
    return b"" if int(length) > MAX_REQUEST_BODY else request.body


def _to_http(result: IssuerResponse) -> HttpResponse:
    return HttpResponse(result.body, status=result.status, headers=result.headers)


_PER_RESPONSE = (
    " If your session middleware sets the cookie's attributes per response instead, "
    "add this check to SILENCED_SYSTEM_CHECKS."
)


def check_session_cookie(**kwargs: Any) -> list[checks.CheckMessage]:
    """Warn when Chrome's cross-site requests to an :class:`IssuerSite` would lack the session.

    Registered as a deployment check (``manage.py check --deploy``).  It reads the
    settings, so it cannot see attributes a middleware sets per response.
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
