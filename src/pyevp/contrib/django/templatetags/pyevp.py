"""Template tags for EVP forms, loaded with ``{% load pyevp %}``."""

from __future__ import annotations

from django import template
from django.core.exceptions import ImproperlyConfigured

from pyevp.contrib.django import get_nonce
from pyevp.nonce import token_input

register = template.Library()


@register.simple_tag(takes_context=True)
def evp_token_input(context: template.Context, field: str = "evt") -> str:
    """Render the hidden input that the browser fills with the token.

    Put it inside the form, next to ``<input type="email" autocomplete="email">``.
    All tags on a page share one nonce (see :func:`~pyevp.contrib.django.get_nonce`).
    """
    request = context.get("request")
    if request is None:
        raise ImproperlyConfigured(
            "{% evp_token_input %} needs the request in the template context: enable "
            "django.template.context_processors.request or render with a request."
        )
    return token_input(get_nonce(request), field=field)
