"""Errors package for eserv module.

This package provides error and exception classes for the eserv service.
"""

__all__ = ['error_factory', 'raise_from_auth_response']

from .authentication import raise_from_auth_response
from .pipeline import error_factory
