"""Collection of workflow automation tools.

This module keeps a small public surface and delegates implementation to subpackages.
"""

__all__ = ['eserv']

from automate.eserv import _component as eserv
