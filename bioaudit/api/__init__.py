"""Client for the BioAudit backend API.

Optional. The scanning engine, the CLI, and the report writer all work with no server
at all, so this package is only imported when the app is configured to sync results.
"""

from .client import (
    Account,
    ApiClient,
    ApiClientError,
    AuthRequiredError,
    Session,
)

__all__ = [
    "Account",
    "ApiClient",
    "ApiClientError",
    "AuthRequiredError",
    "Session",
]
