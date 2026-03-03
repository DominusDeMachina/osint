"""Security module for authentication and authorization."""

from app.core.security.clerk import ClerkTokenClaims, validate_clerk_token


# RBAC imports are lazy to avoid circular imports
# Import directly from app.core.security.rbac when needed


__all__ = [
    "ClerkTokenClaims",
    "validate_clerk_token",
]


def __getattr__(name: str):
    """Lazy import for RBAC dependencies to avoid circular imports."""
    rbac_exports = {
        "RequireAdmin",
        "RequireAdminDep",
        "RequireEditor",
        "RequireEditorDep",
        "RequireGlobalRole",
        "RequireInvestigationRole",
        "RequireOwner",
        "RequireOwnerDep",
        "RequireViewer",
        "RequireViewerDep",
    }
    if name in rbac_exports:
        from app.core.security import rbac  # noqa: PLC0415

        return getattr(rbac, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
