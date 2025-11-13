"""Enhanced authentication middleware with better error messages.

This module provides enhanced versions of MCP SDK authentication middleware
that return more helpful error messages for developers troubleshooting
authentication issues.
"""

from __future__ import annotations

import json

from mcp.server.auth.middleware.bearer_auth import (
    RequireAuthMiddleware as SDKRequireAuthMiddleware,
)
from starlette.types import Receive, Scope, Send

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


class RequireAuthMiddleware(SDKRequireAuthMiddleware):
    """Enhanced authentication middleware with detailed error messages.

    Extends the SDK's RequireAuthMiddleware to provide more actionable
    error messages when authentication fails. This helps developers
    understand what went wrong and how to fix it.
    
    Also handles transferring the upstream_token from the AccessToken
    to the request scope for downstream use.
    """
    
    def __init__(self, *args, **kwargs):
        """Initialize and wrap the app with token transfer logic."""
        super().__init__(*args, **kwargs)
        
        # Store the original app before wrapping it
        original_app = self.app
        
        # Create a wrapper that extracts upstream token after auth validation
        async def token_transfer_wrapper(scope: Scope, receive: Receive, send: Send) -> None:
            # After auth validation, scope["user"] contains AuthenticatedUser with access_token
            logger.debug(f"🔍 Checking scope for user: 'user' in scope = {'user' in scope}")
            if "user" in scope:
                user = scope["user"]
                logger.debug(f"🔍 User type: {type(user)}")
                logger.debug(f"🔍 Has access_token: {hasattr(user, 'access_token')}")
                
                # Get the AccessToken from the AuthenticatedUser
                if hasattr(user, "access_token"):
                    access_token = user.access_token
                    logger.debug(f"🔍 AccessToken type: {type(access_token)}")
                    logger.debug(f"🔍 Has _upstream_token: {hasattr(access_token, '_upstream_token')}")
                    
                    # Transfer upstream token from AccessToken to scope for session access
                    if hasattr(access_token, "_upstream_token"):
                        upstream = access_token._upstream_token
                        scope["upstream_token"] = upstream
                        logger.info(f"✅ Transferred upstream_token to scope: {upstream[:50] if upstream else 'None'}...")
                    else:
                        logger.warning("⚠️  AccessToken has no _upstream_token attribute")
                else:
                    logger.warning("⚠️  User has no access_token attribute")
            else:
                logger.warning("⚠️  No 'user' in scope - cannot transfer upstream token")
            
            # Call the original wrapped application
            await original_app(scope, receive, send)
        
        # Replace self.app with our wrapper
        self.app = token_transfer_wrapper

    async def _send_auth_error(
        self, send: Send, status_code: int, error: str, description: str
    ) -> None:
        """Send an authentication error response with enhanced error messages.

        Overrides the SDK's _send_auth_error to provide more detailed
        error descriptions that help developers troubleshoot authentication
        issues.

        Args:
            send: ASGI send callable
            status_code: HTTP status code (401 or 403)
            error: OAuth error code
            description: Base error description
        """
        # Enhance error descriptions based on error type
        enhanced_description = description

        if error == "invalid_token" and status_code == 401:
            # This is the "Authentication required" error
            enhanced_description = (
                "Authentication failed. The provided bearer token is invalid, expired, or no longer recognized by the server. "
                "To resolve: clear authentication tokens in your MCP client and reconnect. "
                "Your client should automatically re-register and obtain new tokens."
            )
        elif error == "insufficient_scope":
            # Scope error - already has good detail from SDK
            pass

        # Build WWW-Authenticate header value
        www_auth_parts = [
            f'error="{error}"',
            f'error_description="{enhanced_description}"',
        ]
        if self.resource_metadata_url:
            www_auth_parts.append(f'resource_metadata="{self.resource_metadata_url}"')

        www_authenticate = f"Bearer {', '.join(www_auth_parts)}"

        # Send response
        body = {"error": error, "error_description": enhanced_description}
        body_bytes = json.dumps(body).encode()

        await send(
            {
                "type": "http.response.start",
                "status": status_code,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body_bytes)).encode()),
                    (b"www-authenticate", www_authenticate.encode()),
                ],
            }
        )

        await send(
            {
                "type": "http.response.body",
                "body": body_bytes,
            }
        )

        logger.info(
            "Auth error returned: %s (status=%d)",
            error,
            status_code,
        )
