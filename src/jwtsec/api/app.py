"""FastAPI application factory and middleware configuration for jwtsec."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from jwtsec.api.routes import router
from jwtsec.config.settings import get_settings


def create_app() -> FastAPI:
    """Instantiate and configure the FastAPI microservice application."""
    settings = get_settings()

    app = FastAPI(
        title="JWT Security Analyzer & Verification API",
        description=(
            "Production-grade REST microservice providing automated JWT vulnerability auditing, "
            "asymmetric key confusion detection, dictionary cracking, token crafting, and "
            "dual-mode interactive verification testing."
        ),
        version=settings.version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Configure CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routes
    app.include_router(router)

    return app


app = create_app()
