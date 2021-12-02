from fastapi import FastAPI
from loguru import logger

from . import settings
from .endpoints import index, whois


def create_app():
    logger.add(
        settings.LOG_FILE, level=settings.LOG_LEVEL, backtrace=settings.LOG_BACKTRACE
    )

    app = FastAPI(
        debug=settings.DEBUG,
        title=settings.PROJECT_NAME,
    )

    # add routes
    app.include_router(index.router)
    app.include_router(whois.router, prefix="/api")

    return app


app = create_app()
