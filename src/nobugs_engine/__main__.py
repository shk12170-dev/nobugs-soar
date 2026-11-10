"""python -m nobugs_engine  (환경변수 NB_ENGINE_PORT, 기본 5200 / 127.0.0.1에만 연다)"""
import os

import uvicorn

from .app import create_engine_app

if __name__ == "__main__":
    uvicorn.run(create_engine_app(), host="127.0.0.1", port=int(os.environ.get("NB_ENGINE_PORT", "5200")),
                log_level="warning")
