import os
import pytest

# Force test environment and isolated test database URL (asm_test.db)
# to prevent pytest fixtures from dropping tables in the local development database (asm_dev.db).
TEST_DB_PATH = "/home/sabby/Projects/attack-surface-monitor/apps/control-plane/asm_test.db"
TEST_DB_URL = f"sqlite+aiosqlite:///{TEST_DB_PATH}"

os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = TEST_DB_URL

from app.core.config import settings

settings.APP_ENV = "test"
settings.DATABASE_URL = TEST_DB_URL
