import asyncio
import asyncpg
from werkzeug.security import generate_password_hash

# --- Конфиг подключения к Postgres ---
from dotenv import load_dotenv
import os

load_dotenv()  # загружаем .env

DB_CONFIG = {
    "host": os.getenv("DB_HOST"),
    "port": int(os.getenv("DB_PORT")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME")
}


async def create_admin():
    username = "admin"
    password = "HardPass12345"
    password_hash = generate_password_hash(password)

    conn = await asyncpg.connect(**DB_CONFIG)
    await conn.execute("""
        INSERT INTO "user" (username, password_hash, is_admin)
        VALUES ($1, $2, TRUE)
        ON CONFLICT (username) DO NOTHING;
    """, username, password_hash)
    await conn.close()
    print("✅ Админ создан.")


if __name__ == "__main__":
    asyncio.run(create_admin())
