# init_db.py
import asyncio
import asyncpg
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

DB_CONFIG = {
    "host": "quumdrafueyun.beget.app",
    "port": 5432,
    "user": "cloud_user",
    "password": "eLT1ApRZ%Fkf",
    "database": "default_db"
}


async def init_db():
    conn = await asyncpg.connect(**DB_CONFIG)
    await conn.execute("SET search_path TO public;")
    logger.info("✅ Подключение к PostgreSQL установлено.")

    # Пользователи
    await conn.execute('''
    CREATE TABLE IF NOT EXISTS "user" (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        rsa_public_key TEXT,
        password_hash TEXT NOT NULL,
        is_admin BOOLEAN NOT NULL DEFAULT FALSE
    );
    ''')

    # Голосования
    await conn.execute('''
    CREATE TABLE IF NOT EXISTS poll (
        id SERIAL PRIMARY KEY,
        title TEXT NOT NULL,
        end_date TEXT NOT NULL,
        public_key_n TEXT,
        public_key_g TEXT,
        private_key TEXT
    );
    ''')

    # Варианты
    await conn.execute('''
    CREATE TABLE IF NOT EXISTS poll_options (
        id SERIAL PRIMARY KEY,
        poll_id INTEGER NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
        option_text TEXT NOT NULL
    );
    ''')

    # Голоса (без signature)
    await conn.execute('''
    CREATE TABLE IF NOT EXISTS vote (
        id SERIAL PRIMARY KEY,
        poll_id INTEGER NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
        user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
        ciphertexts TEXT NOT NULL,
        signature TEXT
    );
    ''')

    logger.info("✅ Таблицы созданы.")
    await conn.close()
    logger.info("🔒 Отключение от БД.")


if __name__ == "__main__":
    asyncio.run(init_db())
