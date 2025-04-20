import asyncio
import asyncpg
import logging
from werkzeug.security import generate_password_hash

# Настраиваем логгер
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Конфигурация подключения к базе данных (Beget)
DB_CONFIG = {
    "host": "quumdrafueyun.beget.app",
    "port": 5432,
    "user": "cloud_user",
    "password": "eLT1ApRZ%Fkf",
    "database": "default_db"
}


async def init_db():
    try:
        conn = await asyncpg.connect(**DB_CONFIG)
        await conn.execute("SET search_path TO public;")
        logger.info("✅ Подключение к PostgreSQL установлено.")

        # Создание таблицы user
        await conn.execute('''
        CREATE TABLE IF NOT EXISTS "user" (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            is_admin BOOLEAN NOT NULL DEFAULT FALSE,
            rsa_public_key TEXT
        )
        ''')

        # Таблица голосований
        await conn.execute('''
        CREATE TABLE IF NOT EXISTS poll (
            id SERIAL PRIMARY KEY,
            title TEXT NOT NULL,
            end_date TEXT NOT NULL,
            public_key_n TEXT,
            public_key_g TEXT,
            private_key TEXT
        )
        ''')

        # Таблица вариантов ответов
        await conn.execute('''
        CREATE TABLE IF NOT EXISTS poll_options (
            id SERIAL PRIMARY KEY,
            poll_id INTEGER NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
            option_text TEXT NOT NULL
        )
        ''')

        # Таблица голосов
        await conn.execute('''
        CREATE TABLE IF NOT EXISTS vote (
            id SERIAL PRIMARY KEY,
            poll_id INTEGER NOT NULL REFERENCES poll(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
            option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
            encrypted_vote TEXT NOT NULL,
            signature TEXT
        )
        ''')

        logger.info("✅ Таблицы успешно созданы или уже существуют.")

        # Проверка наличия пользователя admin
        user = await conn.fetchrow('SELECT id FROM "user" WHERE username = $1', 'Aleksandr')

        if not user:
            password_hash = generate_password_hash("password")
            await conn.execute(
                'INSERT INTO "user" (username, password_hash, is_admin) VALUES ($1, $2, $3)',
                'Aleksandr', password_hash, True
            )
            logger.info("🆕 Пользователь 'Aleksandr' создан и назначен администратором.")
        else:
            await conn.execute(
                'UPDATE "user" SET is_admin = $1 WHERE username = $2',
                True, 'Aleksandr'
            )
            logger.info("🔁 Пользователь 'Aleksandr' теперь администратор.")

        await conn.close()
        logger.info("🔒 Подключение к базе данных закрыто.")

    except Exception as e:
        logger.error(f"❌ Ошибка инициализации базы данных: {e}")


if __name__ == "__main__":
    asyncio.run(init_db())
