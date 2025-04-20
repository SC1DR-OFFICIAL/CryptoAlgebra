# drop_tables.py
import asyncio
import asyncpg
import logging

# Логирование
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Конфиг подключения к вашей БД PostgreSQL
DB_CONFIG = {
    "host": "quumdrafueyun.beget.app",
    "port": 5432,
    "user": "cloud_user",
    "password": "eLT1ApRZ%Fkf",
    "database": "default_db"
}


async def drop_all_tables():
    conn = await asyncpg.connect(**DB_CONFIG)
    await conn.execute("SET search_path TO public;")
    logger.info("✅ Подключились к БД, начинаем удаление таблиц...")

    # Удаляем все таблицы в правильном порядке
    await conn.execute('DROP TABLE IF EXISTS vote CASCADE;')
    await conn.execute('DROP TABLE IF EXISTS poll_options CASCADE;')
    await conn.execute('DROP TABLE IF EXISTS poll CASCADE;')
    await conn.execute('DROP TABLE IF EXISTS "user" CASCADE;')

    logger.info("🗑️ Все таблицы удалены.")
    await conn.close()
    logger.info("🔒 Отключились от БД.")


if __name__ == "__main__":
    asyncio.run(drop_all_tables())
