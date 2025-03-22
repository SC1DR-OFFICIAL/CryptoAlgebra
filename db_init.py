import sqlite3

conn = sqlite3.connect('election.db')
cursor = conn.cursor()

# Таблица пользователей
cursor.execute('''
CREATE TABLE IF NOT EXISTS user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0
)''')

# Таблица голосований
cursor.execute('''
CREATE TABLE IF NOT EXISTS poll (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    end_date TEXT NOT NULL,
    public_key_n TEXT,
    public_key_g TEXT,
    private_key TEXT
)''')

# Таблица вариантов ответов
cursor.execute('''
CREATE TABLE IF NOT EXISTS poll_options (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id INTEGER NOT NULL,
    option_text TEXT NOT NULL,
    FOREIGN KEY(poll_id) REFERENCES poll(id)
)''')

# Таблица голосов
cursor.execute('''
CREATE TABLE IF NOT EXISTS vote (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    poll_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    option_id INTEGER NOT NULL,
    encrypted_vote TEXT NOT NULL,
    FOREIGN KEY(poll_id) REFERENCES poll(id),
    FOREIGN KEY(user_id) REFERENCES user(id),
    FOREIGN KEY(option_id) REFERENCES poll_options(id)
)''')

conn.commit()
conn.close()
print("База данных обновлена.")

# Проверяем, есть ли пользователь 'Aleksandr'
cursor.execute("SELECT id FROM user WHERE username = ?", ('admin',))
user = cursor.fetchone()

if not user:
    # Создаём пользователя (пароль по умолчанию 'password', но надо захешировать!)
    from werkzeug.security import generate_password_hash
    password_hash = generate_password_hash("password")

    cursor.execute("INSERT INTO user (username, password_hash, is_admin) VALUES (?, ?, ?)",
                   ('Aleksandr', password_hash, 1))
    conn.commit()
    print("Пользователь 'Aleksandr' создан и назначен администратором.")
else:
    # Если пользователь уже есть, просто обновляем его права администратора
    cursor.execute("UPDATE user SET is_admin = 1 WHERE username = ?", ('Aleksandr',))
    conn.commit()
    print("Пользователь 'Aleksandr' теперь администратор.")

conn.close()
