import sqlite3
from werkzeug.security import generate_password_hash

# Открываем соединение с базой данных
conn = sqlite3.connect('election.db')
cursor = conn.cursor()

# Проверяем, есть ли пользователь 'admin'
cursor.execute("SELECT id FROM user WHERE username = ?", ('admin',))
user = cursor.fetchone()

if not user:
    # Создаём пользователя (пароль 'password', но захешированный)
    password_hash = generate_password_hash("password")

    cursor.execute("INSERT INTO user (username, password_hash, is_admin) VALUES (?, ?, ?)",
                   ('admin', password_hash, 1))
    print("Пользователь 'admin' создан и назначен администратором.")
else:
    # Если пользователь уже есть, обновляем его права администратора
    cursor.execute("UPDATE user SET is_admin = 1 WHERE username = ?", ('admin',))
    print("Пользователь 'admin' теперь администратор.")

# Коммитим изменения и закрываем соединение
conn.commit()
conn.close()
