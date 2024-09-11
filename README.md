#  Сервис аутентификации (его подобие)
**POST /users/tokens/create?guid=<GUID пользователя> выдаёт связку ключей в json**  
**POST /users/tokens/refresh (со связкой ключей в теле запроса в json) выдаёт новые ключи**  

Содержимое Access токена - guid, ip пользователя, iat (время выпуска) и jti (уникальный ID), формат JWT HS-512.  
Содержимое Refresh токена - ip пользователя и iat (время выпуска), формат - GCM AES-256 с nonce равным последним 12 байтам Access токена.  
При операции /users/tokens/refresh на годность по времени проверяется только Refresh токен.  
Используется логгер Zap. Для подключения к PostgresSQL используется pq.
## Запуск
### PostgreSQL
    
    CREATE TABLE users (
        guid uuid DEFAULT gen_random_uuid(),
        first_name varchar,
        last_name varchar,
        email varchar
    );
    CREATE INDEX ON users(guid);
    CREATE TABLE tokens (
        user_guid UUID NOT NULL,
        hash varchar NOT NULL,
        created_at TIMESTAMP default current_timestamp
    );
   Тестовые данные для таблицы есть в test/users.sql  
### Переменные окружения или файл go.env

    GO_ENV="DEV"
    DATABASE_DSN="host=localhost port=5432 user= password= dbname= sslmode=disable"
    SECRET="32-byte sequence. Keep it secret"