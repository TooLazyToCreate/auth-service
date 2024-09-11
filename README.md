## Простой сервис аутентификации
Содержимое access токена - ip и guid пользователя, формат JWT.
Содержимое refresh токена - nonce, ip пользователя и кусок access токена,
формат - 12 байт nonce + GCM SHA-256 от сериализованного json с ip + 12 байт access токена, которые включены в аутентификацию токена.
Используется логгер Zap. Для подключения к PostgresSQL используется pq.
### Запуск
**PostgreSQL**

    CREATE TABLE users (
        guid uuid DEFAULT gen_random_uuid(),
        first_name varchar,
        last_name varchar,
        email varchar
    );
    CREATE INDEX ON users(guid);
    CREATE TABLE tokens (
        user_guid UUID NOT NULL,
        hash varchar NOT NULL
    );
   Тестовые данные для таблицы есть в test/users.sql
**go.env**

    GO_ENV="DEV"
    DATABASE_URL="host=localhost port=5432 user= password= dbname= sslmode=disable"
    SECRET="32-byte sequence. Keep it secret"