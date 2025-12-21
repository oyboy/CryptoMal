# CryptoCore

Командная утилита для шифрования и дешифрования файлов с использованием AES-128 в различных режимах, вычисления криптографических хешей, HMAC, генерации ключей и аутентификации.

---

## Возможности

- **Симметричное шифрование (AES‑128)**:
  - Режимы: **ECB**, **CBC**, **CTR**, **OFB**, **GCM** (аутентифицированный режим)
  - Автоматическая генерация ключей и IV/nonce при необходимости
  - Поддержка бинарных файлов, нуль-байтов, произвольных размеров

- **Криптографические хеш‑функции**:
  - **SHA‑256** (реализация с нуля по FIPS 180‑4)
  - **SHA3‑256** (через проверенную реализацию)

- **HMAC (Hash-based Message Authentication Code)**:
  - **HMAC‑SHA256**, реализованный поверх собственной SHA‑256
  - Совместимость с RFC 4231 (проверено тестовыми векторами)

- **Аутентифицированное шифрование (AEAD, GCM)**:
  - AES‑GCM с поддержкой **AAD** (дополнительные аутентифицируемые данные)
  - Формат файла: `nonce (12 байт) | ciphertext | tag (16 байт)`
  - Отказ при ошибке аутентификации (нет вывода открытого текста)

- **Функции выведения ключей (KDF)**:
  - **PBKDF2‑HMAC‑SHA256**:
    - Соль (hex‑строка), настраиваемое число итераций
  - **Иерархическое выведение ключей (HKDF‑подобная функция)**:
    - API `derive_key(master_key, context, length)` в библиотеке
    - Разные контексты → разные ключи из одного мастер‑ключа

- **CSPRNG (криптографически стойкий ГПСЧ)**:
  - Используется для генерации ключей, IV, nonce, солей
  - Тесты случайности

- **Интеграционное и модульное тестирование**:
  - Тесты на:
    - AES‑режимы (round‑trip + NIST‑вектора)
    - GCM (включая негативные случаи, tampering, неверный AAD)
    - SHA‑256 / SHA3‑256 (NIST‑вектора)
    - HMAC
    - PBKDF2
    - KDF/Keygen, CSPRNG, валидацию параметров
  - Скрипт `scripts/test.ps1` запускает полный прогон (build + Rust‑тесты + CLI‑тесты)

---

## Сборка

### Требования

- **Rust** (актуальная версия, через `rustup`)
- **Cargo** (входит в состав Rust)
- Windows / Linux / macOS

### Сборка через Cargo

```bash
# Отладочная сборка
cargo build

# Релизная сборка
cargo build --release
```

## Использование
### Общие команды

```
# Шифрование / дешифрование файлов
cryptocore --encrypt --algorithm aes --mode cbc --key <HEX> --input in.txt --output out.bin
cryptocore --decrypt --algorithm aes --mode cbc --key <HEX> --input out.bin --output dec.txt

# Хеши и HMAC
cryptocore dgst --algorithm sha256 --input file
cryptocore dgst --algorithm sha256 --hmac --key <HEX> --input file

# PBKDF2
cryptocore derive --password "pass" --salt <SALT_HEX> --iterations 100000 --length 32
```

### Шифрование / дешифрование

```
cryptocore --encrypt \
  --algorithm aes \
  --mode cbc \
  --key 00112233445566778899aabbccddeeff \
  --input secret.txt \
  --output secret.cbc.bin

cryptocore --decrypt \
  --algorithm aes \
  --mode cbc \
  --key 00112233445566778899aabbccddeeff \
  --input secret.cbc.bin \
  --output secret.dec.txt
```

Для режимов с IV (CBC, CTR, OFB) при шифровании IV генерируется автоматически и сохраняется в начале файла.
#### GCM (аутентифицированное шифрование)
Шифрование с явным nonce и AAD

```
cryptocore --encrypt \
  --algorithm aes \
  --mode gcm \
  --key 00000000000000000000000000000000 \
  --iv 000000000000000000000000 \
  --aad "meta-data" \
  --input secret.txt \
  --output secret.gcm
```

`--iv` — 12‑байтовый nonce в hex (24 hex‑символа).

`--aad` — произвольная строка (в коде трактуется как байты UTF‑8, а не hex).

Формат файла GCM:
```text
nonce (12 байт) | ciphertext | tag (16 байт)
```
Дешифрование GCM
```
cryptocore --decrypt \
  --algorithm aes \
  --mode gcm \
  --key 00000000000000000000000000000000 \
  --aad "meta-data" \
  --input secret.gcm \
  --output secret.dec.txt
```

#### Хеш‑функции и HMAC (dgst)
`cryptocore dgst --algorithm <algo> --input <file> [доп. флаги]`

Поддерживаемые алгоритмы:
  * sha256
  * sha3-256
```
cryptocore dgst \
  --algorithm sha256 \
  --hmac \
  --key 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
  --input message.txt
```

#### Вывод ключей (derive, PBKDF2‑HMAC‑SHA256)
```
cryptocore derive \
  --password "PASSWORD" \
  [--salt SALT_HEX] \
  [--iterations COUNT] \
  [--length BYTES] \
  [--algorithm pbkdf2] \
  [--output FILE]
```
  * `--password` — строка (используется как пароль).
  * `--salt` — соль в hex. Если не указана — генерируется случайная 16‑байтовая соль.
  * `--iterations` — число итераций (по умолчанию: 100_000).
  * `--length` — длина ключа в байтах (по умолчанию: 32).
  * `--algorithm` — пока только pbkdf2.
  * `--output` — если указан, ключ записывается в файл как сырые байты, а не hex.

## Форматы аргументов
### Ключ (--key)
  * Hex‑строка длиной 32 символа (16 байт) для AES‑128.
  * Пример: 00112233445566778899aabbccddeeff.
### IV / nonce (--iv для GCM, IV для классических режимов)
  * Для GCM: 12‑байтовый nonce (24 hex‑символа).
    * Пример: 000000000000000000000000.
  * Для CBC/CTR/OFB: 16‑байтовый IV (32 hex‑символа), если указывается вручную.
    * Обычно IV генерируется и сохраняется автоматически.
### AAD (--aad)
  * Любая строка; в коде трактуется как байты UTF‑8.
  * Используется для GCM (и при желании в других схемах).
### Вывод dgst
  * По умолчанию: hex‑строка хеша/HMAC в stdout.
  * При --output FILE: hex записывается в файл.
### Вывод derive
  * Всегда: KEY_HEX SALT_HEX в одну строку.
  * При --output FILE: дополнительно сырые байты ключа в файл.

## Тестирование
Покрытие:
  * AES‑режимы (ECB/CBC/CTR/OFB) — roundtrip‑тесты с разными длинами данных.
  * GCM — roundtrip, неверный AAD, tampering nonce/ciphertext/tag, нулевые вектора (NIST‑подобный тест).
  * SHA‑256 / SHA3‑256 — официальные тестовые вектора + тест лавинного эффекта.
  * PBKDF2‑HMAC‑SHA256 — различные длины, итерации, разные пароли/соли.
  * Keygen/Key hierarchy (derive_key) — детерминизм и разделение контекстов.
  * CSPRNG (generator) — дубликаты, гамминговый вес, генерация большого файла.
  * Валидатор CLI‑параметров (validate) — корректные и ошибочные сценарии.

**Полный прогон (CLI + интеграция + производительность)**
```
# Windows PowerShell
.\scripts\test.ps1
```
## Структура проекта
```
src/
  lib.rs                 # библиотечный корень (модули CryptoMal)
  main.rs                # CLI-приложение (cryptocore)

  cryptor/               # AES и режимы (ECB/CBC/CTR/OFB), файл I/O
  gcm.rs                 # Реализация AES-GCM
  hash/                  # SHA-256, SHA3-256, общий Hasher
  mac/
    hmac.rs              # HMAC-SHA256 поверх hash-модуля
  kdf/
    pbkdf2.rs            # PBKDF2-HMAC-SHA256 (с нуля, RFC 2898/6070)
    hkdf.rs              # Иерархическое выведение ключей (HMAC-базированное)
  generator.rs           # CSPRNG (генерация случайных байтов)
  key_manager/
    keygen.rs            # Утилиты для генерации ключей через PBKDF2
    verifier.rs          # Верификация ключей через HMAC
  validate.rs            # Валидация CLI-параметров
  process_hollowing.rs   # (экспериментальные техники, если используются)
  herpaderping.rs        # (экспериментальные техники, если используются)

scripts/
  test.ps1               # Полный тестовый прогон для Windows PowerShell

Cargo.toml               # Конфигурация проекта (зависимости, версии)
README.md                # Этот файл
```

## Заметки по безопасности
  * Ключи, IV, nonce и соли генерируются с помощью криптографически стойкого ГПСЧ (rand::thread_rng).
  * SHA‑256 реализован вручную по стандарту NIST FIPS 180‑4 и проверен на официальных векторах.
  * HMAC‑SHA256 реализован по RFC 2104, проверен на RFC 4231.
  * PBKDF2‑HMAC‑SHA256 реализован по RFC 2898, проверен на RFC 6070.
  * GCM реализует формат nonce | ciphertext | tag и обеспечивает:
    * отказ при неверном теге/AAD,
    * отсутствие утечки открытого текста при ошибке.
  * ECB оставлен только для тестов и демонстрации — не используйте для реальных данных.
  * Пароли и ключи не логируются и не выводятся, кроме явного запроса (например, derive выводит ключ по определению).
