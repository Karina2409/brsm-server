# AGENTS.md — Руководство для контрибьютеров brsm-server

## Структура проекта

Монолитное Spring Boot 3.3 приложение (Java 17, Maven). База — PostgreSQL.

```
src/main/java/org/brsm_server/
├── auth/              # Аутентификация (JWT): контроллер, сервис, DTO запросов
├── controller/        # REST-контроллеры (Event, Exemption, Petition, Report, Student, User)
├── dto/               # DTO для передачи данных между слоями
├── entity/            # JPA-сущности (Student, Event, Report, Petition, Exemption, Document…)
│   └── enums/         # Перечисления: Faculty, RoleEnum, ActionType
├── exception/         # Кастомные исключения
├── help/              # Утилиты (DateFormat, ImageUtil, InputCheck, FacultyNumber)
├── mapper/            # MapStruct-мапперы (Entity ↔ DTO)
├── pdf/               # Генерация PDF (iText): шаблоны для ходатайств, освобождений, отчётов
├── repository/        # Spring Data JPA репозитории
├── security/          # Spring Security: фильтры, JWT-сервис, конфигурация, роли, токены
└── service/           # Интерфейсы сервисов
    └── impl/          # Реализации сервисов
src/main/resources/
└── application.yml    # Конфигурация приложения (БД, JWT, почта)
src/test/              # Тесты (JUnit 5, Mockito, Spring Security Test)
```

## Команды сборки и запуска

| Команда                  | Описание                                   |
|--------------------------|--------------------------------------------|
| `./mvnw clean package`   | Очистка + сборка JAR                       |
| `./mvnw test`            | Запуск тестов                              |
| `./mvnw spring-boot:run` | Локальный запуск приложения                |

Для работы требуется запущенный PostgreSQL (параметры подключения в `application.yml`).

## Стек технологий

- **Spring Boot 3.3.5** — Web, Data JPA, Security, AOP, Mail
- **JWT** (jjwt 0.12.5) — аутентификация/авторизация
- **MapStruct 1.5.5** — маппинг Entity ↔ DTO
- **Lombok** — генерация boilerplate-кода
- **iText 8.0.4** — генерация PDF-документов
- **Apache POI 5.2.3** — работа с Excel
- **Swagger / SpringDoc** — документация API

## Стиль кода и правила именования

- **Архитектурный паттерн:** Controller → Service (интерфейс) → ServiceImpl → Repository
- **Именование классов:** `PascalCase`. Суффиксы: `*Controller`, `*Service`, `*ServiceImpl`, `*Repository`, `*DTO`, `*Mapper`
- **Именование методов/переменных:** `camelCase`
- **Пакеты:** `org.brsm_server.<слой>` (controller, service, entity, dto, mapper, repository, security, pdf, help, exception, auth)
- **DTO:** отдельные классы в пакете `dto/`, маппинг через MapStruct
- **Entities:** аннотации JPA + Lombok (`@Data`, `@Entity`, `@Builder` и т.д.)
- **Контроллеры возвращают только DTO**, никогда — Entity напрямую. Маппинг Entity → DTO выполняется в сервисном слое через MapStruct
- **Исключения:** использовать кастомные классы из пакета `exception/` (`EntityExistsException`, `InvalidTokenException`, `PdfGenerationException`). Не бросать голые `RuntimeException` или `Exception` — при необходимости создать новый кастомный класс
- **Тесты:** JUnit 5 + Mockito. Тестовые классы — `*Tests.java` в `src/test/java/org/brsm_server/`

## Рекомендации по VCS

### Формат коммитов

Используется формат `<тип>: <описание>`:

- `feat:` — новая функциональность
- `fix:` — исправление бага
- `refactor:` — рефакторинг без изменения поведения
- `docs:` — документация
- `database:` — изменения схемы БД
- `init:` — начальная инициализация

Примеры:
```
feat: add users page
fix: fix cors
refactor: refactoring of user classes
```

### Pull Request

- Описание изменений на русском или английском языке
- Ссылка на связанную задачу (если есть)
