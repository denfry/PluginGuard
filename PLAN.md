# PluginGuard — план усиления анализа (Hardening Plan)

> Цель: поднять планку так, чтобы незаметно протащить backdoor/вирус в `.jar` стало
> очень тяжело — через эшелонированную защиту (defense-in-depth): глубокий статический
> движок + supply-chain проверки + динамический sandbox.

## Честная рамка (важно)

**Гарантировать «невозможно» нельзя.** Определить, вредоносна ли произвольная программа, —
алгоритмически неразрешимо (теорема Райса). Sandbox обходят dormant-кодом, проверкой на
песочницу и «бомбами замедленного действия». Поэтому формулировка цели — **не «доказать
безопасность», а «максимально поднять стоимость и заметность атаки»** и честно показывать
остаточный риск. Отчёт всегда сообщает риск, а не вердикт «безопасно».

---

## Текущее состояние (baseline)

Чисто статический анализатор: один ASM-проход на класс → таблица правил по опасным API,
IOC по строкам, обфускация, plugin.yml, best-effort SBOM. Тесты зелёные.

### Найденные дыры в текущем покрытии
1. **Вложенные JAR не анализируются** (`maxNestedJarDepth` задан, но не используется). ← дыра №1
2. **`invokedynamic` не перехватывается** (только `visitMethodInsn`).
3. **Нет декодирования** base64/hex/XOR-блобов и встроенных классов (`CAFEBABE`).
4. **Ресурсы не проверяются** на скрытые payload (полиглоты, классы под чужим расширением).
5. **Нет корреляции** — вызовы репортятся по отдельности, а сигнал малвари — это *комбинация*.
6. **Узкая таблица правил** — нет scripting/JNDI/RMI/десериализации/`setAccessible`/снятия SM.
7. **Нет CVE/репутации** и **нет sandbox**.

---

## Phase 1 — Глубокий статический движок (без инфраструктуры)

Максимум защиты на единицу усилий. Чистая Java, полностью покрыто тестами, без Docker/сети.

### 1.1 Рекурсивный анализ вложенных JAR
- `JarLoader`: рекурсивно распаковывать `.jar`-записи до `maxNestedJarDepth`, сохраняя путь-цепочку
  (напр. `bundled/lib.jar!/com/evil/X.class`).
- Классы вложенных JAR проходят весь пайплайн; findings атрибутируются полным путём.
- Защита от zip-bomb на каждом уровне (лимиты применяются суммарно).

### 1.2 Перехват `invokedynamic` и динамических констант
- `ClassScanner`: реализовать `visitInvokeDynamicInsn` (bootstrap-метод + аргументы).
- Спец-детект: `LambdaMetafactory`, `StringConcatFactory`, и indy на `MethodHandles`/reflection.
- Модель `Invocation` расширить типом (INVOKE* / INDY / reflective-resolved).

### 1.3 Декодирование и пере-сканирование (decode-and-rescan)
- Новый `PayloadDecoder`: находить base64/hex-блобы, декодировать; пробовать простой XOR (1–2 байта).
- Декодированное проверять на: магию `CAFEBABE` (встроенный класс) → **рекурсивно скормить ASM**;
  `PK\x03\x04` (встроенный zip/jar); URL/IOC/шелл-строки внутри декодированного.
- Лимиты на глубину и размер, чтобы не словить декомпресс-бомбу.

### 1.4 Детект скрытых payload и полиглотов
- Новый `EmbeddedPayloadAnalyzer`: сканировать **сырые байты всех записей** (не по расширению) на
  `CAFEBABE` (class), `PK\x03\x04` (zip), `MZ` (PE/.exe), `\x7fELF` (ELF) — ловит классы/jar/exe
  под видом `.png`, `.txt`, `.dat` и т.п.
- Энтропийный анализ ресурсов: высокая энтропия = вероятный зашифрованный payload.

### 1.5 Движок корреляции (combo-findings) — ключевой
- Новый `CorrelationAnalyzer` (запускается последним): поднимает HIGH/CRITICAL при опасных
  комбинациях категорий, например:
  - NETWORK + CLASS_LOADING → «загрузчик удалённого кода»
  - CRYPTO + CLASS_LOADING/большой base64 → «зашифрованный payload-loader»
  - REFLECTION + строки `Runtime`/`exec`/`ProcessBuilder` → «скрытый запуск процессов»
  - DESERIALIZATION + NETWORK → «десериализация недоверенных данных»
  - NATIVE/embedded-exe + PROCESS → «дроппер»
- Новая категория `COMBO`/`EXPLOIT` + новый `Severity` сигнал (поднятие вердикта).

### 1.6 Резолв reflection по строковым операндам
- Когда операнды `Class.forName(...)` / `getMethod(...)` — строковые константы рядом в методе,
  резолвить целевой класс/метод и применять к нему правила опасных API
  (ловит `Class.forName("java.lang.Runtime").getMethod("exec")`).

### 1.7 Сильно расширенная таблица правил `BytecodeAnalyzer`
Добавить (как минимум):
- **Scripting**: `javax.script.ScriptEngineManager`/`ScriptEngine`, Nashorn, Groovy
  (`GroovyShell`/`GroovyClassLoader`), BeanShell, Rhino, JRuby/Jython.
- **JNDI/RMI/LDAP** (класс Log4Shell): `javax.naming.InitialContext.lookup`, `Rmi*`, `ldap://`.
- **Десериализация**: `ObjectInputStream.readObject`, XStream, SnakeYAML небезопасный, Kryo.
- **Снятие защиты**: `AccessibleObject.setAccessible`, `Field.set*`, `System.setSecurityManager(null)`,
  `AccessController.doPrivileged`.
- **Процессы/среда**: `ProcessHandle`, `Runtime.addShutdownHook`, `System.getenv`,
  `System.setProperty`.
- **AWT/Desktop**: `java.awt.Robot` (кейлоггер/скриншоты), `Desktop.browse/open`, `Toolkit`,
  `Clipboard`.
- **JVM-внутренности**: расширить `sun.misc.Unsafe`/`jdk.internal.*`, `MethodHandles.Lookup` приватный доступ.
- **Сеть низкого уровня**: `DatagramSocket`, `MulticastSocket`, `InetAddress.getByName` (DNS-туннели),
  `java.net.http` POST на webhook.
- **Тайм-бомбы**: `Timer`/`ScheduledExecutorService`/`Thread.sleep` в связке с датами
  (`LocalDate`/`System.currentTimeMillis` сравнения) — эвристика отложенной активации.

### 1.8 Углублённый `plugin.yml`/manifest
- `Class-Path` в MANIFEST (внешние jar), `libraries:` тянущие из удалённого Maven, `load: STARTUP`,
  `loadbefore`, чрезмерные `depend`/`softdepend`.

### 1.9 Модель/скоринг/тесты
- Новые `Category` (`SCRIPTING`, `DESERIALIZATION`, `SUPPLY_CHAIN`, `COMBO`).
- `Finding` дополнить опц. полями: `nestedPath`, `tags`/`relatedRuleIds` для combo.
- `ScoreCalculator`: combo-findings бьют сильнее; вердикт-floor по CRITICAL combo.
- Синтетические JAR-кейсы (ASM) для каждого нового детектора + обновить web `types.ts`/UI.

---

## Phase 2 — Supply-chain и репутация (сеть разрешена, с кэшем и fallback)

### 2.1 CVE-проверка зависимостей (OSV.dev)
- Новый `OsvClient`: по обнаруженным `Dependency` (groupId:artifactId:version из `pom.properties`
  и имён вложенных jar) запрашивать https://api.osv.dev/v1/query.
- Локальный кэш на диске + TTL; при отсутствии сети — мягкая деградация (нота в отчёте).
- Findings уровня по CVSS; ссылки на advisory.

### 2.2 Репутация по SHA-256
- Сверка хеша всего jar и вложенных jar с пуллируемыми списками:
  known-malicious (флаг CRITICAL) / known-good (понижение шума).
- Источник: локальный файл/эндпоинт (конфигурируемо).

### 2.3 Конфиг/устойчивость
- Таймауты, ретраи, оффлайн-режим, выключатель сети флагом.
- Кэш в `pluginguard.cache.dir`.

---

## Phase 3 — Динамический sandbox (запуск в изоляции)

> Ловит то, что статикой не видно: reflection-построенные вызовы, расшифрованные payload,
> реальные сетевые/процессные/файловые действия. Честно документируем обходы.

### 3.1 Изолированный раннер
- Отдельный модуль/образ: Docker-контейнер, **non-root**, read-only FS + tmpfs, без capabilities,
  seccomp-профиль, лимиты CPU/RAM/времени (`--network none` либо контролируемый sink).
- Контролируемый egress: внутренний DNS/HTTP-приёмник, который **логирует все попытки**
  соединений вместо реального выхода в интернет.

### 3.2 Инструментация JVM
- Java-agent (ASM/ByteBuddy) + хуки, которые перехватывают и **логируют, но блокируют**:
  запуск процессов, сокеты/DNS, файловые операции, `defineClass`, reflection.
- Запись фактического поведения в структурированный лог.

### 3.3 Mock Paper/Bukkit-харнесс
- Заглушки Bukkit API; вызвать `onLoad`/`onEnable` плагина, чтобы его код реально отработал.
- Триггерить зарегистрированные команды/листенеры синтетическими событиями.

### 3.4 Интеграция в отчёт
- Раздел «Динамические findings»; кросс-проверка со статикой (совпало/новое/только статикой).
- Явные оговорки про sandbox-evasion, dormant-код, тайм-бомбы.

### 3.5 Оркестрация
- `POST /api/scan` запускает статику синхронно; sandbox — асинхронная джоба со статусом
  (`GET /api/scan/{id}` отдаёт частичный результат + статус sandbox).

---

## Порядок работ
1. Phase 1 (1.1 → 1.9) — фундамент, всё под тестами.
2. Phase 2 (2.1 → 2.3) — supply-chain поверх обнаруженных зависимостей.
3. Phase 3 (3.1 → 3.5) — sandbox последним, как отдельный изолированный модуль.

## Критерии готовности
- Новый синтетический malware-кейс на каждый детектор → ловится с ожидаемым `ruleId`.
- Benign-плагин не получает ложных CRITICAL (контроль ложноположительных).
- `./gradlew test` зелёный; web рендерит новые категории/поля.
- README обновлён: что детектится, и честные оговорки об остаточном риске.
