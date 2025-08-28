# Progr3ss Backend

NestJS + PostgreSQL + Redis, Docker Compose-szal csomagolva. Ez a README végigvezet a futtatáson, a `docker-compose.yml`-en és az `.env` beállításokon.

---

## Gyors indítás

```bash
# 1) Klónozás
# git clone <repo-url>
# cd <repo>

# 2) .env létrehozása (példa lentebb)
cp .env.example .env  # vagy hozd létre kézzel

# 3) Futtatás
docker compose up -d --build

# 4) Logok nézése
docker compose logs -f backend

# 5) Leállítás
docker compose down
```

> **Megjegyzés**: Alapértelmezett HTTP port: **8080**. A backend konténeren belül **0.0.0.0:8080**-ra bindeljen (ez a repo kódjában már így van beállítva).

---

## Környezeti változók (`.env`)

Az alkalmazás a következő env változókat használja. **Fejlesztéshez** a lentebbi mintát használhatod; **élesben** feltétlenül cseréld le az értékeket erős, titkos értékekre.

> Tipp: az `.env` fájlt **ne** committold – tedd fel a `.gitignore`-ba.

### Kötelező / hasznos változók

```
# PostgreSQL
PG_HOST=db
PG_PORT=5432
PG_USERNAME=user
PG_PASSWORD=password
PG_DATABASE=dbname

# JWT/Token titkok (csak példaértékek – PROD-ban cseréld!)
AT_SECRET=pRogr3ss_at
RT_SECRET=pRogr3ss_rt
JWT_SECRET=nagyonTitkosProgr3ssKey!492?79.74

# Redis (Compose hálón a host a service neve: "redis")
REDIS_HOST=redis
REDIS_PORT=6379

# Google OAuth – opcionális (ha nincs, a kapcsolódó funkciók legyenek letiltva/no-op)
GOOGLE_ANDROID_CLIENT_ID=optional
GOOGLE_WEB_CLIENT_ID=optional
GOOGLE_WEB_CLIENT_SECRET_ID=optional
```

> **Biztonság**: ha a kód `DATABASE_URL`-t használ, adjuk át így a Compose-ban `?sslmode=disable`-lel, mert a lokális Postgres nem beszél SSL-t.

---

## `docker-compose.yml` felépítés

Az alábbi példa a backend + Postgres + Redis szolgáltatásokat indítja. A Compose **betölti** az `.env`-et és **át is adja** a szükséges változókat a konténereknek.

```yaml
services:
  backend:
    build:
      context: .
    # Apple Silicon / ARM esetén hasznos lehet:
    # platform: linux/arm64
    env_file:
      - ./.env
    environment:
      # Kényelmes egyben átadni az adatbázis URL-t (SSL off dev-ben)
      DATABASE_URL: postgres://${PG_USERNAME}:${PG_PASSWORD}@${PG_HOST}:${PG_PORT}/${PG_DATABASE}?sslmode=disable
      # Redis URL a modulokhoz (Bull/BullMQ stb.)
      REDIS_URL: redis://${REDIS_HOST}:${REDIS_PORT}
      PORT: 8080
    depends_on:
      db:
        condition: service_healthy
      redis:
        condition: service_healthy
    ports:
      - '8080:8080'

  db:
    image: postgres:17
    restart: always
    env_file:
      - ./.env
    environment:
      POSTGRES_USER: ${PG_USERNAME}
      POSTGRES_PASSWORD: ${PG_PASSWORD}
      POSTGRES_DB: ${PG_DATABASE}
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - '5432:5432'
    healthcheck:
      test:
        [
          'CMD-SHELL',
          'pg_isready -U ${PG_USERNAME} -d ${PG_DATABASE} -h 127.0.0.1',
        ]
      interval: 5s
      timeout: 3s
      retries: 10

  redis:
    image: redis:7-alpine
    restart: always
    # Ha a host gépről is csatlakoznál (redis-cli), tartsd meg a port kiexponálást.
    ports:
      - '6379:6379'
    healthcheck:
      test: ['CMD', 'redis-cli', 'ping']
      interval: 5s
      timeout: 3s
      retries: 10

volumes:
  pgdata:
```

### Mi történik itt?

- **`env_file: .env`** – a Compose betölti az `.env`-et.
- **Változó-helyettesítés** – a Compose a `${VAR}` formákat az `.env`-ből vagy a shell környezetből tölti ki.
- **`environment:`** – itt adjuk át a konténernek a tényleges runtime env-eket (pl. `DATABASE_URL`, `REDIS_URL`, `PORT`).
- **`depends_on.condition: service_healthy`** – a backend csak akkor indul, ha a DB/Redis már egészséges.

> **Redis host**: Compose hálón a szolgáltatások a **service nevekkel** érik el egymást. Ezért `REDIS_HOST=redis` (nem `localhost`).

---

## Parancsok és tippek

```bash
# Indítás
docker compose up -d --build

# Logok (összes vagy csak backend)
docker compose logs -f
docker compose logs -f backend

# Konténerek listája
docker compose ps

# Belépés a backend konténerbe
docker exec -it $(docker compose ps -q backend) sh

# Leállítás (volume-ok megtartásával)
docker compose down

# Mindennel együtt leállítás + volume törlés (DB adat is törlődik!)
docker compose down -v
```

---

## Hibaelhárítás

**1) `Error: The server does not support SSL connections` (Postgres)**

- A lokális Postgres nem használ SSL-t. Tedd a `DATABASE_URL` végére: `?sslmode=disable`, vagy add át a `PGSSLMODE=disable` env-et, illetve a TypeORM configban `ssl: false`.

**2) `ECONNREFUSED 127.0.0.1:6379` (Redis)**

- A `localhost` a konténeren belül **magát** jelenti. Használd: `REDIS_HOST=redis`, `REDIS_PORT=6379` és add át `REDIS_URL=redis://redis:6379`.

**3) ARM/AMD figyelmeztetés**

- Apple Silicon/ARM hoston add meg `platform: linux/arm64`, és használj multi-arch image-eket (`node:XX-alpine`, `postgres`, `redis`).

**4) Firebase credential hiányzik**

- Ha a projekt használ Firebase-t, állíts be **egyik** módszerrel:

  - `FIREBASE_CREDENTIALS_PATH=/path/in/container/creds.json` (mountold be a fájlt), **vagy**
  - `FIREBASE_CREDENTIALS_B64=<base64-elt JSON>`.

- Ha nincs beállítva, a `FirebaseService` no-op módban marad (nem dob hibát), de reset link/értesítés nem fog menni.

**5) .env betöltés vs. konténer env**

- A Compose a `${VAR}` formákat az `.env`-ből **helyettesíti**, de a konténerbe **csak** az `environment:` alatt, vagy `env_file:`-on keresztül kerülnek be változók. Ebben a példában **mindkettőt** használjuk: `env_file` beolvassa, `environment` pedig összerakja a `DATABASE_URL`/`REDIS_URL` értékeket.

---

## .gitignore javaslat

```
# Secrets
.env
*.env

# Docker volume/artefaktok
pgdata/

# Build output
/dist
/node_modules
```

---

## Hasznos ellenőrzések

```bash
# Compose config (feloldott változókkal):
docker compose config

# Konténerben elérhető env-ek ellenőrzése:
docker exec -it $(docker compose ps -q backend) sh -lc 'env | sort | egrep "PG_|REDIS|DATABASE_URL|PORT"'

# Hálózati elérés backendből:
docker exec -it $(docker compose ps -q backend) sh -lc 'apk add --no-cache busybox-extras >/dev/null 2>&1 || true; nc -zv db 5432; nc -zv redis 6379'
```

---

## Jegyzetek

- A mailküldés (Mailjet) és a Firebase integráció **opcionális**; ha a szükséges env-ek hiányoznak, a szolgáltatások no-op módban futnak, és az alkalmazás **nem** esik el.
- Éles környezetben állítsd be a titkos értékeket biztonságosan (secrets, vault), és **ne** tedd publikussá az `.env`-et.

---

## `.env.example`

Egy az egyben felhasználható fejlesztői példa (a tényleges `.env`-be másold át, igény szerint módosítsd):

```dotenv
PG_HOST=db
PG_PORT=5432
PG_USERNAME=user
PG_PASSWORD=password
PG_DATABASE=dbname

AT_SECRET=pRogr3ss_at
RT_SECRET=pRogr3ss_rt
JWT_SECRET=nagyonTitkosProgr3ssKey!492?79.74

REDIS_HOST=redis
REDIS_PORT=6379

GOOGLE_ANDROID_CLIENT_ID=optional
GOOGLE_WEB_CLIENT_ID=optional
GOOGLE_WEB_CLIENT_SECRET_ID=optional
```
