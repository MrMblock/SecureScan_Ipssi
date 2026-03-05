# SecureScan

> Plateforme d'orchestration de sécurité de code — OWASP Top 10 2025 x DevSecOps
> Hackathon IPSSI 2026

SecureScan ne reinvente pas les outils d'analyse. Il les orchestre : il integre 7 analyseurs open source, agregge leurs resultats, les mappe sur le referentiel OWASP Top 10 2025, et propose des corrections automatiques via IA ou patterns deterministes.

---

## Fonctionnalites

### Analyse statique (SAST) et dependances (SCA)

| Outil | Type | Langages |
|---|---|---|
| Semgrep | SAST (patterns de code) | 30+ langages |
| Bandit | SAST (securite Python) | Python |
| ESLint Security | SAST (securite JS) | JavaScript, TypeScript |
| TruffleHog | Secrets (cles API, tokens) | Tous |
| npm audit | SCA (dependances) | Node.js |
| pip-audit | SCA (dependances) | Python |
| Composer Audit | SCA (dependances) | PHP |

Les analyseurs tournent en parallele via Celery chord. Chaque resultat JSON est parse, normalise, et mappe automatiquement sur une categorie OWASP.

### Analyse dynamique (DAST)

Scanner de sites web en live avec 7 modules :

- **Headers de securite** : CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Permissions-Policy, Referrer-Policy
- **CORS** : detection wildcard, reflection d'origin, credentials exposes
- **Directory bruteforce** : 55 chemins sensibles (.env, .git, /admin, /phpmyadmin, backups...)
- **XSS reflechi** : 5 payloads testes sur formulaires et parametres URL
- **SQL injection** : 7 payloads + detection de 17 patterns d'erreur SQL (MySQL, PostgreSQL, Oracle, SQLite, MSSQL)
- **Open redirect** : 17 noms de parametres testes (url, redirect, next, goto, callback...)
- **SSL/TLS** : analyse des protocoles et ciphers

### PWN Mon Site (pentest automatise)

Pipeline sequentiel complet pour tester un site web :

1. Recon et crawl (pages, formulaires, technologies)
2. Scan de ports (nmap top 1000)
3. Analyse SSL/TLS (sslyze)
4. Scan de vulnerabilites (nuclei)
5. Tests applicatifs (tous les modules DAST)
6. Agregation et scoring

Progression en temps reel via WebSocket avec fallback polling.

### Mapping OWASP Top 10 2025

Chaque vulnerabilite detectee est classee automatiquement selon le referentiel OWASP 2025 :

| Code | Categorie | Couverture |
|---|---|---|
| A01 | Broken Access Control | Path traversal, CSRF, CORS, SSRF, open redirect |
| A02 | Security Misconfiguration | Debug mode, headers manquants, config par defaut |
| A03 | Software Supply Chain Failures | npm audit, pip-audit, composer audit, malware |
| A04 | Cryptographic Failures | MD5/SHA1, hardcoded secrets, TruffleHog, SSL/TLS |
| A05 | Injection | SQLi, XSS, command injection, eval, template injection |
| A06 | Insecure Design | Rate limiting, race conditions, mass assignment |
| A07 | Authentication Failures | Hardcoded passwords, JWT, sessions, brute force |
| A08 | Software or Data Integrity Failures | Deserialization, prototype pollution |
| A09 | Security Logging & Alerting Failures | Log injection, missing logging |
| A10 | Mishandling of Exceptional Conditions | Error handling, fail-open |

Le mapping utilise des tables de correspondance par outil (Semgrep patterns, Bandit test IDs, ESLint rule IDs, keywords npm/pip) avec un systeme de confiance a 3 niveaux (high, medium, low).

### Score de securite

```
Score = max(0, 100 - somme des penalites)

Penalites par severite :
  critical = 15 pts | high = 8 pts | medium = 3 pts | low = 1 pt
```

Score de 100 = aucune vulnerabilite. Score de 0 = critique. Les faux positifs detectes automatiquement sont exclus du calcul.

### Corrections automatiques

**20 patterns deterministes** (sans API, instantanes) :

1. SQL injection -> requetes parametrees
2. XSS innerHTML -> textContent
3. document.write -> insertAdjacentHTML
4. eval() -> JSON.parse
5. exec() -> subprocess.run(shell=False)
6. os.system -> subprocess.run + shlex.split
7. Secrets hardcodes -> os.environ.get
8. MD5/SHA1 -> SHA-256
9. DEBUG=True -> False
10. CORS wildcard -> origine explicite
11. Cookies sans flags -> httponly + secure + samesite
12. pickle.loads -> json.loads
13. yaml.load -> yaml.safe_load
14. verify=False -> verify=True
15. mktemp -> mkstemp
16. shell=True -> shell=False
17. random -> secrets.token_hex
18. assert -> if/raise
19. chmod 777 -> 0o755
20. telnet/ftp -> SSH/SFTP

**Corrections IA** via les LLM (Gemini, Anthropic et OpenAI): le code vulnerable + le contexte du fichier sont envoyes au LLM qui retourne un JSON structure avec le code corrige et une explication.

### Git Push et Pull Request

Pour les repos GitHub, un utilisateur connecté via Github Oauth peut avoir accès à la feature suivante:
1. Creation d'une branche `fix/<titre>-<id>`
2. Application du patch sur les lignes exactes
3. Commit avec message structure (OWASP, severite, outil)
4. Push via token OAuth de l'utilisateur
5. Creation de la PR via GitHub API

### Rapport PDF/HTML

Rapport de securite professionnel genere via WeasyPrint :
- Resume du scan (score, duree, langages detectes)
- Vue d'ensemble OWASP (barres empilees par severite)
- Findings groupes par categorie OWASP avec recommandations
- Resume par outil d'analyse

### Dashboard

- 3 cartes de statistiques (total vulnerabilites, scans completes, score moyen)
- Graphique OWASP (stacked bar chart par severite)
- Graphique de severite (donut chart)
- Timeline des scores de securite
- Top 5 des fichiers les plus vulnerables
- Historique des scans avec filtres

### Detection de faux positifs

Detection automatique a l'agregation pour les patterns connus :
- setTimeout/setInterval avec fonction (pas une string) = safe
- console.log = rarement une vraie vulnerabilite
- innerHTML avec contenu statique = safe

### Internationalisation

Interface bilingue francais/anglais (470+ cles de traduction). Persistance du choix dans localStorage, switch dynamique.

---

## Stack technique

| Couche | Technologie |
|---|---|
| Backend | Django 5.x + Django REST Framework + Celery + Channels (WebSocket) |
| Frontend | Next.js 15 + React 19 + Tailwind CSS 4 + Recharts + Framer Motion |
| Base de donnees | PostgreSQL 16 |
| File d'attente | Redis 7 + Celery Beat |
| Infra | Docker Compose (7 services) + Nginx |
| IA | Google Gemini (auto-fix) |
| CI/CD | GitHub Actions (lint, tests, E2E Playwright, build Docker, deploy VPS) |
| CLI | Python + Typer + Rich |
| Extension | VSCode (TypeScript) |

---

## Architecture

```
                   ┌──────────────────────────────────────────────────────┐
                   │                     Nginx (80)                      │
                   │  reverse proxy + security headers (HSTS, XFO, etc) │
                   └───────┬─────────────────────────────┬──────────────┘
                           │                             │
                  ┌────────▼────────┐          ┌─────────▼─────────────┐
                  │  Next.js 15     │          │  Django + DRF (8000)  │
                  │  (frontend)     │          │  ├── /api/scanner/    │
                  │  SSR + SPA      │          │  └── /api/accounts/   │
                  └─────────────────┘          └─────────┬─────────────┘
                                                         │
                                                         │ Celery tasks
                                               ┌─────────▼──────────┐
                                               │   Redis 7 (broker) │
                                               └─────────┬──────────┘
                                                         │
                                               ┌─────────▼──────────────────┐
                                               │  Celery Workers            │
                                               │  ├── Semgrep               │
                                               │  ├── Bandit                │
                                               │  ├── TruffleHog            │
                                               │  ├── ESLint Security       │
                                               │  ├── npm audit             │
                                               │  ├── pip-audit             │
                                               │  ├── Composer Audit        │
                                               │  ├── DAST modules (7)      │
                                               │  └── PWN (nmap, nuclei...) │
                                               └────────────────────────────┘
```

**Pipeline de scan SAST/SCA :**

```
POST /api/scanner/scans/ (source_type=git)
  │
  ▼
orchestrate_scan (Celery)
  ├── 1. git clone --depth 1
  ├── 2. detect_languages()
  └── 3. Celery chord:
        group(semgrep, bandit, eslint, npm_audit, ...)
          │
          ▼
        aggregate_results (callback)
          ├── classify_finding() pour chaque resultat
          ├── is_false_positive() auto-detection
          └── compute score + CVSS max
```

---

## Prerequis

- Docker >= 24 et Docker Compose v2
- (Optionnel pour dev sans Docker) `semgrep`, `bandit`, `trufflehog`, `eslint`, `pip-audit` installes localement

---

## Demarrage rapide

```bash
# 1. Cloner le repo
git clone https://github.com/votre-groupe/securescan.git
cd securescan

# 2. Configurer l'environnement
cp .env.example .env
# Editer .env : remplir GITHUB_CLIENT_ID/SECRET pour les features IA et OAuth

# 3. Lancer les 7 services
docker compose up --build

# 4. Appliquer les migrations
docker compose exec backend python manage.py migrate

# 5. (Optionnel) Creer un superuser
docker compose exec backend python manage.py createsuperuser
```

L'application est accessible sur **http://localhost** (Nginx).

---

## Variables d'environnement

Voir [.env.example](.env.example) pour la liste complete.

| Variable | Obligatoire | Description |
|---|---|---|
| `DJANGO_SECRET_KEY` | Oui | Cle secrete Django (generer une cle aleatoire en prod) |
| `POSTGRES_DB/USER/PASSWORD` | Oui | Credentials PostgreSQL |
| `REDIS_URL` | Oui | URL Redis (defaut: `redis://redis:6379/0`) |
| `GEMINI_API_KEY` | Non | Cle API Gemini pour les corrections IA |
| `GITHUB_CLIENT_ID` | Non | OAuth GitHub (login social + creation de PR) |
| `GITHUB_CLIENT_SECRET` | Non | OAuth GitHub |
| `GOOGLE_CLIENT_ID` | Non | OAuth Google (login social) |
| `GOOGLE_CLIENT_SECRET` | Non | OAuth Google |
| `FIELD_ENCRYPTION_KEY` | Recommande | Cle Fernet pour chiffrer les tokens en DB |

---

## API Endpoints

### Scanner

| Methode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/scanner/scans/` | Creer un scan (git URL, ZIP, DAST, PWN) |
| `GET` | `/api/scanner/scans/` | Lister les scans de l'utilisateur |
| `GET` | `/api/scanner/scans/<id>/` | Detail d'un scan |
| `DELETE` | `/api/scanner/scans/<id>/` | Supprimer un scan |
| `GET` | `/api/scanner/scans/<id>/findings/` | Findings pagines (filtres: severity, tool, owasp, status) |
| `GET` | `/api/scanner/scans/<id>/owasp-chart/` | Distribution OWASP pour un scan |
| `GET` | `/api/scanner/scans/<id>/source/?path=` | Lire un fichier source du workspace |
| `GET` | `/api/scanner/scans/<id>/report/pdf/` | Telecharger le rapport PDF |
| `GET` | `/api/scanner/scans/<id>/report/html/` | Telecharger le rapport HTML |
| `GET` | `/api/scanner/scans/compare/?scan1=&scan2=` | Comparer deux scans |
| `POST` | `/api/scanner/findings/<id>/fix/` | Generer un fix IA |
| `POST` | `/api/scanner/findings/<id>/apply/` | Appliquer le fix + creer une PR |
| `PATCH` | `/api/scanner/findings/<id>/status/` | Changer le statut (open, false_positive, fixed) |
| `GET` | `/api/scanner/stats/` | Stats aggregees du dashboard |
| `GET` | `/api/scanner/owasp-chart/` | Distribution OWASP globale |
| `GET` | `/api/scanner/top-files/` | Top 5 fichiers vulnerables |

### Comptes

| Methode | Endpoint | Description |
|---|---|---|
| `POST` | `/api/accounts/signup/` | Inscription |
| `POST` | `/api/accounts/login/` | Connexion (JWT en httpOnly cookie) |
| `POST` | `/api/accounts/logout/` | Deconnexion |
| `GET/PATCH` | `/api/accounts/me/` | Profil utilisateur |
| `POST` | `/api/accounts/oauth/github/` | OAuth GitHub |
| `POST` | `/api/accounts/oauth/google/` | OAuth Google |
| `GET` | `/api/accounts/github/repos/` | Lister les repos GitHub |

---

## CLI

Un outil CLI standalone est disponible dans `cli/` :

```bash
cd cli
pip install -e .

# Scan local
securescan scan ./mon-projet

# Scan DAST
securescan scan https://example.com --dast

# Generer un fix
securescan fix 0

# Formats de sortie
securescan results --format json
securescan results --format sarif   # compatible GitHub Code Scanning
securescan results --format table
```

Commandes : `scan`, `results`, `fix`, `auth`, `config`. Mode interactif disponible sans arguments.

---

## Extension VSCode

Extension disponible dans `vscode-extension/` :

- Scan du workspace via ZIP + API backend
- Diagnostics inline dans l'editeur
- Hover avec details OWASP sur chaque finding
- Quick Fix actions (generer fix IA, appliquer, marquer faux positif)
- Sidebar dashboard avec score et liste des findings

```bash
cd vscode-extension
npm install && npm run compile
# Installer le .vsix dans VSCode
```

---

## Tests

```bash
# Backend (pytest)
docker compose exec backend poetry run pytest

# Frontend (vitest)
cd frontend && pnpm test:run

# E2E (Playwright)
cd frontend && pnpm exec playwright test

# CLI
cd cli && pytest
```

---

## CI/CD

Le pipeline GitHub Actions execute sur chaque PR et push :

1. **backend-lint** : ruff check
2. **frontend-lint** : next lint
3. **backend-test** : pytest (PostgreSQL + Redis en service)
4. **frontend-test** : vitest
5. **frontend-build** : next build
6. **e2e-test** : Playwright (chromium)
7. **docker-build** : docker compose build

Le CD deploie automatiquement sur VPS via SSH apres merge sur main.

---

## Repos de demo

Pour tester avec des vulnerabilites reelles :

```bash
# OWASP Juice Shop (Node.js — XSS, injection, secrets)
https://github.com/juice-shop/juice-shop.git

# DVWA Python
https://github.com/anxolerd/dvpwa.git

# WebGoat (Java)
https://github.com/WebGoat/WebGoat.git
```

Coller l'URL dans le dashboard > **New Scan** > observer les resultats.

---

## Securite du projet

Mesures de securite implementees dans le code :

- **Anti-SSRF** : validation DNS avec blocage des IP privees/reservees (IPv4 + IPv6) + re-validation au moment de l'execution (anti DNS rebinding)
- **Anti zip-slip / zip-bomb** : verification des chemins, taille, et nombre de fichiers avant extraction
- **Anti path traversal** : `os.path.realpath()` sur les lectures de fichiers source
- **Chiffrement des tokens** : Fernet (PBKDF2 key derivation) pour les tokens GitHub et cles API en base
- **JWT httpOnly** : tokens d'authentification en cookies httpOnly + Secure + SameSite=Lax
- **Rate limiting** : 100/min anon, 200/min user, 10/h creation de scan, 5/min auth
- **Headers Nginx** : HSTS, X-Frame-Options DENY, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- **Celery** : serialisation JSON uniquement (pas de pickle)
- **Git push** : token passe via GIT_ASKPASS (jamais ecrit dans .git/config)
- **Upload avatar** : validation extension + taille max + nom UUID

---

## Structure du projet

```
securescan/
├── backend/
│   ├── apps/
│   │   ├── accounts/          # Auth, OAuth, profil utilisateur
│   │   └── scanner/
│   │       ├── models.py      # Scan, Finding, ScanReport
│   │       ├── views.py       # Endpoints REST
│   │       ├── serializers.py
│   │       ├── services/
│   │       │   ├── owasp_mapper.py      # Mapping OWASP 2025 (A01-A10)
│   │       │   ├── autofix.py           # Corrections IA (Gemini)
│   │       │   ├── pattern_fixer.py     # 20 patterns deterministes
│   │       │   ├── apply_fix.py         # Git push + PR GitHub
│   │       │   ├── pdf_report.py        # Generation rapport PDF/HTML
│   │       │   ├── url_validator.py     # Anti-SSRF
│   │       │   ├── language_detector.py # Detection de langages
│   │       │   └── false_positive_detector.py
│   │       ├── tasks/
│   │       │   ├── orchestrator.py      # Pipeline SAST/SCA (Celery chord)
│   │       │   ├── analyzers.py         # 7 analyseurs (subprocess + JSON)
│   │       │   ├── dast_orchestrator.py # Pipeline DAST
│   │       │   ├── pwn_orchestrator.py  # Pipeline PWN complet
│   │       │   ├── dast/modules/        # 7 modules DAST
│   │       │   └── pwn/                 # nmap, sslyze, nuclei, fingerprint
│   │       ├── rules/
│   │       │   └── dom_security.yaml    # Regles Semgrep custom
│   │       └── templates/
│   │           └── scanner/report.html  # Template rapport PDF/HTML
│   └── config/
│       └── settings/          # base, development, production, test
├── frontend/
│   └── src/
│       ├── app/               # Pages Next.js (App Router)
│       │   ├── page.tsx               # Landing page
│       │   ├── login/ signup/         # Auth
│       │   └── (app)/
│       │       ├── dashboard/         # Dashboard principal
│       │       ├── scans/             # Liste + detail + findings
│       │       └── settings/          # Profil + cles API
│       ├── components/
│       │   ├── scanner/       # ScanProgressBar, FindingFixPanel, PwnForm
│       │   ├── landing/       # Hero, Stats, Features, FAQ, OWASP grid
│       │   ├── layout/        # Sidebar, Navbar
│       │   └── auth/          # SocialSignIn
│       ├── hooks/             # usePwnProgress, useScanStatus
│       ├── i18n/              # Locales FR/EN (470+ cles)
│       └── lib/api.ts         # Client Axios (intercepteur 401)
├── cli/
│   ├── securescan_cli/
│   │   ├── main.py            # Commandes Typer
│   │   ├── scan.py            # Logique de scan local
│   │   ├── fix.py             # Corrections (patterns + 3 providers IA)
│   │   ├── dast/              # 6 modules DAST
│   │   └── formatters/        # table, json, sarif
│   └── tests/                 # 12 fichiers, 1600+ lignes
├── vscode-extension/
│   └── src/
│       ├── extension.ts       # Activation
│       ├── commands.ts        # Scan, fix, navigation
│       ├── client.ts          # API client
│       ├── sidebarProvider.ts # Dashboard webview
│       ├── diagnostics.ts     # Inline markers
│       ├── hover.ts           # OWASP hover info
│       └── codeActions.ts     # Quick Fix menu
├── nginx/nginx.conf           # Reverse proxy + security headers
├── docker-compose.yml         # 7 services
├── docker-compose.prod.yml    # Production
├── .github/workflows/
│   ├── ci.yml                 # Lint, tests, build, E2E
│   └── cd.yml                 # Deploy VPS
└── .env.example
```

---

## Equipe

| Membre | Contribution principale |
|---|---|
| Gabriel Saint-Louis | Tech Lead, Architecture backend, orchestrateur, OWASP mapper, auto-fix, CLI |
| Sebastien Gerard | Frontend dashboard, landing page |
| Sanedoma Ndiaye | Docker, CI/CD, deploiement, SAST |
| Keziah Perfillon | Frontend, tests, Dossier Design |

---

*SecureScan — Hackathon IPSSI 2026 - OWASP x DevSecOps*
