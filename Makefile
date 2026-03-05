.PHONY: up down build restart logs migrate makemigrations createsuperuser shell lint test test-backend test-frontend test-cli test-e2e fmt install install-frontend install-backend setup

# ── Setup initial (après un git pull) ────────────────────────────────────────

## Lance install-frontend + install-backend en une seule commande
install: install-frontend install-backend

## Installe les dépendances Node.js du frontend
install-frontend:
	cd frontend && npm install

## Installe les dépendances Python du backend via Poetry
install-backend:
	cd backend && poetry install

## Setup complet : install des dépendances + build Docker + migrations
setup: install build
	docker compose up -d
	docker compose exec backend python manage.py migrate
	@echo "SecureScan prêt sur http://localhost:3000"

# ── Docker ────────────────────────────────────────────────────────────────────

# Docker
up:
	docker compose up -d

down:
	docker compose down

build:
	docker compose build

restart:
	docker compose restart

logs:
	docker compose logs -f

# Django
migrate:
	docker compose exec backend python manage.py migrate

makemigrations:
	docker compose exec backend python manage.py makemigrations

createsuperuser:
	docker compose exec backend python manage.py createsuperuser

shell:
	docker compose exec backend python manage.py shell

# Quality
lint:
	docker compose exec backend ruff check .
	docker compose exec frontend pnpm lint

fmt:
	docker compose exec backend ruff format .

## Lance tous les tests (backend + frontend + CLI)
test: test-backend test-frontend test-cli

## Tests backend (pytest dans le conteneur Docker)
test-backend:
	docker compose exec backend poetry run pytest

## Tests frontend (vitest)
test-frontend:
	cd frontend && pnpm test:run

## Tests CLI (pytest local)
test-cli:
	cd cli && pytest

## Tests end-to-end (Playwright)
test-e2e:
	cd frontend && pnpm exec playwright test
