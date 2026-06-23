init-db:
	@docker compose exec api alembic upgrade head
