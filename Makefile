.PHONY: install run test lint docker-build docker-up clean

install:
	pip install -r requirements.txt
	pip install pytest ruff

run:
	streamlit run app.py

test:
	pytest tests/ -v

lint:
	ruff check src/ app.py tests/

docker-build:
	docker build -t phishing-analyzer .

docker-up:
	docker compose up --build

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
