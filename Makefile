.PHONY: run build lint test

run:
	python main.py

build:
	pyinstaller --noconfirm --onefile --windowed main.py --add-data "ui/assets:ui/assets"

lint:
	ruff check .
	mypy .

test:
	pytest
