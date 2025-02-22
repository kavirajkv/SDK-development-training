commit:
	git add .
	@read -p "Enter commit message: " message; \
	git commit -m "$$message"
