FROM php:8.2-cli-alpine

# Install system dependencies
RUN apk add --no-cache git unzip

# Install Composer
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Copy composer files first for caching
COPY composer.json ./
RUN composer install --no-dev --optimize-autoloader --no-scripts 2>/dev/null || true

# Copy application code
COPY . .

# Install dependencies (with autoload)
RUN composer install --no-dev --optimize-autoloader

# The project to analyze is mounted at /repo (read-only)
VOLUME ["/repo"]

ENTRYPOINT ["php", "run.php"]
