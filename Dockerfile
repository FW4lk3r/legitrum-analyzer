# Base images are pinned by digest so a moved tag cannot silently change the
# build. Update the digest deliberately when bumping versions.
FROM php:8.2-cli-alpine@sha256:69ac2133d7760c988beff12075215bf36a044d7d2439982f8304be0b6f1e3603

# Install system dependencies
RUN apk add --no-cache git unzip

# Install Composer (pinned by digest)
COPY --from=composer:2@sha256:7725eb4545c438629ae8bde3ef0bb9a5038ef566126ad878442a69007242d267 /usr/bin/composer /usr/bin/composer

WORKDIR /app

# Copy composer manifest AND lock first for caching. Both are required so the
# install resolves deterministically from the lock file instead of performing a
# fresh update. Do not mask install failures with '|| true' — a broken
# dependency resolution must fail the build.
COPY composer.json composer.lock ./
RUN composer install --no-dev --optimize-autoloader --no-scripts

# Copy application code. .dockerignore keeps secrets (.env*, secrets/, etc.)
# out of the build context so they are never baked into image layers.
COPY . .

# Install dependencies (with autoload)
RUN composer install --no-dev --optimize-autoloader

# Run as an unprivileged user instead of root.
RUN addgroup -S analyzer && adduser -S -G analyzer analyzer \
    && chown -R analyzer:analyzer /app
USER analyzer

# The project to analyze is mounted at /repo (read-only)
VOLUME ["/repo"]

ENTRYPOINT ["php", "run.php"]
