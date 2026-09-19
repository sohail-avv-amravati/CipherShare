FROM php:8.2-apache

# Install SQLite dependencies and extensions
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    libzip-dev \
    zip \
    && docker-php-ext-install pdo pdo_sqlite zip \
    && rm -rf /var/lib/apt/lists/*

# Enable Apache rewrite module
RUN a2enmod rewrite

# Configure Apache document root to /public
ENV APACHE_DOCUMENT_ROOT /var/www/html/public
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf
RUN sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/apache2.conf /etc/apache2/conf-available/*.conf

# Copy project files
COPY . /var/www/html/

# Create storage and database directories, initialize schema, and set 777 permissions
RUN mkdir -p /var/www/html/storage/uploads /var/www/html/storage/encrypted /var/www/html/storage/temporary /var/www/html/database \
    && php /var/www/html/scripts/init_db.php \
    && php /var/www/html/scripts/init_owner.php \
    && chown -R www-data:www-data /var/www/html/storage /var/www/html/database \
    && chmod -R 777 /var/www/html/storage /var/www/html/database

EXPOSE 80
CMD ["apache2-foreground"]
