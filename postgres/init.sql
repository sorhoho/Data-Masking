-- Runs once on first volume creation.
-- Creates the admin-service database and its user.
CREATE DATABASE admindb;
CREATE USER adminuser WITH PASSWORD 'admin_pass';
GRANT ALL PRIVILEGES ON DATABASE admindb TO adminuser;
