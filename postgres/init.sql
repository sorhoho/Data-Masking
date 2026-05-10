-- Runs once on first volume creation.
-- Creates the admin-service database and its user.
CREATE DATABASE admindb;
CREATE USER adminuser WITH PASSWORD 'admin_pass';
GRANT ALL PRIVILEGES ON DATABASE admindb TO adminuser;
-- PostgreSQL 15+ restricts CREATE in the public schema by default.
-- Connect to admindb and grant schema-level privileges explicitly.
\connect admindb
GRANT ALL ON SCHEMA public TO adminuser;

-- midPoint IGA database
CREATE DATABASE midpoint;
CREATE USER midpoint WITH PASSWORD 'midpoint_pass';
GRANT ALL PRIVILEGES ON DATABASE midpoint TO midpoint;
\connect midpoint
GRANT ALL ON SCHEMA public TO midpoint;
