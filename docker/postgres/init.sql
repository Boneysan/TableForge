-- Initialize Vorpal Board PostgreSQL Database
-- This script creates the basic database structure for local development

-- Create database if it doesn't exist
CREATE DATABASE IF NOT EXISTS vorpal_board;

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Set timezone
SET timezone = 'UTC';

-- Basic indexes and configuration
-- The actual schema will be created by Drizzle migrations

-- Log initialization
DO $$
BEGIN
    RAISE NOTICE 'Vorpal Board database initialized successfully at %', NOW();
END $$;