ALTER TABLE "OidcClient" ADD COLUMN "accessPolicy" JSONB NOT NULL DEFAULT '{"restricted":false,"mappings":[]}'::jsonb;
