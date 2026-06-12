# clustez-pipeline

Hourly cron that runs the Clustez news pipeline (ingest → enrich → analyze →
match → purge) on GitHub Actions. The pipeline code lives in the private
`Cluster` repo and is checked out transiently at run time; results are written
straight to Supabase. This repo is public so the workflow runs on unlimited
free Actions minutes — it contains no application code or secrets.
