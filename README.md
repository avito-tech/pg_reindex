# PG Reindex
Reindexing PostgreSQL databases

### Usage

#### 1. Create new indexes with the new version in the name, without alter the index and locking on the table
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --change-index-name --print-queries
```
#### Delete all old unused indexes from the previous script start, which was not earlier than one hour ago
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --delete-old-indexes
```
#### 2. Create new indexes with preservation of old names, but with alter the index and locking on the table
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --statement-timeout 200 --deadlock-timeout 20 --print-queries
```
#### Delete all old unused indexes from the previous script start, which was not earlier than one hour ago
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --delete-old-indexes
```
#### 3. Create new indexes with the new version in the name, without alter the index and locking on the table and deleting old indexes after creating new ones
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --change-index-name --print-queries --delete-index-after-create
```
#### 4. Create new indexes with preservation of old names, but with alter the index and locking on the table and deleting old indexes after creating new ones
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --statement-timeout 200 --deadlock-timeout 20 --print-queries --delete-index-after-create
```
#### 5. Create a new primary key on a table with a table lock
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --statement-timeout 200 --deadlock-timeout 20 --print-queries --index base.items_pkey
```
#### 6. Create a new index with a table lock and delete the old index after creating a new one
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --statement-timeout 200 --deadlock-timeout 20 --print-queries --delete-index-after-create --index base.items_time_idx
```
#### 7. Create new indexes for the tables specified in the schema and deleting old indexes after creating new ones
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --statement-timeout 200 --deadlock-timeout 20 --print-queries --delete-index-after-create --schema base
```
#### 8. Print only statistics and queries, without affecting any data and without using the statistics of the bloat
```bash
./pg_reindex.py --host=localhost --dbname=base --user=postgres --print-queries --delete-index-after-create --force --dry-run
```

### Info

Optional arguments:
```
pg_reindex.py 
    [-h] [--host HOST] [--port PORT] [--user USER]
    [--password PASSWORD] [--dbname DBNAME]
    [--schema [SCHEMA [SCHEMA ...]]]
    [--exclude-schema [EXCLUDE_SCHEMA [EXCLUDE_SCHEMA ...]]]
    [--table [TABLE [TABLE ...]]]
    [--exclude-table [EXCLUDE_TABLE [EXCLUDE_TABLE ...]]]
    [--index [INDEX [INDEX ...]]] [--dry-run]
    [--print-queries] [--force] [--delete-index-after-create]
    [--delete-old-indexes] [--pgstattuple-install]
    [--change-index-name]
    [--minimal-compact-percent MINIMAL_COMPACT_PERCENT]
    [--reindex-retry-max-count REINDEX_RETRY_MAX_COUNT]
    [--statement-timeout STATEMENT_TIMEOUT]
    [--deadlock-timeout DEADLOCK_TIMEOUT]
    [--log-level {DEBUG,INFO,ERROR}]

  -h, --help            Show this help message and exit
  --host HOST           A database host. By default localhost.
  --port PORT           A database port. By default 5432.
  --user USER           A database user. By default current system user.
  --password PASSWORD   A password for the user.
  --dbname DBNAME       A database to process. By default all the user
                        databses of the instance are processed.
  --schema [SCHEMA [SCHEMA ...]]
                        A schema to process. By default all the schemas of the
                        specified database are processed.
  --exclude-schema [EXCLUDE_SCHEMA [EXCLUDE_SCHEMA ...]]
                        A schema to exclude from processing.
  --table [TABLE [TABLE ...]]
                        A table to process. By default all the tables of the
                        specified schema are processed.
  --exclude-table [EXCLUDE_TABLE [EXCLUDE_TABLE ...]]
                        A table to exclude from processing.
  --index [INDEX [INDEX ...]]
                        A index to process. By default all the indexes of the
                        specified tables are processed.
  --dry-run             Print statistics only, without affecting any data.
  --print-queries       Print reindex and drop queries. Useful if you want to
                        perform manual reindex or drop later.
  --force               Try to compact indexes that do not meet minimal bloat
                        requirements.
  --delete-index-after-create
                        Delete old indexes after creating new ones.
  --delete-old-indexes  Delete all old unused indexes from the previous script
                        start, which was not earlier than one hour ago.
  --pgstattuple-install
                        Installing the pgstattuple extension.
  --change-index-name   Create indexes with the new version in the name,
                        without alter the index and locking.
  --minimal-compact-percent MINIMAL_COMPACT_PERCENT
                        Minimal compact percent. By default 20.
  --reindex-retry-max-count REINDEX_RETRY_MAX_COUNT
                        Reindex retry max count. By default 10.
  --statement-timeout STATEMENT_TIMEOUT
                        Postgres statement timeout, ms. By default 100.
  --deadlock-timeout DEADLOCK_TIMEOUT
                        Postgres deadlock timeout, ms. By default 10.
  --log-level {DEBUG,INFO,ERROR}
                        A log level. By default INFO.
```

### Author

Nikolay Vorobev (nvorobev@avito.ru)

### License

MIT
