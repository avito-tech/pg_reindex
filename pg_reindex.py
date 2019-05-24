#!/usr/bin/env python3
# author: @nvorobev

import os
import re
import sys
import time
import argparse
import getpass
import random
import datetime
import readline
import logging

import psycopg2
from psycopg2.extensions import quote_ident


def format_message(message, color=None):
    """
    Message output format
    """
    def red(msg):
        return "\033[91m{}\033[00m".format(msg)

    def green(msg):
        return "\033[92m{}\033[00m".format(msg)

    if not message:
        message = ''

    message = str(message).replace('\n', '')
    message = message.strip()

    if color == 'red':
        return red(message)
    elif color == 'green':
        return green(message)
    else:
        return message


def prompt(message, suffix=' '):
    """
    Returns the user input
    """
    prompt_text = "{}{}".format(message, suffix)

    input_value = input(prompt_text)

    if not input_value:
        input_value = ''
    else:
        input_value = re.sub(r'\s', '', input_value).lower()

    return input_value


def get_args(params):
    """
    Converting a list of arguments to a string, separated by commas
    """
    return ', '.join(map(lambda x: "'" + x + "'", params))


def get_database_tables(curs, schema=None, table=None, exclude_schema=None, exclude_table=None):
    """
    Getting a list of tables with indexes for further processing
    """
    extra_conditions = ''

    if schema:
        if len(schema) > 0:
            extra_conditions += " and schemaname in ({schema})\n".format(
                schema=get_args(schema)
            )

    if exclude_schema:
        if len(exclude_schema) > 0:
            extra_conditions += " and schemaname not in ({exclude_schema})\n".format(
                exclude_schema=get_args(exclude_schema)
            )

    if table:
        if len(table) > 0:
            extra_conditions = " and schemaname || '.' || tablename in ({table})\n".format(
                table=get_args(table)
            )

    if exclude_table:
        if len(exclude_table) > 0:
            extra_conditions += " and schemaname || '.' || tablename not in ({exclude_table})\n".format(
                exclude_table=get_args(exclude_table)
            )

    query = """
        select
            sq.schemaname,
            sq.tablename
        from (
            select 
                schemaname, 
                tablename,
                pg_indexes_size(quote_ident(schemaname)||'.'||quote_ident(tablename)) as indexes_size
            from pg_catalog.pg_tables
            where
                schemaname !~ 'pg_(temp|toast|catalog).*' and
                schemaname !~ '(information_schema|pg_catalog|kill|tmp|pgq|londiste|londiste_undo)' and
                tablename !~ '(pg_index|kill)'
                {extra_conditions}
        ) sq
        where
            sq.indexes_size > 0
        order by
            sq.schemaname,
            sq.tablename
    """.format(
        extra_conditions=extra_conditions
    )

    curs.execute(query)
    rows = curs.fetchall()

    return rows


def get_pgstattuple_schema_name(curs):
    """
    Getting the schema where the pgstattuple extension is installed
    """
    query = """
        select 
            n.nspname::text,
            e.extversion::numeric
        from pg_catalog.pg_extension e
        join pg_catalog.pg_namespace as n on 
            n.oid = e.extnamespace
        where 
            e.extname = 'pgstattuple'
    """

    curs.execute(query)

    try:
        r = curs.fetchone()
        return [r[0], r[1]]
    except:
        return [None, None]


def advisory_lock(curs, schemaname, tablename):
    """
    Table locking for protection against parallel processing
    """
    query = """
        select 
            pg_try_advisory_lock('pg_catalog.pg_class'::regclass::integer, 
            (quote_ident('{schemaname}') || '.' || quote_ident('{tablename}'))::regclass::integer
        )::boolean
    """.format(
        schemaname=schemaname,
        tablename=tablename
    )

    curs.execute(query)

    lock = curs.fetchone()[0]

    if lock:
        advisory_locks.append([schemaname, tablename])
    else:
        log.info('Skipping processing: another instance is working with table "{}.{}"'.format(schemaname, tablename))

    return lock


def advisory_unlock_all(curs):
    """
    Removing all installed locks from all tables
    """
    for lock in advisory_locks:
        (schemaname, tablename) = lock

        query = """
            select 
                pg_advisory_unlock('pg_catalog.pg_class'::regclass::integer, 
                (quote_ident('{schemaname}') || '.' || quote_ident('{tablename}'))::regclass::integer
            )::boolean
        """.format(
            schemaname=schemaname,
            tablename=tablename
        )

        curs.execute(query)


def get_index_data_list(curs, schemaname, tablename, indexname=None):
    """
    Getting indices with the necessary attributes from a given list of indexes or tables
    """
    extra_conditions = ''

    if indexname:
        if len(indexname) > 0:
            extra_conditions = " and schemaname || '.' || indexname in ({indexname})\n".format(
                indexname=get_args(indexname)
            )

    query = """
        select
            indexname, 
            tablespace, 
            indexdef,
            regexp_replace(indexdef, e'.* USING (\\\\w+) .*', e'\\\\1') as indmethod,
            conname,
            case
                when contype = 'p' then 'PRIMARY KEY'
                when contype = 'u' then 'UNIQUE'
                else null 
            end as contypedef,
            (
                select
                    bool_and(
                        deptype in ('n', 'a', 'i') and
                        not (refobjid = indexoid and deptype = 'n') and
                        not (
                            objid = indexoid and deptype = 'i' and
                            (version < array[9,1] or contype not in ('p', 'u'))))
                from pg_catalog.pg_depend
                left join pg_catalog.pg_constraint on
                    pg_catalog.pg_constraint.oid = refobjid
                where
                    (objid = indexoid and classid = pgclassid) or
                    (refobjid = indexoid and refclassid = pgclassid)
            )::integer as allowed,
            (
                select 
                    string_to_array(indkey::text, ' ')::int[] @> array[0::int]
                from pg_catalog.pg_index
                where indexrelid = indexoid
            )::integer as is_functional,
            condeferrable as is_deferrable,
            condeferred as is_deferred
        from (
            select
                indexname, tablespace, indexdef,
                (
                    quote_ident(schemaname) || '.' ||
                    quote_ident(indexname))::regclass as indexoid,
                'pg_catalog.pg_class'::regclass as pgclassid,
                string_to_array(
                    regexp_replace(
                        version(), e'.*PostgreSQL (\\\\d+\\\\.\\\\d+).*', e'\\\\1'),
                    '.')::integer[] as version
            from pg_catalog.pg_indexes
            where
                schemaname = quote_ident('{schemaname}') and
                tablename = quote_ident('{tablename}') and
                indexname !~ '^tmp_\\\\d+_\\\\d+'
                {extra_conditions}
        ) as sq
        left join pg_catalog.pg_constraint on
            conindid = indexoid and contype in ('p', 'u')
        order by
            indexname
    """.format(
        schemaname=schemaname,
        tablename=tablename,
        extra_conditions=extra_conditions
    )

    curs.execute(query)
    rows = curs.fetchall()

    return rows


def get_table_by_index(curs, indexname):
    """
    Getting the schema name and table by index
    """
    query = """
        select
            schemaname,
            tablename
        from pg_catalog.pg_indexes
        where
            schemaname || '.' || indexname = '{indexname}'
    """.format(
        indexname=indexname
    )

    curs.execute(query)

    return curs.fetchone()


def get_table_by_name(curs, tablename):
    """
    Getting the schema name and table from the table
    """
    query = """
        select
            schemaname,
            tablename
        from pg_catalog.pg_tables
        where
            schemaname || '.' || tablename = '{tablename}'
    """.format(
        tablename=tablename
    )

    curs.execute(query)

    return curs.fetchone()


def get_index_size_statistics(curs, schemaname, indexname):
    """
    Getting the size of the index and the number of pages
    """
    query = """
        select 
            size,
            ceil(size / bs) as page_count
        from (
            select
                pg_catalog.pg_relation_size((quote_ident('{schemaname}') || '.' || quote_ident('{indexname}'))::regclass) as size,
                current_setting('block_size')::real as bs
        ) as sq
    """.format(
        schemaname=schemaname,
        indexname=indexname
    )

    curs.execute(query)

    return curs.fetchone()


def get_index_bloat_stats(curs, pgstattuple, pgstattuple_ver, schemaname, indexname):
    """
    Getting bloat index statistics based on the pgstattuple extension
    """
    query = """
        select
            case
                when avg_leaf_density = 'NaN' then 0
                else
                    round(
                        (100 * (1 - avg_leaf_density / fillfactor))::numeric, 2
                    )
            end as free_percent,
            case
                when avg_leaf_density = 'NaN' then 0
                else
                    ceil(
                        index_size * (1 - avg_leaf_density / fillfactor)
                    )
            end as free_space
        from (
            select
                coalesce(
                    (
                        select (
                            regexp_matches(
                                reloptions::text, e'.*fillfactor=(\\\\d+).*'))[1]),
                    '90')::real as fillfactor,
                pgsi.*
            from pg_catalog.pg_class c
            join pg_catalog.pg_namespace n on 
                n.oid = c.relnamespace
            cross join {pgstattuple}.pgstatindex({object}) as pgsi
            where 
                c.oid = (quote_ident('{schemaname}') || '.' || quote_ident('{indexname}'))::regclass
        ) as oq
    """.format(
        pgstattuple=pgstattuple,
        object='c.oid' if pgstattuple_ver > 1 else "n.nspname || '.' || c.relname",
        schemaname=schemaname,
        indexname=indexname
    )

    curs.execute(query)

    return curs.fetchone()


def get_reindex_query(indexname, indexdef, tablespace, conname):
    """
    Getting a request to re-create an index
    """
    if args.change_index_name and not conname:
        tmp_name = indexname

        digits = re.findall(r'(_\d+)', tmp_name)
        if len(digits) > 0:
            last = digits[len(digits)-1]
            need_replace = tmp_name.index(last) + len(last) == len(tmp_name)
            if need_replace:
                for d in digits:
                    if len(d) > 2:
                        tmp_name = tmp_name.replace(d, '')

        ver_id_search = re.findall(r'_ver[0-9]+$', tmp_name)

        if ver_id_search:
            ver_id = ver_id_search[0][4:]
            new_ver_id = int(ver_id) + 1
            reindex_indexname = re.sub(r'_ver[0-9]+$', '_ver' + str(new_ver_id), tmp_name)
        else:
            reindex_indexname = tmp_name + '_ver1'
    else:
        reindex_indexname = '_tmp_' + indexname

    if len(reindex_indexname) > 63 or len(reindex_indexname) == 0:
        readline.parse_and_bind('tab: complete')
        while len(reindex_indexname) > 63 or len(reindex_indexname) == 0:
            if reindex_indexname.find('_tmp_') == 0:
                reindex_indexname = '_tmp_{}_{}'.format(int(time.time()), random.randint(1000000000, 9000000000))
            else:
                if len(reindex_indexname) > 63:
                    reindex_indexname = prompt(
                        "The name length for new index '{reindex_indexname}' exceeds 63 characters ({reindex_indexname_len}).\n"
                        "Please enter name for new index:".format(
                            reindex_indexname=reindex_indexname,
                            reindex_indexname_len=len(reindex_indexname)
                        ),
                        suffix='\n>>> '
                    )
                else:
                    reindex_indexname = prompt(
                        "The name for new index can not be empty!\n"
                        "Please enter name for new index:",
                        suffix='\n>>> '
                    )

    reindex_query = indexdef.replace('INDEX ' + indexname, 'INDEX CONCURRENTLY ' + reindex_indexname)

    if tablespace:
        reindex_query += ' TABLESPACE ' + tablespace

    reindex_query += ';'

    return [reindex_indexname, reindex_query]


def drop_temp_index(curs, schemaname, reindex_indexname):
    """
    Delete a new index created to replace the old one
    """
    drop_query = """
        DROP INDEX CONCURRENTLY {schemaname}.{reindex_indexname};
    """.format(
        schemaname=quote_ident(schemaname, curs),
        reindex_indexname=quote_ident(reindex_indexname, curs)
    )

    try:
        curs.execute(drop_query)
        log.info('Drop temporary index: "{}", done'.format(reindex_indexname))
    except Exception as e:
        log.error(format_message(message='Unable drop temporary index "{}", {}'.format(reindex_indexname, e), color='red'))


def drop_old_index(curs, drop_query):
    """
    Deleting an old index
    """
    drop_query = drop_query.strip()
    deleted = False

    try:
        if not args.dry_run:
            curs.execute(drop_query)
            deleted = True
        if not args.delete_index_after_create:
            log.info(drop_query)
    except Exception as e:
        log.error(format_message(message=e, color='red'))

    return deleted


def exist_table(curs, schemaname, tablename):
    """
    Checking the table availability in the database
    """
    query = """
        select 1 
        from pg_tables 
        where 
            schemaname = '{schemaname}' and 
            tablename = '{tablename}'
    """.format(
        schemaname=schemaname,
        tablename=tablename
    )

    curs.execute(query)

    return curs.rowcount == 1


def drop_old_index_later(curs, drop_query):
    """
    Saving a request to delete an old index to delete later
    """
    try:
        if not exist_table(curs, 'public', 'zdrop_index_later'):
            curs.execute("""
                create table if not exists public.zdrop_index_later
                (
                    drop_query text NOT NULL PRIMARY KEY,
                    create_time timestamp NOT NULL DEFAULT now()
                );
                comment on table public.zdrop_index_later
                is 'The table was created by the script pg_reindex.py, it stores information about old indexes that will be deleted.';
            """)
        curs.execute("""insert into zdrop_index_later (drop_query) values (%s)""", [str(drop_query.strip())])
    except Exception as e:
        log.error(format_message(message=e, color='red'))


def drop_old_indexes(curs):
    """
    Removing old indexes for which more than an hour ago created new indexes
    """
    query = """
        select
            format('DROP INDEX CONCURRENTLY %s.%s', quote_ident(n.nspname), quote_ident(c.relname)) as drop_query
        from pg_class c
        join pg_catalog.pg_namespace n on 
            n.oid = c.relnamespace
        join pg_index i on 
            i.indexrelid = c.oid
        where
            c.relkind = 'i' and
            (
                c.relname ~ '^_tmp_' or
                (
                    c.relname ~ '^tmp_\\\\d+_\\\\d+' and
                    now() - to_timestamp(substring(c.relname, 5, 10)::integer)::timestamp > '1 hour'::interval
                )
            )
        order by
            c.relname
    """

    curs.execute(query)
    rows = curs.fetchall()

    for row in rows:
        drop_old_index(curs, row[0])

    if exist_table(curs, 'public', 'zdrop_index_later'):

        query = """
            select
                drop_query
            from zdrop_index_later
            where
                now() - create_time > '1 hour'::interval
            order by
                create_time
        """

        curs.execute(query)
        rows = curs.fetchall()

        for row in rows:
            if drop_old_index(curs, row[0]):
                curs.execute("""delete from zdrop_index_later where drop_query = %s""", [str(row[0])])

        curs.execute("""select count(*) from zdrop_index_later""")
        row_count = curs.fetchone()[0]

        if row_count == 0:
            curs.execute("""drop table if exists zdrop_index_later""")


def index_is_valid(curs, schemaname, reindex_indexname):
    """
    Validating an index created with CONCURRENTLY
    """
    query = """
        select
            i.indisvalid
        from pg_class c
        join pg_index i on
            i.indexrelid = c.oid
        join pg_namespace ns on
            c.relnamespace = ns.oid
        where
            ns.nspname = '{schemaname}' and
            c.relname = '{reindex_indexname}' and
            c.relkind = 'i'
    """.format(
        schemaname=schemaname,
        reindex_indexname=reindex_indexname
    )

    isvalid = False
    try:
        curs.execute(query)
        isvalid = curs.fetchone()[0]
    except Exception as e:
        log.error(format_message(message='Could not check the validity of the index "{}", {}'.format(indexname, e), color='red'))

    if not isvalid:
        log.info('Index "{}" did not pass the validity check'.format(indexname))

    return isvalid


def get_alter_drop_index_query(schemaname, tablename, indexname, reindex_indexname, conname, contypedef, is_deferrable, is_deferred):
    """
    Getting a request to replace a new index if the index name is stored, and deleting the old one, if the deletion is not deferred
    """
    alter_query = None
    drop_query = None

    if conname:
        conname_options = contypedef + ' USING INDEX ' + indexname

        if is_deferrable:
            conname_options += ' DEFERRABLE'
        if is_deferred:
            conname_options += ' INITIALLY DEFERRED'

        alter_query = """
            BEGIN;
                SET LOCAL statement_timeout TO {statement_timeout};
                SET LOCAL deadlock_timeout TO {deadlock_timeout};
                ALTER TABLE {schemaname}.{tablename} DROP CONSTRAINT {conname};
                ALTER INDEX {schemaname}.{reindex_indexname} RENAME TO {indexname};
                ALTER TABLE {schemaname}.{tablename} ADD CONSTRAINT {conname} {conname_options};
            END;
        """.format(
            statement_timeout=args.statement_timeout,
            deadlock_timeout=args.deadlock_timeout,
            schemaname=schemaname,
            tablename=tablename,
            reindex_indexname=reindex_indexname,
            indexname=indexname,
            conname=conname,
            conname_options=conname_options
        )
    else:
        if args.change_index_name:
            drop_query = """
                DROP INDEX CONCURRENTLY {schemaname}.{indexname};
            """.format(
                schemaname=schemaname,
                indexname=indexname
            )
        else:
            tmp_index_name = 'tmp_{}_{}'.format(int(time.time()), random.randint(1000000000, 9000000000))

            alter_query = """
                BEGIN;
                    SET LOCAL statement_timeout TO {statement_timeout};
                    SET LOCAL deadlock_timeout TO {deadlock_timeout};
                    ALTER INDEX {schemaname}.{indexname} RENAME TO {tmp_index_name};
                    ALTER INDEX {schemaname}.{reindex_indexname} RENAME TO {indexname};
                END;
            """.format(
                statement_timeout=args.statement_timeout,
                deadlock_timeout=args.deadlock_timeout,
                schemaname=schemaname,
                indexname=indexname,
                reindex_indexname=reindex_indexname,
                tmp_index_name=tmp_index_name
            )

            drop_query = """
                DROP INDEX CONCURRENTLY {schemaname}.{tmp_index_name};
            """.format(
                schemaname=schemaname,
                tmp_index_name=tmp_index_name
            )

    return [alter_query, drop_query]


def print_queries(reindex_query=None, alter_query=None, drop_query=None):
    """
    Displays requests for reindexing, etc.
    """
    if reindex_query is not None or alter_query is not None or drop_query is not None:
        formatter = logging.Formatter(fmt='%(message)s')
        handler.setFormatter(formatter)
        screen_handler.setFormatter(formatter)
        log.addHandler(handler)
        log.addHandler(screen_handler)

        log.info('')

        for sql in [reindex_query, alter_query, drop_query]:
            tab = False
            if sql:
                queries = sql.split(';')
                for query in queries:
                    query = query.strip()
                    if query:
                        if not args.delete_index_after_create and query.count('DROP ') > 0:
                            continue
                        if (query + ';').count('END;') > 0:
                            tab = False
                        query = '   ' + query + ';' if tab else query + ';'
                        log.info(query)
                        if query.count('BEGIN;') > 0:
                            tab = True

        log.info('')

        formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        screen_handler.setFormatter(formatter)
        log.addHandler(handler)
        log.addHandler(screen_handler)


def size_pretty(curs, size):
    """
    Convert size to readable view
    """
    curs.execute('select pg_size_pretty(%s::numeric)', [size])

    return curs.fetchone()[0]


if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('--host', type=str, action="store", default='localhost',
                        help='A database host. By default localhost.')
    parser.add_argument('--port', type=int, action="store", default=5432,
                        help='A database port. By default 5432.')
    parser.add_argument('--user', type=str, action="store", default=os.getenv('PGUSER', getpass.getuser()),
                        help='A database user. By default current system user.')
    parser.add_argument('--password', type=str, action="store", default=os.getenv('PGPASSWORD'),
                        help='A password for the user.')
    parser.add_argument('--dbname', type=str, action="store",
                        help='A database to process. By default all the user databses of the instance are processed.')
    parser.add_argument('--schema', type=str, nargs='*', action="append", default=[],
                        help='A schema to process. By default all the schemas of the specified database are processed.')
    parser.add_argument('--exclude-schema', type=str, nargs='*', action="append", default=[],
                        help='A schema to exclude from processing.')
    parser.add_argument('--table', type=str, nargs='*', action="append", default=[],
                        help='A table to process. By default all the tables of the specified schema are processed.')
    parser.add_argument('--exclude-table', type=str, nargs='*', action="append", default=[],
                        help='A table to exclude from processing.')
    parser.add_argument('--index', type=str, nargs='*', action="append", default=[],
                        help='A index to process. By default all the indexes of the specified tables are processed.')
    parser.add_argument('--dry-run', action='store_true', default=False,
                        help='Print statistics only, without affecting any data.')
    parser.add_argument('--print-queries', action='store_true', default=False,
                        help='Print reindex and drop queries. Useful if you want to perform manual reindex or drop later.')
    parser.add_argument('--force', action='store_true', default=False,
                        help='Try to compact indexes that do not meet minimal bloat requirements.')
    parser.add_argument('--delete-index-after-create', action='store_true', default=False,
                        help='Delete old indexes after creating new ones.')
    parser.add_argument('--delete-old-indexes', action='store_true', default=False,
                        help='Delete all old unused indexes from the previous script start, which was not earlier than one hour ago.')
    parser.add_argument('--pgstattuple-install', action='store_true', default=False,
                        help='Installing the pgstattuple extension.')
    parser.add_argument('--change-index-name', action='store_true', default=False,
                        help='Create indexes with the new version in the name, without alter the index and locking.')
    parser.add_argument('--minimal-compact-percent', type=int, action="store", default=20,
                        help='Minimal compact percent. By default 20.')
    parser.add_argument('--reindex-retry-max-count', type=int, action="store", default=10,
                        help='Reindex retry max count. By default 10.')
    parser.add_argument('--statement-timeout', type=int, action="store", default=100,
                        help='Postgres statement timeout, ms. By default 100.')
    parser.add_argument('--deadlock-timeout', type=int, action="store", default=10,
                        help='Postgres deadlock timeout, ms. By default 10.')
    parser.add_argument('--log-level', choices=['DEBUG', 'INFO', 'ERROR'], default='INFO',
                        help='A log level. By default INFO.')
    args = parser.parse_args()

    args.schema = [el for elements in args.schema for el in elements]
    args.exclude_schema = [el for elements in args.exclude_schema for el in elements]
    args.table = ['public.' + el if el.count('.') == 0 else el for elements in args.table for el in elements]
    args.exclude_table = [el for elements in args.exclude_table for el in elements]
    args.index = ['public.' + el if el.count('.') == 0 else el for elements in args.index for el in elements]

    LEVELS = {'DEBUG': logging.DEBUG, 'INFO': logging.INFO, 'ERROR': logging.ERROR}

    level = LEVELS.get(args.log_level, logging.INFO)

    log_file = 'pg_reindex_{}_{}_{}.log'.format(args.host, args.dbname, int(time.time()))

    formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

    handler = logging.FileHandler(log_file, mode='w')
    handler.setFormatter(formatter)

    screen_handler = logging.StreamHandler(stream=sys.stdout)
    screen_handler.setFormatter(formatter)

    log = logging.getLogger(__name__)
    log.setLevel(level)
    log.addHandler(handler)
    log.addHandler(screen_handler)

    try:
        conn = psycopg2.connect(
            'host={host} port={port} dbname={dbname} {user} {password}'.format(
                host=args.host,
                port=args.port,
                dbname=args.dbname,
                user=(' user=' + args.user if args.user else ''),
                password=(' password=' + args.password if args.password else '')
            )
        )
    except psycopg2.OperationalError as e:
        log.error(format_message(message='No connect to server', color='red'))
        sys.exit(1)
    conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
    curs = conn.cursor()

    if args.delete_old_indexes:
        drop_old_indexes(curs)
        sys.exit(0)

    log.info('Process started, host: {}, dbname: {}'.format(args.host, args.dbname))

    free_space_total = 0
    free_space_total_plan = 0

    pgstattuple = None
    pgstattuple_ver = None

    advisory_locks = list()

    try:
        if len(args.index) > 0:
            for index in args.index:
                index_info = get_table_by_index(curs, index)
                if index_info is None:
                    log.error(format_message(message='Index "{}" not found'.format(index), color='red'))
                    sys.exit(0)
                (schemaname, tablename) = index_info
                if schemaname is not None and tablename is not None:
                    if args.schema.count(schemaname) == 0:
                        args.schema.append(schemaname)
                    if args.table.count(schemaname + '.' + tablename) == 0:
                        args.table.append(schemaname + '.' + tablename)
        elif not args.force:
            (pgstattuple, pgstattuple_ver) = get_pgstattuple_schema_name(curs)
            if pgstattuple is None:
                if args.pgstattuple_install:
                    curs.execute('create extension pgstattuple')
                    (pgstattuple, pgstattuple_ver) = get_pgstattuple_schema_name(curs)
                if pgstattuple is None:
                    log.error(format_message(message='Skip handling database {}: pgstattuple extension is not found'.format(args.dbname), color='red'))
                    sys.exit(0)

        if len(args.table) > 0:
            for table in args.table:
                table_info = get_table_by_name(curs, table)
                if table_info is None:
                    log.error(format_message(message='Table "{}" not found'.format(table), color='red'))
                    sys.exit(0)
                (schemaname, tablename) = table_info
                if schemaname is not None and tablename is not None:
                    if args.schema.count(schemaname) == 0:
                        args.schema.append(schemaname)
                    if args.table.count(schemaname + '.' + tablename) == 0:
                        args.table.append(schemaname + '.' + tablename)

        tables = get_database_tables(curs, args.schema, args.table, args.exclude_schema, args.exclude_table)

        if tables is None:
            log.error(format_message(message='No tables to process', color='red'))
            sys.exit(0)

        for table in tables:
            (schemaname, tablename) = table

            if not exist_table(curs, schemaname, tablename):
                log.info('Table "{}.{}" not found'.format(schemaname, tablename))
                continue

            if advisory_lock(curs, schemaname, tablename):
                indexes = get_index_data_list(curs, schemaname, tablename, args.index)

                if indexes is None:
                    continue

                for index in indexes:
                    (indexname, tablespace, indexdef, indmethod, conname, contypedef, allowed, is_functional, is_deferrable, is_deferred) = index

                    (size, page_count) = get_index_size_statistics(curs, schemaname, indexname)

                    if page_count <= 5:
                        log.info('Skipping reindex: "{}.{}", empty or 5 page index'.format(schemaname, indexname))
                        continue

                    if indmethod != 'btree':
                        log.info('Skipping reindex: "{}.{}" index is {} a not btree, reindexing is up to you'.format(schemaname, indexname, indmethod))
                        continue

                    if allowed != 1:
                        log.info('Skipping reindex: "{}.{}", can not reindex without heavy locks because of its dependencies, reindexing is up to you'.format(schemaname, indexname))
                        continue

                    if len(args.index) == 0 and not args.force:
                        (free_percent, free_space) = get_index_bloat_stats(curs, pgstattuple, pgstattuple_ver, schemaname, indexname)

                        if free_percent < args.minimal_compact_percent:
                            log.info('Skipping reindex: "%s.%s", %d%% space to compact from %d%% minimum required' % (schemaname, indexname, free_percent, args.minimal_compact_percent))
                            continue

                        free_space_total_plan += free_space

                        log.info('Bloat stats: "%s.%s" - free_percent %d%%, free_space %s' % (schemaname, indexname, free_percent, size_pretty(curs, free_space)))

                    (reindex_indexname, reindex_query) = get_reindex_query(indexname, indexdef, tablespace, conname)

                    (alter_query, drop_query) = get_alter_drop_index_query(quote_ident(schemaname, curs),
                                                                           quote_ident(tablename, curs),
                                                                           quote_ident(indexname, curs),
                                                                           quote_ident(reindex_indexname, curs),
                                                                           quote_ident(conname, curs) if conname else conname,
                                                                           contypedef, is_deferrable, is_deferred)

                    if args.print_queries:
                        print_queries(reindex_query, alter_query, drop_query)

                    if args.dry_run:
                        continue

                    reindex_time = datetime.datetime.now()

                    try:
                        queries = reindex_query.split(';')
                        for query in queries:
                            query = query.strip()
                            if query:
                                query += ';'
                                curs.execute(query)
                    except psycopg2.Error as e:
                        log.error(format_message(message='{}, {}'.format(e.pgcode, e.pgerror), color='red'))
                        drop_temp_index(curs, schemaname, reindex_indexname)
                        continue

                    if not index_is_valid(curs, schemaname, reindex_indexname):
                        drop_temp_index(curs, schemaname, reindex_indexname)
                        continue

                    if is_functional == 1:
                        try:
                            query = 'ANALYZE {}.{}'.format(schemaname, tablename)
                            curs.execute(query)
                            log.info('{} - done'.format(query))
                        except psycopg2.Error as e:
                            log.error(format_message(message='{}, {}'.format(e.pgcode, e.pgerror), color='red'))
                            drop_temp_index(curs, schemaname, reindex_indexname)
                            continue

                    locked_alter_attempt = 0

                    if alter_query is not None:
                        while locked_alter_attempt < args.reindex_retry_max_count:
                            try:
                                queries = alter_query.split(';')
                                for query in queries:
                                    query = query.strip()
                                    if query:
                                        query += ';'
                                        curs.execute(query)
                                break
                            except psycopg2.Error as e:
                                curs.execute('ROLLBACK;')
                                locked_alter_attempt += 1
                                if e.pgerror.find('canceling statement due to statement timeout') != -1:
                                    log.info('Reindex: "{}.{}", lock retry {}'.format(schemaname, indexname, locked_alter_attempt))
                                else:
                                    log.error(format_message(message='{}, {}'.format(e.pgcode, e.pgerror), color='red'))

                        if locked_alter_attempt >= args.reindex_retry_max_count:
                            log.info('Reindex: "{}.{}", unable lock, reindexing is up to you, queries:'.format(schemaname, indexname))
                            print_queries(alter_query=alter_query, drop_query=drop_query)
                            continue

                    reindex_time = (datetime.datetime.now() - reindex_time).total_seconds()

                    if args.change_index_name and not conname:
                        (new_size, new_page_count) = get_index_size_statistics(curs, schemaname, reindex_indexname)
                    else:
                        (new_size, new_page_count) = get_index_size_statistics(curs, schemaname, indexname)

                    free_percent = int(100 * (1 - float(new_size) / size))
                    free_space = size - new_size
                    free_space_total += free_space

                    if args.change_index_name and not conname:
                        message = 'Reindex: %s.%s, initial size %s pages (%s), has been reduced by %d%% (%s), duration %d seconds. New index name: %s' % (
                            schemaname, indexname, size_pretty(curs, size), page_count,
                            free_percent, size_pretty(curs, free_space), reindex_time, reindex_indexname
                        )
                        log.info(format_message(message=message, color='green'))
                    else:
                        message = 'Reindex: %s.%s, initial size %s pages (%s), has been reduced by %d%% (%s), duration %d seconds, attempts %d' % (
                            schemaname, indexname, size_pretty(curs, size), page_count,
                            free_percent, size_pretty(curs, free_space), reindex_time, locked_alter_attempt
                        )
                        log.info(format_message(message=message, color='green'))

                    if not conname:
                        if args.delete_index_after_create:
                            drop_old_index(curs, drop_query)
                        elif args.change_index_name:
                            drop_old_index_later(curs, drop_query)
    except Exception as e:
        log.error(format_message(message=e, color='red'))
    finally:
        if free_space_total_plan > 0 and args.dry_run:
            log.info(format_message(message='Total has been reduced by {}'.format(size_pretty(curs, free_space_total_plan)), color='green'))
        elif free_space_total > 0:
            log.info(format_message(message='Total has been reduced by {}'.format(size_pretty(curs, free_space_total)), color='green'))
        advisory_unlock_all(curs)
        log.info('Process completed, host: {}, dbname: {}'.format(args.host, args.dbname))
