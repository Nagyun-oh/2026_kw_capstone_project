"""P6 읽기 전용 조회 목록. SQL 원문·요청 본문·계정·잠금 데이터는 반환하지 않는다."""
import re

TABLES=('network_logs','detected_threats','waf_detections','ip_blacklist',
        'request_alerts','request_correlations','waf_sync_status','ai_request_outbox')
GAUGES={'Threads_connected','Threads_running','Innodb_row_lock_current_waits','Max_used_connections'}
STATUS_NAMES=tuple(sorted(GAUGES | {'Uptime','Questions','Queries','Connections','Threads_created',
    'Created_tmp_tables','Created_tmp_disk_tables','Slow_queries','Select_scan','Sort_merge_passes',
    'Innodb_buffer_pool_reads','Innodb_buffer_pool_read_requests','Innodb_row_lock_waits',
    'Innodb_row_lock_time','Table_locks_waited','Com_commit','Com_rollback','Bytes_received','Bytes_sent',
    'Performance_schema_digest_lost'}))
DIGEST_COUNTERS=('count','timer_ps','lock_ps','rows_examined','rows_sent','rows_affected',
                 'no_index_used','tmp_disk_tables','errors')
FIELDS={
 'metadata':('server_hash','version','utc_at','session_at','session_timezone','global_timezone','performance_schema'),
 'status':('name','value'),
 'instrumentation':('digest_consumer','statement_consumer','enabled_statement_instruments','timed_statement_instruments'),
 'digests':('digest','verb','tables','observer_candidate','first_seen',*DIGEST_COUNTERS),
 'locks':('data_lock_waits','pending_metadata_locks'),
 'transactions':('active','lock_wait','oldest_ms','rows_locked','rows_modified'),
 'outbox':('state','count','max_attempts','ready_count','oldest_pending_ms','published_count',
           'publish_sum_us','publish_max_us','invalid_time_count'),
 'tables':('table','estimated_rows','data_bytes','index_bytes')}


def queries(run_id=None):
    if run_id is not None and (not isinstance(run_id,str) or not re.fullmatch(r'[A-Za-z0-9_+.-]{1,160}',run_id)):
        raise ValueError('DB 관측 run ID 형식 오류')
    table_names=','.join("'"+name+"'" for name in TABLES)
    statuses=','.join("'"+name+"'" for name in STATUS_NAMES)
    scope=''
    if run_id is not None:
        scope=" JOIN network_logs n ON n.id=o.log_id WHERE BINARY JSON_UNQUOTE(JSON_EXTRACT(IF(JSON_VALID(n.raw_log),n.raw_log,'{}'),'$.test_run'))=BINARY CONVERT(0x"+run_id.encode().hex()+" USING utf8mb4)"
    related=','.join("IF(LOCATE('"+t+"',LOWER(DIGEST_TEXT))>0,'"+t+"',NULL)" for t in TABLES)
    return {
 'metadata':"""SELECT JSON_OBJECT('server_hash',SHA2(@@server_uuid,256),'version',@@version,
 'utc_at',UTC_TIMESTAMP(6),'session_at',NOW(6),'session_timezone',@@session.time_zone,
 'global_timezone',@@global.time_zone,'performance_schema',@@performance_schema);""",
 'status':f"SELECT JSON_OBJECT('name',VARIABLE_NAME,'value',VARIABLE_VALUE) FROM performance_schema.global_status WHERE VARIABLE_NAME IN ({statuses}) ORDER BY VARIABLE_NAME;",
 'instrumentation':"""SELECT JSON_OBJECT(
 'digest_consumer',(SELECT ENABLED FROM performance_schema.setup_consumers WHERE NAME='statements_digest'),
 'statement_consumer',(SELECT ENABLED FROM performance_schema.setup_consumers WHERE NAME='events_statements_current'),
 'enabled_statement_instruments',(SELECT COUNT(*) FROM performance_schema.setup_instruments WHERE NAME LIKE 'statement/%' AND ENABLED='YES'),
 'timed_statement_instruments',(SELECT COUNT(*) FROM performance_schema.setup_instruments WHERE NAME LIKE 'statement/%' AND ENABLED='YES' AND TIMED='YES'));""",
 'digests':f"""SELECT JSON_OBJECT('digest',DIGEST,
 'verb',CASE WHEN DIGEST_TEXT LIKE 'SELECT%' THEN 'SELECT' WHEN DIGEST_TEXT LIKE 'INSERT%' THEN 'INSERT' WHEN DIGEST_TEXT LIKE 'UPDATE%' THEN 'UPDATE' WHEN DIGEST_TEXT LIKE 'DELETE%' THEN 'DELETE' ELSE 'OTHER' END,
 'tables',JSON_ARRAY({related}),
 'observer_candidate',IF(LOWER(DIGEST_TEXT) LIKE '%json_object%' OR LOWER(DIGEST_TEXT) LIKE '%performance_schema%' OR LOWER(DIGEST_TEXT) LIKE '%information_schema%',1,0),
 'first_seen',FIRST_SEEN,'count',COUNT_STAR,'timer_ps',SUM_TIMER_WAIT,'lock_ps',SUM_LOCK_TIME,
 'rows_examined',SUM_ROWS_EXAMINED,'rows_sent',SUM_ROWS_SENT,'rows_affected',SUM_ROWS_AFFECTED,
 'no_index_used',SUM_NO_INDEX_USED,'tmp_disk_tables',SUM_CREATED_TMP_DISK_TABLES,'errors',SUM_ERRORS)
 FROM performance_schema.events_statements_summary_by_digest
 WHERE SCHEMA_NAME='security_db' OR DIGEST IS NULL ORDER BY DIGEST LIMIT 2001;""",
 'locks':"""SELECT JSON_OBJECT('data_lock_waits',
 (SELECT COUNT(*) FROM performance_schema.data_lock_waits w JOIN performance_schema.data_locks l
 ON l.ENGINE=w.ENGINE AND l.ENGINE_LOCK_ID=w.REQUESTING_ENGINE_LOCK_ID WHERE l.OBJECT_SCHEMA='security_db'),
 'pending_metadata_locks',(SELECT COUNT(*) FROM performance_schema.metadata_locks WHERE OBJECT_SCHEMA='security_db' AND LOCK_STATUS='PENDING'));""",
 'transactions':"""SELECT JSON_OBJECT('active',COUNT(*),'lock_wait',COALESCE(SUM(TRX_STATE='LOCK WAIT'),0),
 'oldest_ms',MAX(TIMESTAMPDIFF(MICROSECOND,TRX_STARTED,NOW(6)))/1000,
 'rows_locked',COALESCE(SUM(TRX_ROWS_LOCKED),0),'rows_modified',COALESCE(SUM(TRX_ROWS_MODIFIED),0))
 FROM information_schema.INNODB_TRX WHERE TRX_MYSQL_THREAD_ID<>CONNECTION_ID();""",
 'outbox':f"""SELECT JSON_OBJECT('state',o.state,'count',COUNT(*),'max_attempts',MAX(o.attempts),
 'ready_count',SUM(o.state IN ('PENDING','IN_FLIGHT') AND o.available_at<=UTC_TIMESTAMP(6)),
 'oldest_pending_ms',MAX(IF(o.state IN ('PENDING','IN_FLIGHT'),TIMESTAMPDIFF(MICROSECOND,o.created_at,UTC_TIMESTAMP(6))/1000,NULL)),
 'published_count',SUM(o.published_at IS NOT NULL),
 'publish_sum_us',SUM(IF(o.published_at>=o.created_at,TIMESTAMPDIFF(MICROSECOND,o.created_at,o.published_at),NULL)),
 'publish_max_us',MAX(IF(o.published_at>=o.created_at,TIMESTAMPDIFF(MICROSECOND,o.created_at,o.published_at),NULL)),
 'invalid_time_count',SUM(o.created_at>UTC_TIMESTAMP(6) OR (o.published_at IS NOT NULL AND o.published_at<o.created_at)))
 FROM ai_request_outbox o {scope} GROUP BY o.state;""",
 'tables':f"SELECT JSON_OBJECT('table',TABLE_NAME,'estimated_rows',TABLE_ROWS,'data_bytes',DATA_LENGTH,'index_bytes',INDEX_LENGTH) FROM information_schema.TABLES WHERE TABLE_SCHEMA='security_db' AND TABLE_NAME IN ({table_names}) ORDER BY TABLE_NAME;"}
