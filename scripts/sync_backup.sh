#!/bin/env bash
# sync local backup files to company archive server
# 2016-07-31

DB_ID=(rm-bp140ari78gkdtigq)
DATA_DIR=/opt/db_backup/data

BINLOG_SERVER=bymdb_binlog
REMOTE_BINLOG_PATH=/backup/byxs/binlog
FULLBACLUP_SERVER=bymdb_binlog
REMOTE_FULLBACLUP_PATH=/backup/byxs/full_backup

LOG=${DATA_DIR}/log/sync-$(date '+%Y%m%dT%H%M%S').log

echo "# Init sync..." > $LOG


for item in "${DB_ID[@]}"
do
    echo "# Starting sync db $item binlog" >> $LOG
    scr_dir=${DATA_DIR}/${item}/binlog

    while [ -f "${scr_dir}/.lock" ]
    do
        echo "# Found lock file waitting..."
        sleep 1m
    done

    rsync -avz ${scr_dir}/ ${BINLOG_SERVER}:${REMOTE_BINLOG_PATH} >> $LOG
done

echo "# Sync all finish." >> $LOG
exit 0