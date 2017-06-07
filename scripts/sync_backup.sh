#!/bin/env bash
# sync local backup files to company archive server
# 2016-07-31 i@hupo.me

DB_ID=(rm-bp140ari78gkdtigq)
DATA_DIR=/opt/db_backup/data

BINLOG_SERVER=bymdb_binlog
REMOTE_BINLOG_PATH=/backup/byxs/binlog
FULLBACLUP_SERVER=bymdb_fullbackup
REMOTE_FULLBACLUP_PATH=/backup/byxs/full_backup

LOG=${DATA_DIR}/log/sync-$(date '+%Y%m%dT%H%M%S').log

echo "# Init sync..." > $LOG


while [ -f "${DATA_DIR}/.lock" ]
do
    echo "# Found lock file waitting..."
    sleep 1m
done

for item in "${DB_ID[@]}"
do
    echo "# Starting sync db $item binlogs" >> $LOG
    scr_dir=${DATA_DIR}/${item}/binlog

    rsync -avz ${scr_dir}/ ${BINLOG_SERVER}:${REMOTE_BINLOG_PATH} >> $LOG
done


for item in "${DB_ID[@]}"
do
    echo "# Starting sync db $item fullbackups" >> $LOG
    scr_dir=${DATA_DIR}/${item}/fullbackup

    rsync -avz ${scr_dir}/ ${FULLBACLUP_SERVER}:${REMOTE_FULLBACLUP_PATH} >> $LOG
done

echo "# Sync all finish." >> $LOG
exit 0