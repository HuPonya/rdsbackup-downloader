#!/bin/env bash
# cp service file and conf to system
# 2016-07-31

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

#echo $DIR

cp -f $DIR/rdsbackup.service /etc/systemd/system/
cp -f $DIR/rdsbackup.timer /etc/systemd/system/

systemctl daemon-reload

exit 0