#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals
from builtins import str
from future import standard_library

import logging
import os
import requests
import base64
import sys
import time
import datetime
import hmac
import uuid
from hashlib import sha1
import json
import math
import hashlib
import argparse
from subprocess import Popen, PIPE

standard_library.install_aliases()

if sys.version_info[0] == 2:
    requests.packages.urllib3.contrib.pyopenssl.inject_into_urllib3()
    from urllib import quote
    from urllib import urlencode
else:
    from urllib.parse import quote
    from urllib.parse import urlencode


try:
    config = json.loads(open('conf/setting.json').read())
    ACCESS_KEY_ID = config['key_id']
    ACCESS_KEY_SECRET = config['key_secret']
    DBINSTANCEID = config['dbid']
    SEARCH_BEFORE_DAYS = config['search_before_days']
    FETCH_TYPE = config['fetch_type']
    FETCH_FULLBACUP = config['fetch_fullbacup']
    FETCH_BINLOG = config['fetch_binlog']
    DATA_DIR = config['data_dir']
    FULLBACUP_DIR = "%s/%s/fullbackup" % (DATA_DIR, DBINSTANCEID)
    BINLOG_DIR = "%s/%s/binlog" % (DATA_DIR, DBINSTANCEID)
    JOB_DIR = "%s/jobs" % DATA_DIR
    LOG_DIR = "%s/log" % DATA_DIR
    ARIA2_BIN = "aria2c" if config['aria2_bin'] == "" else config['aria2_bin']

except KeyError:
    print("Unable to locate Aliyun api credentials!")
    sys.exit(1)


if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
                    datefmt='%m-%d %H:%M',
                    filename='%s/%s.log' % (LOG_DIR,
                                            time.strftime("%Y-%m-%d")),
                    filemode='w')

console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter(
    '%(name)-12s: %(levelname)-8s %(message)s'))
logging.getLogger('').addHandler(console)


logger = logging.getLogger(__name__)


def _convert_size(size_bytes):
    if size_bytes == 0:
        return "0B"

    size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return "%s %s" % (s, size_name[i])


def _calculate_md5(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _gen_hook_args(args):
    s = ''
    binlogs = args['binlogs']
    full_backups = args['full_backups']
    for item in binlogs:
        filepath = "%s/%s/%s" % (BINLOG_DIR,
                                 item['instanceid'],
                                 item['filename'])
        s = "%s\n%s" % (s, filepath)
    for item in full_backups:
        filepath = "%s/%s" % (FULLBACUP_DIR, item['filename'])
        s = "%s\n%s" % (s, filepath)

    s = "%s\n" % (s)
    return s


# for ali api signature
def _percent_encode(txt):
    res = quote(str(txt))
    res = res.replace('+', '%20')
    res = res.replace('*', '%2A')
    res = res.replace('%7E', '~')
    return res


def _compute_signature(parameters, access_key_secret):
    sortedParameters = sorted(
        parameters.items(), key=lambda parameters: parameters[0])

    canonicalizedQueryString = ''
    for (k, v) in sortedParameters:
        canonicalizedQueryString += '&' + \
            _percent_encode(k) + '=' + _percent_encode(v)

    stringToSign = 'GET&%2F&' + _percent_encode(canonicalizedQueryString[1:])
    bs = access_key_secret + "&"

    h = hmac.new(
        key=bytearray(bs, 'utf-8'),
        msg=bytearray(stringToSign, 'utf-8'),
        digestmod=sha1
    )
    signature = base64.encodestring(h.digest()).strip()
    return signature


def _compose_url(params):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    parameters = {
        'Format': 'JSON',
        'Version': '2014-08-15',
        'AccessKeyId': ACCESS_KEY_ID,
        'SignatureVersion': '1.0',
        'SignatureMethod': 'HMAC-SHA1',
        'SignatureNonce': str(uuid.uuid1()),
        'Timestamp': timestamp,
    }

    for key in params.keys():
        parameters[key] = params[key]

    signature = _compute_signature(parameters, ACCESS_KEY_SECRET)
    parameters['Signature'] = signature

    url = "https://rds.aliyuncs.com/?" + urlencode(parameters)

    return url


def _make_request(params):
    url = _compose_url(params)

    r = requests.get(url)

    try:
        r.raise_for_status()
        obj = r.json()
        return obj
    except requests.exceptions.HTTPError as e:
        logger.error("Getting backup list error, aliapi response: %s", r.text)
        raise SystemExit(e)
    except ValueError as e:
        raise SystemExit(e)


def _add_lockfile(path):
    # TODO: check lockfile if file already exist script should throw error
    if not os.path.exists(path):
        os.makedirs(path)
    lockfile = "%s/.lock" % path
    with open(lockfile, 'a'):
        os.utime(lockfile, None)


def _remove_lockfile(path):
    os.remove("%s/.lock" % path)


def get_download_info():
    # FUCK YOU ALIYUN
    # api DescribeBackups time format yyyy-MM-dd’T’HH:mmZ
    # api DescribeBinlogFiles time format yyyy-MM-dd’T’HH:mm:ssZ
    befroe_day = 86400 * datetime.timedelta(days=SEARCH_BEFORE_DAYS).days
    starttime = time.strftime("%Y-%m-%dT%H:%M", time.gmtime(
        time.time() - befroe_day))
    now = time.time() - datetime.timedelta(seconds=1).seconds
    endtime = time.strftime("%Y-%m-%dT%H:%M",
                            time.gmtime(now))
    full_backups = []
    binlogs = []

    if FETCH_FULLBACUP:
        logger.info("# Fetch fullbackup files list")
        payload = {
            'Action': 'DescribeBackups',
            'DBInstanceId': DBINSTANCEID,
            'StartTime': "%sZ" % starttime,
            'EndTime': "%sZ" % endtime
        }

        resp = _make_request(payload)
        logger.debug("Getting fullbackup list aliapi response:\n%s", resp)

        try:
            items = resp['Items']['Backup']
            for item in items:
                name = item['BackupDownloadURL'].split('/')[-1].split('?')[0]
                if FETCH_TYPE == 'difference':
                    filepath = "%s/%s" % (FULLBACUP_DIR, name)
                    if os.path.exists(filepath):
                        l_size = os.stat(filepath).st_size
                        r_size = item['BackupSize']
                        if _convert_size(l_size) == _convert_size(r_size):
                            continue

                full_backups.append({'filename': name,
                                     'url': item['BackupDownloadURL'],
                                     'checksum': None})
        except KeyError:
            logger.error("Can't parse fullbackup list")

    if FETCH_BINLOG:
        logger.info("# Fetch binglog files list")
        payload = {
            'Action': 'DescribeBinlogFiles',
            'DBInstanceId': DBINSTANCEID,
            'StartTime': "%s:00Z" % starttime,
            'EndTime': "%s:00Z" % endtime
        }

        resp = _make_request(payload)
        logger.debug("getting binlog list aliapi response:\n%s", resp)

        try:
            items = resp['Items']['BinLogFile']
            for item in items:
                name = item['DownloadLink'].split('/')[-1].split('?')[0]
                if FETCH_TYPE == 'difference':
                    filepath = "%s/%s/%s" % (BINLOG_DIR,
                                             item['HostInstanceID'],
                                             name)
                    if os.path.exists(filepath):
                        l_md5 = _calculate_md5(filepath)
                        r_md5 = item['Checksum']
                        if l_md5 == r_md5:
                            continue

                binlogs.append({'filename': name,
                                'url': item['DownloadLink'],
                                'checksum': item['Checksum'],
                                'instanceid': item['HostInstanceID'],
                                'LogBeginTime': item['LogBeginTime'],
                                'LogEndTime': item['LogEndTime']})
        except KeyError:
            logger.error("Can't parse binlog list")

    return {'full_backups': full_backups, 'binlogs': binlogs}


def make_donwload_job(infos):
    logger.info("# Starting make download job file")
    if not os.path.exists(JOB_DIR):
        os.makedirs(JOB_DIR)

    jobfiles = {}
    now = time.strftime("%Y-%m-%d", time.gmtime())
    if FETCH_FULLBACUP:
        filename = "%s/full_%s.txt" % (JOB_DIR, now)
        with open(filename, 'w') as f:
            for item in infos['full_backups']:
                f.write(item['url'])
                f.write('\n')
                f.write('\n')
                f.write(" dir=%s\n" % FULLBACUP_DIR)
                f.write(" out=%s\n" % item['filename'])
                f.write(" file-allocation=falloc\n")
                f.write(" continue=true\n")
                f.write(" max-connection-per-server=10\n")
                f.write("  split=10\n\n")
        jobfiles['fucll_backup'] = filename

    if FETCH_BINLOG:
        filename = "%s/binlog_%s.txt" % (JOB_DIR, now)
        with open(filename, 'w') as f:
            for item in infos['binlogs']:
                f.write(item['url'])
                f.write('\n')
                f.write('\n')
                f.write(" dir=%s/%s\n" % (BINLOG_DIR, item['instanceid']))
                f.write(" out=%s\n" % item['filename'])
                f.write(" check-integrity=true\n")
                f.write(" checksum=md5=%s\n" % item['checksum'])
                f.write(" continue=true\n")
                f.write(" max-connection-per-server=10\n")
                f.write("  split=10\n\n")
            jobfiles['binglog'] = filename

    return jobfiles


def exec_download_job(job_files):
    if FETCH_FULLBACUP:
        job_file = job_files['fucll_backup']
        logger.info(
            "# Starting download fullbackup files, job file: %s", job_file)

        p = Popen('%s -i %s' % (ARIA2_BIN, job_file), shell=True, stdin=PIPE,
                  stdout=PIPE, close_fds=True, bufsize=1,
                  universal_newlines=True)
        output, err = p.communicate()
        if p.returncode == 0:
            logger.info("# Download fullbackup files success")
        else:
            logger.info("# Download fullbackup files error")

        logger.debug("aria2 return:\n%s", output)

    if FETCH_BINLOG:
        job_file = job_files['binglog']
        logger.info("# Starting download binlog files, job file: %s", job_file)

        p = Popen('%s -i %s' % (ARIA2_BIN, job_file),
                  shell=True, stdin=PIPE, stdout=PIPE,
                  close_fds=True, bufsize=1, universal_newlines=True)
        output, err = p.communicate()
        if p.returncode == 0:
            logger.info("# Download binlog files success")
        else:
            logger.info("# Download binlog files error")

        logger.debug("aria2 return:\n%s", output)


def main(args):
    _add_lockfile(DATA_DIR)
    logger.info("# Downloader starting...")
    info = get_download_info()
    job = make_donwload_job(info)
    exec_download_job(job)

    if args.hook:
        hook_args = _gen_hook_args(info)
        logger.debug("run hook args:\n%s", hook_args)
        p = Popen([args.hook, hook_args])
        p.wait()

    _remove_lockfile(DATA_DIR)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--hook', action="store",
                        help='hook script')
    args = parser.parse_args()
    main(args)
