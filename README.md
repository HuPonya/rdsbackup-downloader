# rdsbackup-downloader
通过aria2将RDS备份文件下载到本地

### 使用
执行`python /this/a/app/path/rdsbackup-downloader/app/main.py`即可。rdsbackup-downloader会读取项目根目录（当前目录）下`app/conf/setting.json`。

### 配置
需要安装aria2。

实例配置[setting.json](app/conf/setting-sample.json)。
配置类别：

 - key_id，阿里云Access Key ID。
 - key_secret，阿里云Access Key Secret。
 - dbid, RDS实例ID。
 - data_dir，数据文件夹。
 - search_before_days, 搜索最早几天的备份文件。
 - fetch_fullbacup, 下载全量备份。
 - fetch_binlog, 下载增量备份。

### Docker化
[dockerfile](dockerfile)
运行命令参照systemd [service文件](scripts/rdsbackup.service)
