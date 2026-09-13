#!/bin/sh
### BEGIN INIT INFO
# Provides:          mailstack-web
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $network $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: MailStack Admin Console and Webmail
# Description:       MailStack management control plane and webmail client service
### END INIT INFO
case "$1" in
  start)
    @SETSID_PREFIX@su -s /bin/sh mailstack-admin -c "PORT=@ADMIN_PORT@ HOST=@ADMIN_HOST@ COOKIE_SECURE=@COOKIE_SECURE_VAL@ NODE_ENV=production @NODE_BIN@ /opt/mailstack/server.cjs >/var/log/mailstack-web.log 2>&1 &"
    @SETSID_PREFIX@su -s /bin/sh mailstack-webmail -c "WEBMAIL_PORT=@WEBMAIL_PORT@ WEBMAIL_HOST=@WEBMAIL_HOST@ WEBMAIL_PUBLIC_DIR=/opt/mailstack/webmail-public COOKIE_SECURE=@COOKIE_SECURE_VAL@ NODE_ENV=production @NODE_BIN@ /opt/mailstack/webmail.cjs >/var/log/mailstack-webmail.log 2>&1 &"
    ;;
  stop)
    pkill -f "@NODE_BIN@ /opt/mailstack/server.cjs" || true
    pkill -f "@NODE_BIN@ /opt/mailstack/webmail.cjs" || true
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  status)
    pgrep -f "@NODE_BIN@ /opt/mailstack/server.cjs" >/dev/null && echo "mailstack-web: running" || echo "mailstack-web: stopped"
    pgrep -f "@NODE_BIN@ /opt/mailstack/webmail.cjs" >/dev/null && echo "mailstack-webmail: running" || echo "mailstack-webmail: stopped"
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
  esac
