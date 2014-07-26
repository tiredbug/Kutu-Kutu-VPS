#!/bin/bash

function check_install {
    if [ -z "`which "$1" 2>/dev/null`" ]
    then
        executable=$1
        shift
        while [ -n "$1" ]
        do
            DEBIAN_FRONTEND=noninteractive apt-get -q -y install "$1"
            print_info "$1 installed for $executable"
            shift
        done
    else
        print_warn "$2 already installed"
    fi
}

function check_remove {
    if [ -n "`which "$1" 2>/dev/null`" ]
    then
        DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
        print_info "$2 removed"
    else
        print_warn "$2 is not installed"
    fi
}

function check_sanity {
    # Do some sanity checking.
    if [ $(/usr/bin/id -u) != "0" ]
    then
        die 'Must be run by root user'
    fi

    if [ ! -f /etc/debian_version ]
    then
        die "Distribution is not supported"
    fi
}

function die {
    echo "ERROR: $1" > /dev/null 1>&2
    exit 1
}

function get_domain_name() {
    # Getting rid of the lowest part.
    domain=${1%.*}
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    case "$lowest" in
    com|net|org|gov|edu|co)
        domain=${domain%.*}
        ;;
    esac
    lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
    [ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
    # Check whether our local salt is present.
    SALT=/var/lib/radom_salt
    if [ ! -f "$SALT" ]
    then
        head -c 512 /dev/urandom > "$SALT"
        chmod 400 "$SALT"
    fi
    password=`(cat "$SALT"; echo $1) | md5sum | base64`
    echo ${password:0:13}
}

function install_dash {
    check_install dash dash
    rm -f /bin/sh
    ln -s dash /bin/sh
}

function install_dropbear {
    check_install dropbear dropbear
    check_install /usr/sbin/xinetd xinetd

    # Disable SSH
    touch /etc/ssh/sshd_not_to_be_run
    invoke-rc.d ssh stop

    # Enable dropbear to start. We are going to use xinetd as it is just
    # easier to configure and might be used for other things.
    cat > /etc/xinetd.d/dropbear <<END
service ssh
{
    socket_type     = stream
    only_from       = 0.0.0.0
    wait            = no
    user            = root
    protocol        = tcp
    server          = /usr/sbin/dropbear
    server_args     = -i
    disable         = no
}
END
    invoke-rc.d xinetd restart
}

function install_exim4 {
    check_install mail exim4
    if [ -f /etc/exim4/update-exim4.conf.conf ]
    then
        sed -i \
            "s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
            /etc/exim4/update-exim4.conf.conf
        invoke-rc.d exim4 restart
    fi
}

function install_mysql {
    # Install the MySQL packages
    check_install mysqld mysql-server
    check_install mysql mysql-client

    # Install a low-end copy of the my.cnf to disable InnoDB, and then delete
    # all the related files.
    invoke-rc.d mysql stop
    rm -f /var/lib/mysql/ib*
    cat > /etc/mysql/conf.d/lowendbox.cnf <<END
# These values override values from /etc/mysql/my.cnf

[mysqld]
key_buffer = 8M
query_cache_size = 0
table_cache = 32

init_connect='SET collation_connection = utf8_unicode_ci'
init_connect='SET NAMES utf8'
character-set-server = utf8
collation-server = utf8_unicode_ci
skip-character-set-client-handshake

default_storage_engine=MyISAM
ignore_builtin_innodb

log-slow-queries=/var/log/mysql/slow-queries.log

[client]
default-character-set = utf8
END
    invoke-rc.d mysql start

    # Generating a new password for the root user.
    passwd=`get_password root@mysql`
    mysqladmin password "$passwd"
    cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
    chmod 600 ~/.my.cnf
}

#function install_nginx {
#    check_install nginx nginx
    
    # Need to increase the bucket size for Debian 5.
#    cat > /etc/nginx/conf.d/lowendbox.conf <<END
#server_names_hash_bucket_size 64;
#END

#    invoke-rc.d nginx restart
#}

function install_nginx {
    check_install nginx "nginx"

    if [ ! -d /etc/nginx/ssl_keys ]; then
        mkdir /etc/nginx/ssl_keys
    fi
    if [ ! -e /etc/nginx/ssl_keys/dhparam-1024.pem ]; then
        openssl dhparam -out /etc/nginx/ssl_keys/dhparam-1024.pem 1024
    fi

# Create a ssl default ssl certificate.
# This can be reused instead of creating a creating a self signed certificate.
    if [ ! -e /etc/nginx/ssl_keys/default.pem ]; then
	cat > /etc/nginx/ssl_keys/default.conf <<END
[req]
distinguished_name  = req_distinguished_name

[ req_distinguished_name ]
countryName         = Country Name (2 letter code)
countryName_default     = XX
countryName_min         = 2
countryName_max         = 2

commonName          = Common Name (eg, YOUR name)
commonName_default  = Default CA
commonName_max          = 64
END
	openssl genrsa -passout pass:password -des3 -out /etc/nginx/ssl_keys/default.key.secure 4096
	openssl req -passin pass:password -new -x509 -key /etc/nginx/ssl_keys/default.key.secure -out /etc/nginx/ssl_keys/default.pem -days 3650 -config /etc/nginx/ssl_keys/default.conf -batch
	openssl rsa -passin pass:password -in /etc/nginx/ssl_keys/default.key.secure -out /etc/nginx/ssl_keys/default.key

	#openssl ecparam -out /etc/nginx/ssl_keys/default.ec.key -name secp521r1 -genkey
	#openssl req -new -key /etc/nginx/ssl_keys/default.ec.key -x509 -nodes -days 3650 -out /etc/nginx/ssl_keys/default.ec.crt -config /etc/nginx/ssl_keys/default.ec.conf -batch
    fi

    cat > /etc/nginx/nginx.conf <<END
user www-data;
worker_processes $CPUCORES;
pid /run/nginx.pid;

events {
	worker_connections 768;
	# multi_accept on;
}

http {

	##
	# Basic Settings
	##

	sendfile on;
	tcp_nopush on;
	tcp_nodelay on;
	keepalive_timeout 65;
	types_hash_max_size 2048;
	server_names_hash_bucket_size 64;
	ignore_invalid_headers on;
	log_format  main  '\$remote_addr \$host \$server_port \$remote_user [\$time_local] "\$request" '
               '\$status \$body_bytes_sent "\$http_referer" "\$http_user_agent" "\$http_x_forwarded_for"';
	upstream php {
		server unix:/var/run/php5-fpm.sock;
	}

	# server_name_in_redirect off;

	include mime.types;
	default_type application/octet-stream;

	##
	# Logging Settings
	##

	access_log /var/log/nginx/access.log main;
	error_log /var/log/nginx/error.log error;

	##
	# Gzip Settings
	##

	gzip on;
	gzip_disable "msie6";
	gzip_min_length 1400;
	gzip_vary on;
	gzip_proxied any;
	gzip_comp_level 6;
	gzip_buffers 16 8k;
	gzip_http_version 1.1;
	gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;

	ssl_certificate ssl_keys/default.pem;
	ssl_certificate_key ssl_keys/default.key;
	ssl_dhparam ssl_keys/dhparam-1024.pem;
	ssl_session_timeout 5m;
	ssl_session_cache shared:SSL:10m;
	ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2;
	ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:ECDHE-RSA-AES256-SHA:DHE-RSA-AES256-SHA:DHE-RSA-CAMELLIA256-SHA:ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:DHE-RSA-AES128-SHA:DHE-RSA-CAMELLIA128-SHA:HIGH:!aNULL;
	ssl_prefer_server_ciphers on;

	include /etc/nginx/conf.d/*.conf;
	include /etc/nginx/sites-enabled/*;
}

END

# Remove deprecated file
    rm -f /etc/nginx/conf.d/lowendbox.conf

# Make sure sites-available & sites enabled exist
# Should only be needed when installing a cpu optimised nginx from my own repository.
	if [ ! -d /etc/nginx/sites-available ]; then
		mkdir /etc/nginx/sites-available
	fi
	if [ ! -d /etc/nginx/sites-enabled ]; then
		mkdir /etc/nginx/sites-enabled
	fi

    cat > /etc/nginx/sites-available/default <<END
server {
END
    if [ "$INTERFACE" = "all" ]; then
        cat >> /etc/nginx/sites-available/default <<END
    listen 80 default_server; ## listen for ipv4
    listen 443 default_server ssl; ## listen for ipv4
    listen [::]:80 default_server ipv6only=on; ## listen for ipv6
    listen [::]:443 default_server ipv6only=on ssl; ## listen for ipv6
END
    else
        if [ "$INTERFACE" = "ipv6" ]; then
            cat >> /etc/nginx/sites-available/default <<END
    listen [::]:80 default_server; ## listen for ipv6
    listen [::]:443 default_server ipv6only=on ssl; ## listen for ipv6
END
        else
            cat >> /etc/nginx/sites-available/default <<END
    listen 80 default_server; ## listen for ipv4
    listen 443 default_server ssl; ## listen for ipv4
END
        fi
    fi
    cat >> /etc/nginx/sites-available/default <<END
    server_name  _;
    access_log  /var/log/nginx/default.log main;
    ssl_ciphers "ALL:!aNULL:!RC4";
    return 444;
}
END
	cat > /etc/nginx/standard.conf <<END
location = /favicon.ico {
	return 204;
	log_not_found off;
	access_log off;
}

location = /robots.txt {
	log_not_found off;
	access_log off;
}

# Make sure files with the following extensions do not get loaded by nginx because nginx would display the source code, and these files can contain PASSWORDS!
location ~* \.(engine|inc|info|install|make|module|profile|test|po|sh|.*sql|theme|tpl(\.php)?|xtmpl)$|^(\..*|Entries.*|Repository|Root|Tag|Template)$|\.php_
{
	return 444;
}

# Deny all attempts to access hidden files such as .htaccess, .htpasswd, .DS_Store (Mac).
location ~ /\. {
	return 444;
	access_log off;
	log_not_found off;
	}

location ~*  \.(jpg|jpeg|png|gif|css|js|ico)$ {
	expires max;
	log_not_found off;
}
END
    cat > /etc/nginx/nophp.conf <<END
location ~* \.php\$ {
	return 444;
}
END
    cat > /etc/nginx/nocgi.conf <<END
location ~* \\.(pl|cgi|py|sh|lua)\$ {
	return 444;
}
END
    cat > /etc/nginx/disallow.conf <<END
location ~* (roundcube|webdav|smtp|http\\:|soap|w00tw00t) {
	return 444;
}
if (\$http_user_agent ~* "(Morfeus|larbin|ZmEu|Toata|Huawei|talktalk)" ) {
	return 444;
}
END
#   delete deprecated file
    rm -f /etc/nginx/disallow-agent.conf

    invoke-rc.d nginx restart
    chown www-data:adm /var/log/nginx/*
    sed -i "s/rotate 52/rotate 1/" /etc/logrotate.d/nginx
}

function install_nginx-upstream {
    wget -O - http://nginx.org/keys/nginx_signing.key | apt-key add -
    cat > /etc/apt/sources.list.d/nginx.list <<END
deb http://nginx.org/packages/debian/ wheezy nginx
#deb-src http://nginx.org/packages/debian/ wheezy nginx
END
    apt-get update
    apt-get -y remove nginx nginx-full nginx-common
    apt-get install nginx
    sed -i "s/rotate 52/rotate 1/" /etc/logrotate.d/nginx
}

function install_php {
    check_install php-cgi php5-cgi php5-cli php5-mysql
    cat > /etc/init.d/php-cgi <<END
#!/bin/bash
### BEGIN INIT INFO
# Provides:          php-cgi
# Required-Start:    networking
# Required-Stop:     networking
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Start the PHP FastCGI processes web server.
### END INIT INFO

PATH=/sbin:/bin:/usr/sbin:/usr/bin
NAME="php-cgi"
DESC="php-cgi"
PIDFILE="/var/run/www/php.pid"
FCGIPROGRAM="/usr/bin/php-cgi"
FCGISOCKET="/var/run/www/php.sock"
FCGIUSER="www-data"
FCGIGROUP="www-data"

if [ -e /etc/default/php-cgi ]
then
    source /etc/default/php-cgi
fi

[ -z "\$PHP_FCGI_CHILDREN" ] && PHP_FCGI_CHILDREN=1
[ -z "\$PHP_FCGI_MAX_REQUESTS" ] && PHP_FCGI_MAX_REQUESTS=5000

ALLOWED_ENV="PATH USER PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS FCGI_WEB_SERVER_ADDRS"

set -e

. /lib/lsb/init-functions

case "\$1" in
start)
    unset E
    for i in \${ALLOWED_ENV}; do
        E="\${E} \${i}=\${!i}"
    done
    log_daemon_msg "Starting \$DESC" \$NAME
    env - \${E} start-stop-daemon --start -x \$FCGIPROGRAM -p \$PIDFILE \\
        -c \$FCGIUSER:\$FCGIGROUP -b -m -- -b \$FCGISOCKET
    log_end_msg 0
    ;;
stop)
    log_daemon_msg "Stopping \$DESC" \$NAME
    if start-stop-daemon --quiet --stop --oknodo --retry 30 \\
        --pidfile \$PIDFILE --exec \$FCGIPROGRAM
    then
        rm -f \$PIDFILE
        log_end_msg 0
    else
        log_end_msg 1
    fi
    ;;
restart|force-reload)
    \$0 stop
    sleep 1
    \$0 start
    ;;
*)
    echo "Usage: \$0 {start|stop|restart|force-reload}" >&2
    exit 1
    ;;
esac
exit 0
END
    chmod 755 /etc/init.d/php-cgi
    mkdir -p /var/run/www
    chown www-data:www-data /var/run/www

    cat > /etc/nginx/fastcgi_php <<END
location ~ \.php$ {
    include /etc/nginx/fastcgi_params;

    fastcgi_index index.php;
    fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
    if (-f \$request_filename) {
        fastcgi_pass unix:/var/run/www/php.sock;
    }
}
END
    update-rc.d php-cgi defaults
    invoke-rc.d php-cgi start
}

function install_syslogd {
    # We just need a simple vanilla syslogd. Also there is no need to log to
    # so many files (waste of fd). Just dump them into
    # /var/log/(cron/mail/messages)
    check_install /usr/sbin/syslogd inetutils-syslogd
    invoke-rc.d inetutils-syslogd stop

    for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
    do
        [ -f "$file" ] && rm -f "$file"
    done
    for dir in fsck news
    do
        [ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
    done

    cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.*                  -/var/log/cron
mail.*                  -/var/log/mail
END

    [ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
    cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
   rotate 4
   weekly
   missingok
   notifempty
   compress
   sharedscripts
   postrotate
      /etc/init.d/inetutils-syslogd reload >/dev/null
   endscript
}
END

    invoke-rc.d inetutils-syslogd start
}

function install_wordpress {
    check_install wget wget
    if [ -z "$1" ]
    then
        die "Usage: `basename $0` wordpress <hostname>"
    fi

    # Downloading the WordPress' latest and greatest distribution.
    mkdir /tmp/wordpress.$$
    wget -O - http://wordpress.org/latest.tar.gz | \
        tar zxf - -C /tmp/wordpress.$$
    mv /tmp/wordpress.$$/wordpress "/var/www/$1"
    rm -rf /tmp/wordpress.$$
    chown www-data:www-data -R "/var/www/$1"

    # Setting up the MySQL database
    dbname=`echo $1 | tr . _`
    userid=`get_domain_name $1`
    # MySQL userid cannot be more than 15 characters long
    userid="${userid:0:15}"
    passwd=`get_password "$userid@mysql"`
    cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
    sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
        "/var/www/$1/wp-config.php"
    mysqladmin create "$dbname"
    echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
        mysql

    # Setting up Nginx mapping
    cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server {
    server_name $1;
    root /var/www/$1;
    include /etc/nginx/fastcgi_php;
    location / {
        index index.php;
        if (!-e \$request_filename) {
            rewrite ^(.*)$  /index.php last;
        }
    }
}
END
    invoke-rc.d nginx reload
}

function install_php {
    check_install php5-fpm "php5-fpm php5-cli php5-mysqlnd php5-cgi php5-gd php5-curl php-apc"
    if [ "$SERVER" = "nginx" ]; then
	cat > /etc/nginx/fastcgi_php <<END
location ~ \.php$ {
	include /etc/nginx/fastcgi_params;
	fastcgi_index index.php;
	fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
	if (-f \$request_filename) {
		fastcgi_pass php;
	}
}
END
fi
    sed -i "/pm =/cpm = ondemand" /etc/php5/fpm/pool.d/www.conf
    if [ "$MEMORY" = "low" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 1" /etc/php5/fpm/pool.d/www.conf
	elif [ "$MEMORY" = "64" ]; then
		sed -i "/pm.max_children =/cpm.max_children = 2" /etc/php5/fpm/pool.d/www.conf
	elif [ "$MEMORY" = "96" ]; then
       	sed -i "/pm.max_children =/cpm.max_children = 3" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "128" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 4" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "192" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 6" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "256" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 8" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "384" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 12" /etc/php5/fpm/pool.d/www.conf
    elif [ "$MEMORY" = "512" ]; then
        sed -i "/pm.max_children =/cpm.max_children = 16" /etc/php5/fpm/pool.d/www.conf
    fi
    sed -i "/pm.max_requests =/cpm.max_requests = 500" /etc/php5/fpm/pool.d/www.conf
    sed -i "/pm.status_path =/cpm.status_path = \/status" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen =/clisten = /var/run/php5-fpm.sock" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.owner =/clisten.owner = www-data" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.group =/clisten.group = www-data" /etc/php5/fpm/pool.d/www.conf
    sed -i "/listen.mode =/clisten.mode = 0666" /etc/php5/fpm/pool.d/www.conf
	cat > /etc/php5/conf.d/lowendscript.ini <<END
apc.enable_cli = 1
apc.mmap_file_mask=/tmp/apc.XXXXXX
date.timezone = `cat /etc/timezone`
END
    service php5-fpm restart
    if [ "$SERVER" = "nginx" ]; then
	if [ -f /etc/init.d/php-cgi ];then
            service php-cgi stop
            update-rc.d php-cgi remove
            rm /etc/init.d/php-cgi
            service nginx restart
            print_info "/etc/init.d/php-cgi removed"
	fi
    fi
}
function print_info {
    echo -n -e '\e[1;36m'
    echo -n $1
    echo -e '\e[0m'
}

function print_warn {
    echo -n -e '\e[1;33m'
    echo -n $1
    echo -e '\e[0m'
}

function remove_unneeded {
    # Some Debian have portmap installed. We don't need that.
    check_remove /sbin/portmap portmap

    # Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
    # which might make some low-end VPS inoperatable. We will do this even
    # before running apt-get update.
    check_remove /usr/sbin/rsyslogd rsyslog

    # Other packages that seem to be pretty common in standard OpenVZ
    # templates.
    check_remove /usr/sbin/apache2 'apache2*'
    check_remove /usr/sbin/named bind9
    check_remove /usr/sbin/smbd 'samba*'
    check_remove /usr/sbin/nscd nscd

    # Need to stop sendmail as removing the package does not seem to stop it.
    if [ -f /usr/lib/sm.bin/smtpd ]
    then
        invoke-rc.d sendmail stop
        check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
    fi
}

function update_upgrade {
    # Run through the apt-get update/upgrade first. This should be done before
    # we try to install any package
    apt-get -q -y update
    apt-get -q -y upgrade
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
exim4)
    install_exim4
    ;;
mysql)
    install_mysql
    ;;
nginx)
    install_nginx
    ;;
php)
    install_php
    ;;
system)
    remove_unneeded
    update_upgrade
    install_dash
    install_syslogd
    install_dropbear
    ;;
wordpress)
    install_wordpress $2
    ;;
*)
    echo 'Usage:' `basename $0` '[option]'
    echo 'Available option:'
    for option in system exim4 mysql nginx php wordpress
    do
        echo '  -' $option
    done
    ;;
esac
