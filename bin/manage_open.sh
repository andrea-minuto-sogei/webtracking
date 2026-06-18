#!/bin/bash
set -euo pipefail

# How to run:
# curl http://mdwservizio01.srv.sogei.it/WebTracking/manage_open.sh -o manage_open.sh
# sh manage_open.sh --setup | tee manage.log
# sh manage_open.sh --update | tee manage.log
# sh manage_open.sh --help
# sh manage_open.sh --version
# rm manage_open.sh

# Version
VERSION="2026.6.8.1"

# Variables
WEBTRACKING_HOME="/webtracking"

log()
{
   # Extract hour in 00–23
   local h=$(date +%H)

   # Milliseconds from nanoseconds
   local ms=$(date +%N | cut -c1-3)

   # Output matching the format: yyyy-MM-dd HH:mm:ss:SSS z
   printf '[%s]: %s\n' "$(date +%Y-%m-%d) $h:$(date +%M):$(date +%S):$ms $(date +%Z)" "$*"
}

usage()
{
   cat << EOF
Usage: $(basename "$0") [OPTIONS]

OPTIONS:
   --setup          Setup WebTracking with Splunk forwarder
   --update         Update Splunk forwarder binaries
   -h, --help       Display this help message
   -v, --version    Display version information

EXAMPLES:
   sh $(basename "$0") --setup
   sh $(basename "$0") --update
   sh $(basename "$0") --help
   sh $(basename "$0") --version

EOF
}

version()
{
   echo "$(basename "$0") version $VERSION"
}

setup()
{
   log "Starting setup phase"
   
   if [[ $EUID -ne 0 ]]
   then
      log "This script must be run as root" >&2
      exit 1
   fi

   if ! id apache >/dev/null 2>&1
   then
      log "User apache not found. Cannot proceed." >&2
      exit 1
   fi

   log "VERSION=$VERSION"
   
   log "Starting WebTracking installation"

   log "Ensuring $WEBTRACKING_HOME directory exists"
   mkdir -p $WEBTRACKING_HOME
   
   log "Downloading webtracking binaries"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/webtracking-bin.zip -o webtracking-bin.zip
   
   log "Extracting webtracking binaries"
   unzip -uo webtracking-bin.zip -d /
   
   log "Cleaning up"
   rm -f webtracking-bin.zip
   
   log "Setting ownership and permissions"
   chown root:apache $WEBTRACKING_HOME
   chmod g+w $WEBTRACKING_HOME
   chown -R root:apache $WEBTRACKING_HOME/{logs,splunk}

   log "Starting Splunk forwarder installation"
   
   log "Downloading Splunk forwarder"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/splunkforwarder.tgz -o splunkforwarder.tgz
   
   log "Extracting Splunk forwarder"
   tar -xaf splunkforwarder.tgz -C $WEBTRACKING_HOME

   log "Setting ownership and permissions for Splunk forwarder"
   chown -R apache:apache $WEBTRACKING_HOME/splunkforwarder
   
   log "Cleaning up"
   rm -f splunkforwarder.tgz
   
   log "Disabling history command expansion to avoid issues with semanage fcontext patterns"
   set +H

   log "Configuring SELinux contexts for WebTracking directories"
   semanage fcontext -a -t var_lib_t "$WEBTRACKING_HOME/splunkforwarder(?!/bin)(/.*)?"

   log "Configuring SELinux contexts for WebTracking log and update directories"
   semanage fcontext -a -t httpd_sys_rw_content_t "$WEBTRACKING_HOME/(update|logs|splunk)(/.*)?"
   
   log "Configuring SELinux contexts for WebTracking binary directories"
   semanage fcontext -a -t bin_t "$WEBTRACKING_HOME/(bin|splunkforwarder/bin)(/.*)?"

   log "Configuring SELinux contexts for WebTracking library directories"
   semanage fcontext -a -t httpd_modules_t "$WEBTRACKING_HOME/lib(/.*)?"

   log "Re-enabling history command expansion"
   set -H
   
   log "Apply SELinux contexts"
   restorecon -R $WEBTRACKING_HOME
   
   log "Setting up webtracking Splunk forwarder"
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
   
   log "Configuring Splunk forwarder deployment file"
   echo '[target-broker:deploymentServer]' > $WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf
   echo 'targetUri = TRASPLMGLP01-03.srv.sogei.it:8089' >> $WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf
   chown apache:apache $WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf

   log "Wait 10 seconds and stop Splunk forwarder"
   sleep 10
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk stop

   log "Enabling boot start for Splunk forwarder"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk enable boot-start -user apache -systemd-managed 1

   log "Reloading systemd daemon and start Splunk forwarder"
   systemctl daemon-reload
   systemctl start SplunkForwarder

   log "Displaying Splunk forwarder version"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk --version | tail -1 || true

   log "Add check.sh to crontab if not already present"
    (crontab -l 2>/dev/null | grep -q "/webtracking/bin/check.sh") || \
    (crontab -l 2>/dev/null; \
    crontab -l 2>/dev/null | grep -q . && echo ""; \
    echo "# Check splunkd process and stale files"; \
    echo "*/15 * * * * /webtracking/bin/check.sh") | \
    crontab -
    crontab -l | grep -B1 "/webtracking/bin/check.sh"

   log "Setup phase completed successfully"
}

update()
{
   log "Starting update phase"
   
   if [[ $EUID -ne 0 ]]
   then
      log "This script must be run as root" >&2
      exit 1
   fi

   if ! id apache >/dev/null 2>&1
   then
      log "User apache not found. Cannot proceed." >&2
      exit 1
   fi

   log "VERSION=$VERSION"

   log "Starting WebTracking update"

   log "Stopping Apache web server to release log files"
   systemctl stop httpd

   log "Downloading webtracking binaries"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/webtracking-bin.zip -o webtracking-bin.zip
   
   log "Extracting webtracking binaries"
   unzip -uo webtracking-bin.zip -d /
   
   log "Cleaning up"
   rm -f webtracking-bin.zip

   log "Starting Apache web server"
   systemctl start httpd
   
   log "Starting Splunk forwarder update"

   log "Downloading Splunk forwarder"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/splunkforwarder.tgz -o splunkforwarder.tgz

   log "Stopping Splunk forwarder"
   systemctl stop SplunkForwarder
   
   log "Extracting new Splunk forwarder binaries"
   tar xaf $WEBTRACKING_HOME/update/splunkforwarder.tgz -C "$WEBTRACKING_HOME"
   
   log "Starting Splunk forwarder"
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
   
   log "Cleaning up symbolic links"
   find -L $WEBTRACKING_HOME/splunkforwarder -type l -exec rm -v {} \;
   
   log "Removing update archive"
   rm -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
   
   log "Displaying Splunk forwarder version"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk --version | tail -1 || true

   log "Update phase completed successfully"
}

main()
{
   local command="${1:-}"
   
   case "$command" in
      --setup)
         log "Executing setup operation"
         setup
         ;;
      --update)
         log "Executing update operation"
         update
         ;;
      -h|--help)
         log "Displaying help information"
         usage
         exit 0
         ;;
      -v|--version)
         log "Displaying version information"
         version
         exit 0
         ;;
      "")
         usage
         exit 1
         ;;
      *)
         log "Error: Unknown option '$command'" >&2
         usage
         exit 1
         ;;
   esac
}

main "$@"
