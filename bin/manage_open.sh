#!/bin/bash
set -euo pipefail

# Authors: 
#    Andrea Minuto
#    GitHub Copilot

# How to run:
# curl http://mdwservizio01.srv.sogei.it/WebTracking/manage_open.sh -o manage_open.sh
# sh manage_open.sh --setup | tee manage.log
# sh manage_open.sh --update | tee manage.log
# sh manage_open.sh --no-auto-cleanup --setup | tee manage.log
# sh manage_open.sh --help
# sh manage_open.sh --version

# Exit on error, unset variable, or pipe failure
set -euo pipefail

# Version
readonly VERSION="2026.9.28.1"

# Variables
readonly WEBTRACKING_HOME="/webtracking"

# ---------------------------------------------------------------------------
# log  — writes a timestamped line to stdout.
# Usage: log "message"
# Format: [yyyy-MM-dd HH:mm:ss:SSS TZ]: message
# ---------------------------------------------------------------------------
log()
{
   # Single date call to avoid inconsistent timestamps across sub-invocations
   local now
   now=$(date +"%Y-%m-%d %H:%M:%S:%3N %Z")
   printf '[%s]: %s\n' "${now}" "$*"
}

# Controls whether the script removes itself after execution
to_be_perform_cleanup=true

cleanup()
{
  local exit_code=${1:-0}

  if [[ "$exit_code" -ne 0 ]]
  then
      log "Cleanup skipped: previous command failed with exit code $exit_code"
      return
  fi

  log "Cleanup: removing temporary files"
  rm -f -- "splunkforwarder.tgz"
  rm -f -- "webtracking-bin.zip"
  
  if [[ "$to_be_perform_cleanup" == true ]]
  then
    log "Cleanup: removing script $0"
    rm -f -- "$0"
  fi
}

# Call cleanup on exit, passing the exit code so it can skip on failure
trap 'cleanup "$?"' EXIT

usage()
{
   cat << EOF
Usage: $(basename "$0") [OPTIONS]

Options:
   --setup           Setup WebTracking and Splunk Universal Forwarder
   --update          Update WebTracking and Splunk Universal Forwarder
   --no-auto-cleanup Do not remove the script itself after execution
   -h, --help        Display this help message
   -v, --version     Display version information

Example usage:
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
   
   log "Starting WebTracking and Splunk Universal Forwarder installation"

   log "Ensuring $WEBTRACKING_HOME directory exists"
   mkdir -p $WEBTRACKING_HOME
   
   log "Downloading webtracking binaries"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/webtracking-bin.zip -o webtracking-bin.zip
   
   log "Extracting webtracking binaries"
   unzip -uo webtracking-bin.zip -d /
   
   log "Cleaning up"
   rm -f webtracking-bin.zip

   log "Displaying webtracking version"
   cat $WEBTRACKING_HOME/bin/version.txt
   
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

   log "Wait 10 seconds and stop Splunk Universal Forwarder"
   sleep 10
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk stop

   log "Enabling boot start for Splunk Universal Forwarder"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk enable boot-start -user apache -systemd-managed 1

   log "Reloading systemd daemon and start Splunk Universal Forwarder"
   systemctl daemon-reload
   systemctl start SplunkForwarder

   log "Displaying Splunk Universal Forwarder version"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk --version | tail -1 || true

   log "Add check.sh to crontab if not already present"
   if ! crontab -l 2>/dev/null | grep -F "/webtracking/bin/check.sh" >/dev/null
   then
      {
         crontab -l 2>/dev/null || true
         crontab -l 2>/dev/null | grep -F . >/dev/null && echo ""
         echo "# Check splunkd process and stale files"
         echo "*/15 * * * * /webtracking/bin/check.sh"
      } | crontab -
   fi

   if ! crontab -l 2>/dev/null | grep -F -B1 "/webtracking/bin/check.sh"
   then
      log "ERROR: Could not verify check.sh crontab entry"
      exit 1
   fi

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

   log "Starting WebTracking and Splunk Universal Forwarder update"

   log "Stopping Apache web server to release log files"
   systemctl stop httpd

   log "Downloading webtracking binaries"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/webtracking-bin.zip -o webtracking-bin.zip
   
   log "Extracting webtracking binaries"
   unzip -uo webtracking-bin.zip -d /
   
   log "Cleaning up"
   rm -f webtracking-bin.zip

   log "Displaying webtracking version"
   cat $WEBTRACKING_HOME/bin/version.txt

   log "Starting Apache web server"
   systemctl start httpd
   
   log "Starting Splunk Universal Forwarder update"

   log "Downloading Splunk Universal Forwarder"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/splunkforwarder.tgz -o splunkforwarder.tgz

   log "Stopping Splunk Universal Forwarder"
   systemctl stop SplunkForwarder
   
   log "Extracting new Splunk Universal Forwarder binaries"
   tar xaf splunkforwarder.tgz -C "$WEBTRACKING_HOME"

   log "Setting ownership and permissions for Splunk Universal Forwarder"
   chown -R apache:apache $WEBTRACKING_HOME/splunkforwarder

   log "Disabling boot start for Splunk Universal Forwarder"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk disable boot-start -user apache -systemd-managed 1
   
   log "Starting Splunk Universal Forwarder to apply the update"
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk start --accept-license --answer-yes --no-prompt
   
   log "Cleaning up symbolic links"
   find -L $WEBTRACKING_HOME/splunkforwarder -type l -exec rm -v {} \;
   
   log "Removing update archive"
   rm -f splunkforwarder.tgz

   log "Wait 10 seconds and stop Splunk Universal Forwarder"
   sleep 10
   sudo -u apache $WEBTRACKING_HOME/splunkforwarder/bin/splunk stop

   log "Enabling boot start for Splunk Universal Forwarder"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk enable boot-start -user apache -systemd-managed 1

   log "Reloading systemd daemon and start Splunk Universal Forwarder"
   systemctl daemon-reload
   systemctl start SplunkForwarder

   log "Displaying Splunk Universal Forwarder version"
   $WEBTRACKING_HOME/splunkforwarder/bin/splunk --version | tail -1 || true

   log "Update phase completed successfully"
}

main()
{
   local command="${1:-}"
   
   case "$command" in
      --setup)
         setup
         ;;
      --update)
         update
         ;;
      --no-auto-cleanup)
         to_be_perform_cleanup=false
         log "Auto cleanup disabled. The script will not remove itself after execution."
         ;;
      -h|--help)
         usage
         cleanup_to_be_perform=false
         exit 0
         ;;
      -v|--version)
         version
         cleanup_to_be_perform=false
         exit 0
         ;;
      "")
         usage
         cleanup_to_be_perform=false
         exit 1
         ;;
      *)
         log "Error: Unknown option '$command'" >&2
         cleanup_to_be_perform=false
         exit 1
         ;;
   esac
}

main "$@"
