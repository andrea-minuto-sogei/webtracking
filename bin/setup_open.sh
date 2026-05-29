#!/bin/bash
set -euo pipefail

VERSION="2025.5.29.1"

log()
{
   # Extract hour in 00–23
   local h=$(date +%H)

   # Milliseconds from nanoseconds
   local ms=$(date +%N | cut -c1-3)

   # Output matching the format: yyyy-MM-dd HH:mm:ss:SSS z
   printf '[%s]: %s\n' "$(date +%Y-%m-%d) $h:$(date +%M):$(date +%S):$ms $(date +%Z)" "$*"
}

main()
{
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
   log "Starting execution"

   log "Ensuring /webtracking directory exists"
   mkdir -p /webtracking
   
   log "Downloading webtracking binaries"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/webtracking-bin.zip -o webtracking-bin.zip
   
   log "Extracting webtracking binaries"
   unzip -uo webtracking-bin.zip -d /
   
   log "Cleaning up"
   rm -f webtracking-bin.zip
   
   log "Setting ownership and permissions"
   chown root:apache /webtracking
   chmod g+w /webtracking
   chown -R root:apache /webtracking/{logs,splunk}
   
   log "Downloading Splunk forwarder"
   curl http://mdwservizio01.srv.sogei.it/WebTracking/splunkforwarder.tgz -o splunkforwarder.tgz
   
   log "Extracting Splunk forwarder"
   tar -xzf splunkforwarder.tgz -C /webtracking

   log "Setting ownership and permissions for Splunk forwarder"
   chown -R apache:apache /webtracking/splunkforwarder
   
   log "Cleaning up"
   rm -f splunkforwarder.tgz
   
   log "Setting SELinux contexts"
   semanage fcontext -a -t var_lib_t '/webtracking/splunkforwarder(?!/bin)(/.*)?'
   semanage fcontext -a -t httpd_sys_rw_content_t '/webtracking/(update|logs|splunk)(/.*)?'
   semanage fcontext -a -t bin_t '/webtracking/(bin|splunkforwarder/bin)(/.*)?'
   semanage fcontext -a -t httpd_modules_t '/webtracking/lib(/.*)?'
   
   log "Apply SELinux contexts"
   restorecon -Rv /webtracking
   
   log "Setting up webtracking Splunk forwarder"
   SPLUNK_OS_USER=apache /webtracking/splunkforwarder/bin/splunk start --accept-license --answer-yes
   
   log "Configuring Splunk forwarder deployment"
   echo '[target-broker:deploymentServer]' > /webtracking/splunkforwarder/etc/system/local/deploymentclient.conf
   echo 'targetUri = TRASPLMGLP01-03.srv.sogei.it:8089' >> /webtracking/splunkforwarder/etc/system/local/deploymentclient.conf
   chown apache:apache /webtracking/splunkforwarder/etc/system/local/deploymentclient.conf

   log "Wait 10 seconds and restart Splunk forwarder"
   sleep 10
   SPLUNK_OS_USER=apache /webtracking/splunkforwarder/bin/splunk restart

   log "Finished execution"
}

main "$@"
