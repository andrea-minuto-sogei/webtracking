#!/bin/bash 

# This script is intended to be run periodically (e.g. via cron) to check the health of the Splunk forwarder on the webtracking server. 
#  It performs the following checks:
#     1. Verifies that the splunkd process is running by checking for the presence of the splunkd binary in the process list.
#     2. Checks the free space on the filesystem where /webtracking is mounted, ensuring that it has more than 20% free space.
#     If any of the checks fail, it attempts to restart the Splunk forwarder service.

# Return codes:
# 0 - All checks passed, no action needed
# 1 - WEBTRACKING_HOME directory does not exist or is not accessible
# 2 - Script not run as the correct user
# 3 - Splunk restart failed

# Version
VERSION=2026.9.28.1

#!/usr/bin/env bash
set -euo pipefail

# Mount point to check
WEBTRACKING_HOME="/webtracking"
# Directory where webtracking Splunk files are stored (for cleanup)
WEBTRACKING_SPLUNK="$WEBTRACKING_HOME/splunk"
# Directory for webtracking data files (for cleanup)
WEBTRACKING_LOGS="$WEBTRACKING_HOME/logs"
# Path to the splunkd binary (used to identify the process)
SPLUNKD_PATH="splunkd"

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

# Check if the splunkd process is active (search by full path)
is_splunkd_running() 
{
   if command -v pgrep >/dev/null 2>&1
   then
      pgrep -f -- "$SPLUNKD_PATH" >/dev/null 2>&1
      return $?
   else
      # fallback to ps if pgrep not available
      ps aux | grep -- "$SPLUNKD_PATH" | grep -v grep >/dev/null 2>&1
      return $?
   fi
}

# Check free space on the mount point; returns free percentage as integer
get_free_percent() 
{
   if [ ! -e "$WEBTRACKING_HOME" ]
   then
      # Mount point missing -> treat as 0% free (failure)
      printf '0'
      return 0
   fi

   # POSIX-compatible df output parsing
   # Use df -P for portable output
   used_pct=$(df -P "$WEBTRACKING_HOME" 2>/dev/null | awk 'NR==2 {gsub(/%/,"",$5); print $5}') || used_pct=""
   if [ -z "$used_pct" ]
   then
      # Unable to determine -> treat as 0% free
      printf '0'
      return 0
   fi

   free_pct=$((100 - used_pct))
   printf '%d' "$free_pct"
}

perform_restart() 
{
   log "Restarting Splunk: ${SPLUNK_RESTART_CMD[*]}"
   # Execute the restart command; preserve exit code
   "${SPLUNK_RESTART_CMD[@]}"
   rc=$?
   log "Splunk restart exit code: $rc"
   return $rc
}

# Main
log "$0: started"
log "version: $VERSION"

# Owner of WEBTRACKING_HOME directory (required user to run this script)
if [ -d "$WEBTRACKING_HOME" ]
then
   WEBTRACKING_OWNER=$(stat -c '%U' "$WEBTRACKING_HOME")
else
   echo "ERROR: WEBTRACKING_HOME directory $WEBTRACKING_HOME does not exist" >&2
   exit 1
fi

# if WEBTRACKING_OWNER is root
# then we use systemctl to stop the service
# else we use the splunk CLI with the appropriate user
if [ "$WEBTRACKING_OWNER" = "root" ]
then
   # Command to stop splunk (used before update)
   SPLUNK_STOP_CMD=(systemctl stop SplunkForwarder)
   
   # Command to restart splunk
   SPLUNK_RESTART_CMD=(systemctl restart SplunkForwarder)

   # User
   SPLUNK_USER="apache"
else
   # Command to stop splunk (used before update)
   SPLUNK_STOP_CMD=("$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop --answer-yes --no-prompt)

   # Command to restart splunk
   SPLUNK_RESTART_CMD=("$WEBTRACKING_HOME/splunkforwarder/bin/splunk" restart --answer-yes --no-prompt)

   # User
   SPLUNK_USER=$WEBTRACKING_OWNER
fi

if [[ "$(whoami)" != "$WEBTRACKING_OWNER" ]]
then
   log "ERROR: The command was launched as the user $(whoami) and must have been run as the $WEBTRACKING_OWNER user"
   exit 2
fi

# User
log "Running as user: $(whoami)"

# Move or remove the webtracking files as needed, then check splunkd process and free space, and restart if needed
log "Move or remove the webtracking files as needed"

# cleanup zero-byte and old files in WEBTRACKING_SPLUNK
if [ -d "$WEBTRACKING_SPLUNK" ]
then
   log "Cleaning up zero-byte and old files in $WEBTRACKING_SPLUNK"     
   find "$WEBTRACKING_SPLUNK" -type f \( -size 0 -o -mtime +10 \) -exec rm -v {} \;
fi

# moving aged log files in WEBTRACKING_LOGS if no process is using them
if [ -d "$WEBTRACKING_LOGS" ]
then
   # files modified more than 30 minutes ago
   log "Moving stale log files to folder $WEBTRACKING_SPLUNK"
   find "$WEBTRACKING_LOGS" -type f -mmin +30 | while read -r logfile; do
      # skip if any process still has the file open
      if ! lsof "$logfile" >/dev/null 2>&1
      then
         mv -v "$logfile" "$WEBTRACKING_SPLUNK/$(basename "$logfile")"
      fi
   done
fi

# Update splunk forwarder
if [[ -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" ]]
then
   log "Update splunkforwarder binaries"
   "${SPLUNK_STOP_CMD[@]}"
   tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
   chown -R $SPLUNK_USER:$SPLUNK_USER $WEBTRACKING_HOME/splunkforwarder
   if [ "$WEBTRACKING_OWNER" = "root" ]
   then
      $WEBTRACKING_HOME/splunkforwarder/bin/splunk disable boot-start -user $SPLUNK_USER -systemd-managed 1
      sudo -u $SPLUNK_USER "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
   else
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
   fi
   find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
   rm -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
   if [ "$WEBTRACKING_OWNER" = "root" ]
   then
      sleep 10
      sudo -u $SPLUNK_USER $WEBTRACKING_HOME/splunkforwarder/bin/splunk stop
      $WEBTRACKING_HOME/splunkforwarder/bin/splunk enable boot-start -user $SPLUNK_USER -systemd-managed 1
      systemctl daemon-reload
   fi
fi

if is_splunkd_running
then
   log "splunkd process appears to be running"
   process_ok=true
else
   log "splunkd process NOT running"
   process_ok=false
fi

free_pct=$(get_free_percent)
log "free space on $WEBTRACKING_HOME: ${free_pct}%"

# Requirement: filesystem must have MORE THAN 20% free.
# So require free_pct -gt 20 to be considered healthy.
if [ "$process_ok" = true ] && [ "$free_pct" -gt 20 ]
then
   log "All checks passed (process running and free > 20%). No action needed."
   exit 0
else
   log "One or more checks failed; attempting to restart splunkd"
   if perform_restart
   then
      log "Splunk restart succeeded"
      exit 0
   else
      log "Splunk restart failed"
      exit 3
   fi
fi
