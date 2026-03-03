#!/bin/bash 

# Version
VERSION=2026.3.3.1

#!/usr/bin/env bash
set -euo pipefail

# Path to the splunkd binary (used to identify the process)
SPLUNKD_PATH="splunkd"
# Full command to restart splunk
SPLUNK_RESTART_CMD=("/webtracking/splunkforwarder/bin/splunk" restart --answer-yes --no-prompt)
# Mount point to check
WEBTRACKING_HOME="/webtracking"
# Directory where webtracking Splunk files are stored (for cleanup)
WEBTRACKING_SPLUNK="/webtracking/splunk"
# Directory for webtracking data files (for cleanup)
WEBTRACKING_LOGS="/webtracking/logs"
# owner of the IHS installation (required user to run this script)
IHS_OWNER="webihs"

log()
{
   # Extract hour in 00–23
   local h=$(date +%H)

   # Milliseconds from nanoseconds
   local ms=$(date +%N | cut -c1-3)

   # Output matching the format: yyyy-MM-dd HH:mm:ss:SSS z
   printf '[%s]: %s\n' "$(date +%Y-%m-%d) $h:$(date +%M):$(date +%S):$ms $(date +%Z)" "$*"
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

if [[ "$(whoami)" != "$IHS_OWNER" ]]
then
   log "ERROR: The command was launched as the user $(whoami) and must have been run as the $IHS_OWNER user"
   exit 1
fi

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
   "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop
   tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
   "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
   find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
   rm -fv "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
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
      exit 2
   fi
fi
