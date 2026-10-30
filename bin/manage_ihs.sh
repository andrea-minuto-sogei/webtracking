# Authors: 
#    Andrea Minuto
#    Livia Cimini
#    Marcello Pirazzoli
#    GitHub Copilot
#    IBM Bob

# How to run:
# curl http://mdwservizio01.srv.sogei.it/WebTracking/manage_ihs.sh -o manage_ihs.sh
# sh manage_ihs.sh --all | tee manage.log
# sh manage_ihs.sh --splunkforwarder --webtracking --template | tee manage.log
# sh manage_ihs.sh --setup | tee manage.log
# sh manage_ihs.sh --no-auto-cleanup --setup | tee manage.log
# sh manage_ihs.sh --help
# sh manage_ihs.sh --version

# Exit on error, unset variable, or pipe failure
set -euo pipefail

# Version
readonly VERSION=2026.9.28.1

# Set variables
readonly IHS_OWNER="webihs"
readonly WEBTRACKING_HOME="/webtracking"
readonly IHS_HOME="/prod/IBM/HTTPServer"
readonly IHS_BIN_DIR="$IHS_HOME/bin"
readonly IHS_CONF_DIR="$IHS_HOME/conf.d"
readonly DOWNLOAD_URL="http://mdwservizio01.srv.sogei.it/WebTracking"
readonly SPLUNKFORWARDER_URL="$DOWNLOAD_URL/splunkforwarder.tgz"
readonly WEBTRACKING_BIN_URL="$DOWNLOAD_URL/webtracking-bin.zip"

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
  rm -f -- "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
  rm -f -- "$WEBTRACKING_HOME/update/webtracking-bin.zip"
  rm -f -- "${HOME}/apachectl_template"
  
  if [[ "$to_be_perform_cleanup" == true ]]
  then
    log "Cleanup: removing script $0"
    rm -f -- "$0"
  fi
}

# Call cleanup on exit, passing the exit code so it can skip on failure
trap 'cleanup "$?"' EXIT

version()
{
   echo "$(basename "$0") version $VERSION"
}

# Default behavior: if no options, print help and exit
UPDATE_SPLUNK=false
UPDATE_WEBTRACKING=false
UPDATE_TEMPLATE=false
SETUP=false
SHOW_HELP=true
SHOW_VERSION=false

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --splunkforwarder)
      UPDATE_SPLUNK=true
      SHOW_HELP=false
      shift
      ;;
    --webtracking)
      UPDATE_WEBTRACKING=true
      SHOW_HELP=false
      shift
      ;;
    --template)
      UPDATE_TEMPLATE=true
      SHOW_HELP=false
      shift
      ;;
    --all)
      UPDATE_SPLUNK=true
      UPDATE_WEBTRACKING=true
      UPDATE_TEMPLATE=true
      SHOW_HELP=false
      shift
      ;;
    --setup)
      SETUP=true
      SHOW_HELP=false
      shift
      ;;
    --no-auto-cleanup)
      to_be_perform_cleanup=false
      log "Auto cleanup disabled. The script will not remove itself after execution."
      shift
      ;;
    -h|--help)
      SHOW_HELP=true
      cleanup_to_be_perform=false
      shift
      ;;
    -v|--version)
      SHOW_VERSION=true
      SHOW_HELP=false
      cleanup_to_be_perform=false
      shift
      ;;
    *)
      echo "Unknown option: $1"
      cleanup_to_be_perform=false
      exit 1
      ;;
  esac
done


# If help, print help and exit
if [[ "$SHOW_HELP" == true ]]
then
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Options:
  --splunkforwarder    Update the Splunk Universal Forwarder
  --webtracking        Update the binaries of the web_tracking module
  --template           Update the Apache apachectl template
  --all                Perform all updates (equivalent to --splunkforwarder --webtracking --template)
  --setup              Perform initial setup (create folders, add cron jobs, etc.)
  --no-auto-cleanup    Do not remove the script itself after execution
  -h, --help           Print this help message
  -v, --version        Print the version number

If no options are provided, print help and exit.

Example usage:
  sh $(basename "$0") --all | tee manage.log
  sh $(basename "$0") --splunkforwarder --webtracking --template | tee manage.log
  sh $(basename "$0") --setup | tee manage.log
  sh $(basename "$0") --help
  sh $(basename "$0") --version

Note:
  If there are apachectl?* scripts not built using the apachectl_template,
  it is strongly recommended to create for each service a fake apachectl_<service> file 
  with just one line: IHS_CONFIGURATION_FILE=${IHS_HOME}/conf/<httpd_conf>.conf
  Where <httpd_conf> is the name of the corresponding httpd configuration file.

  For example, if the httpd configuration file is httpd_myservice.conf,
  create an apachectl_myservice file that contains the line:
  IHS_CONFIGURATION_FILE=${IHS_HOME}/conf/httpd_myservice.conf

  Alternatively and when for a service there is no existing apachectl?* script,
  it is possible to create a symbolic link to the corresponding apachectl-like script:
  ln -s ${IHS_HOME}/bin/myservice_ctl ${IHS_HOME}/bin/apachectl_myservice
EOF

  exit 0
fi

# If version, print version and exit
if [[ "$SHOW_VERSION" == true ]]
then
  version
  exit 0
fi

# Get apachectl files that match the given conf file (may be multiple)
get_apachectl_for_conf()
{
   local conf_file="$1"
   local filename=$(basename "$conf_file")
   
   # Get all httpd conf files that include this filename
   local httpd_conf_files=$(grep -l "$filename" "$IHS_HOME/conf/"*.conf)
   
   # For each httpd conf, find apachectl files that reference it
   for httpd_conf in $httpd_conf_files
   do
     local part_name=$(basename "$httpd_conf")
     grep -l "IHS_CONFIGURATION_FILE.*${part_name}" "$IHS_BIN_DIR"/apachectl* 2>/dev/null
   done | sort -u
}

# Check whether the current user is IHS_OWNER, if not, exit with error
if [[ "$(whoami)" != "$IHS_OWNER" ]]
then
  log "ERROR: The command was launched as the user $(whoami) and must have been run as the $IHS_OWNER user"
  exit 1
fi

# Print version
log "VERSION=$VERSION"

# If setup, print setup message, else print update message
if [[ $SETUP == true ]]
then
  log "Starting setup process"
else
  log "Starting update process"
fi

# Check prerequisites
if [[ "$SETUP" == true ]]
then
  if [[ ! -d "$IHS_HOME" ]]
  then
    log "ERROR: The folder $IHS_HOME does not exist"
    exit 1
  fi

  # The owner of the IHS_HOME directory must be IHS_OWNER
  IHS_OWNER_ACTUAL=$(stat -c '%U' "$IHS_HOME")
  if [[ "$IHS_OWNER_ACTUAL" != "$IHS_OWNER" ]]
  then
    log "ERROR: The owner of the $IHS_HOME directory is $IHS_OWNER_ACTUAL and must be $IHS_OWNER"
    exit 1
  fi

  if [[ ! -d "$WEBTRACKING_HOME" ]]
  then
    log "ERROR: The folder $WEBTRACKING_HOME does not exist"
    exit 1
  fi

  # The owner of the WEBTRACKING_HOME directory must be IHS_OWNER
  WEBTRACKING_ACTUAL_OWNER=$(stat -c '%U' "$WEBTRACKING_HOME")
  if [[ "$WEBTRACKING_ACTUAL_OWNER" != "$IHS_OWNER" ]]
  then
    log "ERROR: The owner of the $WEBTRACKING_HOME directory is $WEBTRACKING_ACTUAL_OWNER and must be $IHS_OWNER"
    exit 1
  fi
fi

if [[ "$UPDATE_TEMPLATE" == true || "$SETUP" == true ]]
then
  log "Downloading apachectl_template"
  curl "$DOWNLOAD_URL/apachectl_template" -o "${HOME}/apachectl_template"
fi

# Update apachectl files in IHS_BIN_DIR
if [[ ("$UPDATE_TEMPLATE" == true || "$SETUP" == true) && -f "${HOME}/apachectl_template" ]]
then
  log "Updating or installing apachectl files"
  for apachectl_file in "$IHS_BIN_DIR"/apachectl?*
  do
    if [[ -f "$apachectl_file" ]] && grep -q "^IHS_CONFIGURATION_FILE" "$apachectl_file"
    then
      log "Updating template for $apachectl_file"

      # Store the line beginning with IHS_CONFIGURATION_FILE
      ACTUAL_CONF_FILE=$(grep "^IHS_CONFIGURATION_FILE" "$apachectl_file")
      
      # Replace the file with the content of apachectl_template
      cp -p "${HOME}/apachectl_template" "$apachectl_file"

      # Set execute permissions         
      chmod +x "$apachectl_file"
      
      # Add the original IHS_CONFIGURATION_FILE line
      sed -i "/^IHS_CONFIGURATION_FILE/c\\$ACTUAL_CONF_FILE" "$apachectl_file"

      # version
      "$apachectl_file" --version | head -1 || true

      # status
      "$apachectl_file" status || true
    else
      log "Installing new apachectl template for $apachectl_file if it will find a corresponding conf file"

      # Search the corresponding conf file for this apachectl file
      conf_file=$(grep -Po "^[^#]+\s*\K$IHS_HOME/conf/\S+\.conf" "$apachectl_file" 2>/dev/null | head -1)
      if [[ -n "$conf_file" && -f "$conf_file" ]]
      then
        # Print the conf file being used
        log "Found corresponding conf file for $apachectl_file: $conf_file"

        # Replace old file with the content of apachectl_template
        cp -p "${HOME}/apachectl_template" "$apachectl_file"
        
        # Set IHS_CONFIGURATION_FILE line
        sed -i "/^IHS_CONFIGURATION_FILE/c\\IHS_CONFIGURATION_FILE=$conf_file" "$apachectl_file"

        # Set execute permissions
        chmod +x "$apachectl_file"

        # version
        "$apachectl_file" --version | head -1 || true

        # status
        "$apachectl_file" status || true
      else
        log "ERROR: Could not find a corresponding conf file for $apachectl_file."
        exit 1
      fi
    fi
  done
  
  # Remove the apachectl_template
  rm -f "${HOME}/apachectl_template"
fi

# Check whether exists the folder /webtracking
if [[ "$UPDATE_SPLUNK" == true || "$UPDATE_WEBTRACKING" == true || "$SETUP" == true ]]
then
  if [[ -d "$WEBTRACKING_HOME" ]]
  then
    if [[ "$SETUP" == true ]]
    then
      log "Setting up WebTracking environment for the first time"
      # Create necessary conf directory if it doesn't exist (option -p)
      mkdir -p "$IHS_CONF_DIR"
      
      # Create update directory if it doesn't exist  (option -p)
      mkdir -p "$WEBTRACKING_HOME/update"
    fi
    
    # Download files based on options
    if [[ "$UPDATE_SPLUNK" == true || "$SETUP" == true ]]
    then
      log "Downloading splunk universal forwarder binaries"
      curl "$SPLUNKFORWARDER_URL" -o "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
    fi
    
    if [[ "$UPDATE_WEBTRACKING" == true || "$SETUP" == true ]]
    then
      log "Downloading webtracking binaries"
      curl "$WEBTRACKING_BIN_URL" -o "$WEBTRACKING_HOME/update/webtracking-bin.zip"
    fi

    # Setup splunk universal forwarder and webtracking binaries if setup option is selected
    if [[ "$SETUP" == true && -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" && -f "$WEBTRACKING_HOME/update/webtracking-bin.zip" ]]
    then
      log "Setting up WebTracking environment for the first time"

      log "Installing splunk universal forwarder binaries"
      tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
      rm -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
      log "Starting splunk universal forwarder"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt

      # Setting up splunk universal forwarder deployment client
      log "Setting up splunk universal forwarder deployment client"
      echo '[target-broker:deploymentServer]' > "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
      echo 'targetUri = TRASPLMGLP01-03.srv.sogei.it:8089' >> "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
      cat "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
      
      log "Sleeping for 10 seconds before restarting splunk universal forwarder"
      sleep 10
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" restart
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" --version | tail -1 || true

      # Installing webtracking binaries
      log "Installing webtracking binaries"
      unzip -uo "$WEBTRACKING_HOME/update/webtracking-bin.zip" -d "$(dirname "$WEBTRACKING_HOME")"
      rm -f "$WEBTRACKING_HOME/update/webtracking-bin.zip"
      cat "$WEBTRACKING_HOME/bin/version.txt"

      # Reset UPDATE_SPLUNK and UPDATE_WEBTRACKING to false to avoid re-installing them in the next steps
      UPDATE_SPLUNK=false
      UPDATE_WEBTRACKING=false
    fi
    
    # Update splunk universal forwarder
    if [[ "$UPDATE_SPLUNK" == true && -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" ]]
    then
      log "Update splunk universal forwarder binaries"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop
      tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
      find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
      rm -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
      "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" --version | tail -1 || true
    fi
    
    # Update webtracking
    if [[ "$UPDATE_WEBTRACKING" == true && -f "$WEBTRACKING_HOME/update/webtracking-bin.zip" ]]
    then
      # Stop all webtracking services
      log "Stopping webtracking services"
      for conf_file in "$IHS_CONF_DIR"/webtracking*.conf
      do
        if [[ -f "$conf_file" ]]
        then
            apachectl_to_run=$(get_apachectl_for_conf "$conf_file")
            if [[ -n "$apachectl_to_run" ]]
            then
              while IFS= read -r apachectl_path; do
                log "$conf_file: $apachectl_path stop"
                "$apachectl_path" stop || true
              done <<EOF
$apachectl_to_run
EOF
            fi
        fi
      done
      
      # Update webtracking binaries
      log "Update webtracking binaries"
      unzip -uo "$WEBTRACKING_HOME/update/webtracking-bin.zip" -d "$(dirname "$WEBTRACKING_HOME")"
      rm -f "$WEBTRACKING_HOME/update/webtracking-bin.zip"
      cat "$WEBTRACKING_HOME/bin/version.txt"
      
      # Start all webtracking services
      log "Starting webtracking services"
      for conf_file in "$IHS_CONF_DIR"/webtracking*.conf
      do
        if [[ -f "$conf_file" ]]
        then
          apachectl_to_run=$(get_apachectl_for_conf "$conf_file")
          if [[ -n "$apachectl_to_run" ]]
          then
            while IFS= read -r apachectl_path; do
              log "$conf_file: $apachectl_path start"
              "$apachectl_path" start || true
              "$apachectl_path" status || true
            done <<EOF
$apachectl_to_run
EOF
          fi
        fi
      done
    fi
      
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
  else
    log "ERROR: The folder $WEBTRACKING_HOME does not exist"
    exit 1
  fi
fi

if [[ $SETUP == true ]]
then
  log "Setup process completed"
else
  log "Update process completed"
fi