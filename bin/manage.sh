# Authors: 
#    Andrea Minuto
#    Livia Cimini
#    Marcello Pirazzoli
#    GitHub Copilot
#    IBM Bob

# This script sets up or updates the WebTracking binaries and the Splunk Universal Forwarder.
# It performs the following steps:
# 1. Checks if the script is run as the webihs user.
# 2. Verifies the existence of the /webtracking directory.
# 3. Downloads the latest Splunk forwarder and WebTracking binaries.
# 4. Updates the apachectl files in the IHS bin directory.
# 5. Stops all WebTracking services.
# 6. Updates the Splunk forwarder and WebTracking binaries.
# 7. Restarts all WebTracking services.

# How to run:
# curl http://mdwservizio01.srv.sogei.it/WebTracking/manage.sh -o manage.sh
# sh manage.sh --all | tee manage.log
# sh manage.sh --splunkforwarder --webtracking --template | tee manage.log
# sh manage.sh --setup | tee manage.log
# sh manage.sh --help
# sh manage.sh --version
# rm manage.sh

# Note
# If no apachectl* file is built using the apachectl_template, 
# it is necessary to create a fake apachectl_<service> file with just one line
# IHS_CONFIGURATION_FILE=/prod/IBM/HTTPServer/conf.d/httpd_<service>.conf

# Version
VERSION=2026.4.23.1

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
    -h|--help)
      SHOW_HELP=true
      shift
      ;;
    -v|--version)
      SHOW_VERSION=true
      SHOW_HELP=false
      shift
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

# If help, print help and exit
if [[ "$SHOW_HELP" == true ]]
then
  echo "Usage: $0 [OPTIONS]"
  echo ""
  echo "Options:"
  echo "  --splunkforwarder    Update the Splunk Universal Forwarder"
  echo "  --webtracking        Update the binaries of the web_tracking module"
  echo "  --template           Update the Apache apachectl template"
  echo "  --all                Perform all updates (equivalent to --splunkforwarder --webtracking --template)"
  echo "  --setup              Perform initial setup (create folders, add cron jobs, etc.)"
  echo "  -h, --help           Print this help message"
  echo "  -v, --version        Print the version number"
  echo ""
  echo "If no options are provided, print help and exit."
  exit 0
fi

# If version, print version and exit
if [[ "$SHOW_VERSION" == true ]]
then
  echo "WebTracking Update or Setup Script Version: $VERSION"
  exit 0
fi

# Set variables
IHS_OWNER="webihs"
WEBTRACKING_HOME="/webtracking"
IHS_HOME="/prod/IBM/HTTPServer"
IHS_BIN_DIR="$IHS_HOME/bin"
IHS_CONF_DIR="$IHS_HOME/conf.d"
DOWNLOAD_URL="http://mdwservizio01.srv.sogei.it/WebTracking"
SPLUNKFORWARDER_URL="$DOWNLOAD_URL/splunkforwarder.tgz"
WEBTRACKING_BIN_URL="$DOWNLOAD_URL/webtracking-bin.zip"

# log function
log()
{
   # Extract hour in 00–23
   local h=$(date +%H)

   # Milliseconds from nanoseconds
   local ms=$(date +%N | cut -c1-3)

   # Output matching the format: yyyy-MM-dd HH:mm:ss:SSS z
   printf '[%s]: %s\n' "$(date +%Y-%m-%d) $h:$(date +%M):$(date +%S):$ms $(date +%Z)" "$*"
}

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

# Check whether the current user is webihs
if [[ "$(whoami)" != "$IHS_OWNER" ]]
then
  log "ERROR: The command was launched as the user $(whoami) and must have been run as the $IHS_OWNER user"
  exit 1
fi

# Check whether exists the folder /webtracking
if [[ -d "$WEBTRACKING_HOME" ]]
then
  if [[ $SETUP == false ]]
  then
    log "WebTracking Update Script Version: $VERSION"
  else
    log "WebTracking Setup Script Version: $VERSION"
    
    # Create necessary directory
    mkdir -p "$IHS_CONF_DIR"
  fi
  
  # Create update directory if it doesn't exist
  mkdir -p "$WEBTRACKING_HOME/update"
  
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
  
  if [[ "$UPDATE_TEMPLATE" == true || "$SETUP" == true ]]
  then
    log "Downloading apachectl_template"
    curl "$DOWNLOAD_URL/apachectl_template" -o "$WEBTRACKING_HOME/update/apachectl_template"
  fi
  
  # Update apachectl files in IHS_BIN_DIR
  if [[ ("$UPDATE_TEMPLATE" == true || "$SETUP" == true) && -f "$WEBTRACKING_HOME/update/apachectl_template" ]]
  then
    log "Updating apachectl files"
    for apachectl_file in "$IHS_BIN_DIR"/apachectl*
    do
      if [[ -f "$apachectl_file" ]] && grep -q "^IHS_CONFIGURATION_FILE" "$apachectl_file"
      then
        log "Updating $apachectl_file"

        # Store the line beginning with IHS_CONFIGURATION_FILE
        ACTUAL_CONF_FILE=$(grep "^IHS_CONFIGURATION_FILE" "$apachectl_file")
        
        # Replace the file with the content of apachectl_template
        cp -p "$WEBTRACKING_HOME/update/apachectl_template" "$apachectl_file"

        # Set execute permissions         
        chmod +x "$apachectl_file"
        
        # Add back the original IHS_CONFIGURATION_FILE line
        sed -i "/^IHS_CONFIGURATION_FILE/c\\$ACTUAL_CONF_FILE" "$apachectl_file"

        # version
        "$apachectl_file" --version | head -1 || true

        # status
        "$apachectl_file" status || true
      fi
    done
    
    # Remove the apachectl_template
    rm -f "$WEBTRACKING_HOME/update/apachectl_template"
  fi

  # Setup splunk universal forwarder and webtracking binaries if setup option is selected
  if [[ "$SETUP" == true && -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" && -f "$WEBTRACKING_HOME/update/webtracking-bin.zip" ]]
  then
    log "Setting up WebTracking environment for the first time"

    log "Creating necessary directories"
    mkdir -p "$IHS_HOME/conf.d"

    log "Installing splunk universal forwarder binaries"
    tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
    rm -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
    log "splunk user: admin, password: admin1234"
    "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license

    # Setting up splunk universal forwarder deployment client
    log "Setting up splunk universal forwarder deployment client"
    echo '[target-broker:deploymentServer]' > "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
    echo 'targetUri = TRASPLMGLP01-03.srv.sogei.it:8089' >> "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
    cat "$WEBTRACKING_HOME/splunkforwarder/etc/system/local/deploymentclient.conf"
    
    log "Sleeping for 15 seconds before restarting splunk universal forwarder"
    sleep 15
    "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" restart

    # Installing webtracking binaries
    log "Installing webtracking binaries"
    unzip -uo "$WEBTRACKING_HOME/update/webtracking-bin.zip" -d "$(dirname "$WEBTRACKING_HOME")"
    rm -f "$WEBTRACKING_HOME/update/webtracking-bin.zip"
    cat "$WEBTRACKING_HOME/bin/version.txt"
  fi
  
  # Update splunk universal forwarder
  if [[ "$UPDATE_SPLUNK" == true && -f "$WEBTRACKING_HOME/update/splunkforwarder.tgz" ]]
  then
    log "Update splunk universal forwarder binaries"
    "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" stop
    tar xaf "$WEBTRACKING_HOME/update/splunkforwarder.tgz" -C "$WEBTRACKING_HOME"
    "$WEBTRACKING_HOME/splunkforwarder/bin/splunk" start --accept-license --answer-yes --no-prompt
    find -L "$WEBTRACKING_HOME/splunkforwarder" -type l -exec rm -v {} \;
    rm -fv "$WEBTRACKING_HOME/update/splunkforwarder.tgz"
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
    
    log "Add check.sh to crontab if not already present"
    (crontab -l 2>/dev/null | grep -q "/webtracking/bin/check.sh") || \
    (crontab -l 2>/dev/null; \
    crontab -l 2>/dev/null | grep -q . && echo ""; \
    echo "# Check splunkd process and stale files"; \
    echo "*/15 * * * * /webtracking/bin/check.sh") | \
    crontab -
    crontab -l | grep -B1 "/webtracking/bin/check.sh"
  fi

  if [[ $SETUP == false ]]
  then
    log "WebTracking update process completed"
  else
    log "WebTracking setup process completed"
  fi
else
  log "ERROR: The folder $WEBTRACKING_HOME does not exist"
  exit 1
fi
