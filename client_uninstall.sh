$CONFIRMED=1
while [[ ! $CONFIRMED ]]; do
  read -rp "Are you sure you want to uninstall? Configuration and certificates will be removed (Y/n)" uninstall
  
  if [[ "$uninstall" == "Y" || "$uninstall" == "yes" ]]; then
    echo "Uninstall confirmed"
    break
  elif [[ "$uninstall" == "n" || "$uninstall" == "no" ]]; then
    echo "Uninstallation cancelled"
    exit 1
  else
    echo "Please enter 'Y'/'yes' to confirm or 'n'/'no' to cancel"
  fi
done

OS="$(uname)"
if [[ "$OS" == "Darwin" ]]; then
    echo "Running on macOS"
elif [[ "$OS" == "Linux" ]]; then
    echo "Uninstalling for linux system..."

    echo "Removing systemd service..."
    systemctl stop veil.service
    systemctl disable veil.service
    rm /etc/systemd/system/veil.service

    systemctl daemon-reload
    systemctl reset-failed
    
    echo "Removing veil environment"
    rm -rf /etc/veil

    echo "Removing binaries"
    rm /bin/veil-client-service /bin/veil-cli /bin/veilctl
else
    echo "Unsupported OS: $OS"
    exit 1
fi
