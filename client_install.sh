#!/bin/bash

OS="$(uname)"
USERNAME="${SUDO_USER:-$(whoami)}"

USERID="$(id -u $USERNAME)"
GROUPID="$(id -g $USERNAME)"

echo "Installing as user: $USERNAME with uid=$USERID, gid=$GROUPID"

if [[ "$OS" == "Darwin" ]]; then
    echo "Installing on macOS..."

    echo "Setting up launchd plist..."
    sed "s/__UID__/$USERID/g; s/__GID__/$GROUPID/g" veil-client.plist.template > /Library/LaunchDaemons/com.veil.client.plist
    cp ./client-service/target/debug/client-service /usr/local/bin/veil-client-service

    echo "Creating veil environment"
    mkdir -p /etc/veil
    mkdir -p /etc/veil/certs
    
    if [ -f "/etc/veil/veil.conf" ]; then
        echo "Found preexisting configuration file."
    else
        echo "Creating configuration file"
        touch /etc/veil/veil.conf && echo -e "servers {\n}" >> /etc/veil/veil.conf
    fi

    # echo "Loading plist"
    # launchctl load /Library/LaunchDaemons/com.veil.client.plist

    echo "Installing CLI/CTL tool"
    cp ./cli/target/debug/cli /usr/local/bin/veil-cli
    cp ./cli/veilctl.sh /usr/local/bin/veilctl
elif [[ "$OS" == "Linux" ]]; then
    echo "Installing for linux system..."

    echo "Setting up systemd service..."
    sed "s/__ID__/$USERID $GROUPID/" veil.service.template > /etc/systemd/system/veil.service
    cp ./client-service/target/debug/client-service /bin/veil-client-service
    
    echo "Creating veil environment"
    mkdir -p /etc/veil
    mkdir -p /etc/veil/certs
    
    if [ -f "/etc/veil/veil.conf" ]; then
        echo "Found preexisting configuration file."
    else
        echo "Creating configuration file"
        touch /etc/veil/veil.conf && echo -e "servers {\n}" >> /etc/veil/veil.conf
    fi
    
    echo "Reloading systemd"
    systemctl daemon-reexec
    systemctl daemon-reload
    
    echo "Activating service"
    systemctl enable veil.service
    systemctl start veil.service

    echo "Installing CLI/CTL tool"
    cp ./cli/target/debug/cli /bin/veil-cli
    cp ./cli/veilctl.sh /bin/veilctl
else
    echo "Unsupported OS: $OS"
    exit 1
fi
