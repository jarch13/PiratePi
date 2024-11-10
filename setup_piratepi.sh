#!/bin/bash

# Pirate Pi Setup Script
# This script sets up an offline file-sharing and chat server on a Raspberry Pi 5
# using an external USB Wi-Fi adapter.

# Run this script as root
# Usage: sudo bash setup_piratepi.sh

# Exit on any error
set -e

# Redirect output to a log file
exec > >(tee -i setup_piratepi.log)
exec 2>&1

echo "Starting Pirate Pi setup..."

# Ensure the script is run as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root using sudo."
  exit 1
fi

# Update and upgrade the system
echo "Updating system packages..."
apt-get update && apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
apt-get install -y hostapd dnsmasq nginx python3-pip python3-venv git clamav clamav-daemon ufw

# Stop services that might interfere during setup
systemctl stop hostapd
systemctl stop dnsmasq

# Identify the external USB Wi-Fi interface
echo "Detecting external USB Wi-Fi adapter..."

# List wireless interfaces
WIRELESS_INTERFACES=$(iw dev | awk '$1=="Interface"{print $2}')
ONBOARD_WIFI="wlan0"
EXTERNAL_WIFI=""

for iface in $WIRELESS_INTERFACES; do
  if [ "$iface" != "$ONBOARD_WIFI" ]; then
    EXTERNAL_WIFI="$iface"
    break
  fi
done

if [ -z "$EXTERNAL_WIFI" ]; then
  echo "No external USB Wi-Fi adapter found. Exiting."
  exit 1
fi

echo "External USB Wi-Fi adapter detected: $EXTERNAL_WIFI"

# Optionally disable onboard Wi-Fi
read -p "Do you want to disable the onboard Wi-Fi (wlan0)? (y/n): " DISABLE_WIFI
if [ "$DISABLE_WIFI" == "y" ] || [ "$DISABLE_WIFI" == "Y" ]; then
  echo "Disabling onboard Wi-Fi..."
  echo "dtoverlay=disable-wifi" >> /boot/config.txt
  systemctl disable wpa_supplicant.service
  echo "Onboard Wi-Fi disabled. A reboot is required for this change to take effect."
fi

# Prompt for SSID and passphrase
read -p "Enter the SSID for your access point (default: PiratePi): " SSID
SSID=${SSID:-PiratePi}

while true; do
  read -s -p "Enter the password for your access point (minimum 8 characters): " PASSPHRASE
  echo
  if [ ${#PASSPHRASE} -ge 8 ]; then
    break
  else
    echo "Password must be at least 8 characters long. Please try again."
  fi
done

# Configure static IP address for the Wi-Fi interface
echo "Configuring static IP address for $EXTERNAL_WIFI..."
cat >> /etc/dhcpcd.conf <<EOF

interface $EXTERNAL_WIFI
    static ip_address=192.168.4.1/24
    nohook wpa_supplicant
EOF

# Restart dhcpcd service
service dhcpcd restart

# Configure hostapd
echo "Configuring hostapd..."
cat > /etc/hostapd/hostapd.conf <<EOF
interface=$EXTERNAL_WIFI
driver=nl80211
ssid=$SSID
hw_mode=g
channel=7
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase=$PASSPHRASE
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
EOF

# Point hostapd to the configuration file
sed -i "s|#DAEMON_CONF=\"\"|DAEMON_CONF=\"/etc/hostapd/hostapd.conf\"|" /etc/default/hostapd

# Configure dnsmasq
echo "Configuring dnsmasq..."
mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig

cat > /etc/dnsmasq.conf <<EOF
interface=$EXTERNAL_WIFI
dhcp-range=192.168.4.2,192.168.4.20,255.255.255.0,24h
EOF

# Enable and start hostapd and dnsmasq
echo "Starting hostapd and dnsmasq services..."
systemctl unmask hostapd
systemctl enable hostapd
systemctl restart hostapd
systemctl restart dnsmasq

# Enable IP forwarding (not required since we're offline)
# echo "Enabling IP forwarding..."
# sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf
# sysctl -p

# Install and configure the Flask application
echo "Setting up the Flask application..."

# Create application directory
APP_DIR="/var/www/piratepi"
mkdir -p $APP_DIR
chown -R pi:www-data $APP_DIR
chmod -R 775 $APP_DIR

# Switch to application directory
cd $APP_DIR

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install wheel
pip install flask flask-socketio eventlet uwsgi

# Deactivate virtual environment
deactivate

# Create Flask app directory structure
echo "Creating application structure..."
mkdir -p $APP_DIR/{static/templates,uploads}

# Set ownership and permissions
chown -R pi:www-data $APP_DIR
chmod -R 775 $APP_DIR

# Create the Flask application file
cat > $APP_DIR/app.py <<'EOF'
from flask import Flask, render_template, request, redirect, url_for, send_from_directory, session
from flask_socketio import SocketIO, emit
import os
import subprocess
from markupsafe import escape

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 * 1024  # 10 GB limit

socketio = SocketIO(app, async_mode='eventlet')

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # Handle file upload
        file = request.files['file']
        if file:
            filename = file.filename
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Scan the file with ClamAV
            result = subprocess.run(['clamscan', file_path], stdout=subprocess.PIPE)
            scan_output = result.stdout.decode()

            if 'Infected files: 0' in scan_output:
                return redirect(url_for('uploaded_file', filename=filename))
            else:
                os.remove(file_path)
                return 'File is infected and has been removed.', 400
    return render_template('upload.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/files')
def list_files():
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    return render_template('files.html', files=files)

@app.route('/chat')
def chat():
    return render_template('chat.html')

@socketio.on('set_username')
def on_set_username(data):
    session['username'] = escape(data['username'])

@socketio.on('send_message')
def handle_send_message_event(data):
    data['username'] = session.get('username', 'Anonymous')
    emit('receive_message', data, broadcast=True)

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0')
EOF

# Create templates
echo "Creating HTML templates..."

# base.html
cat > $APP_DIR/templates/base.html <<'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{% block title %}Pirate Pi{% endblock %}</title>
    <link rel="stylesheet" href="{{ url_for('static', filename='css/styles.css') }}">
    <link id="theme-style" rel="stylesheet" href="{{ url_for('static', filename='css/default.css') }}">
    {% block head %}{% endblock %}
</head>
<body>
    {% block content %}{% endblock %}
    <script src="{{ url_for('static', filename='js/socket.io.js') }}"></script>
    <script src="{{ url_for('static', filename='js/script.js') }}"></script>
</body>
</html>
EOF

# index.html
cat > $APP_DIR/templates/index.html <<'EOF'
{% extends "base.html" %}
{% block title %}Home{% endblock %}
{% block content %}
<h1>Welcome to Pirate Pi</h1>
<nav>
    <a href="{{ url_for('upload_file') }}">Upload File</a>
    <a href="{{ url_for('list_files') }}">Download Files</a>
    <a href="{{ url_for('chat') }}">Chat</a>
</nav>
{% endblock %}
EOF

# upload.html
cat > $APP_DIR/templates/upload.html <<'EOF'
{% extends "base.html" %}
{% block title %}Upload File{% endblock %}
{% block content %}
<h1>Upload File</h1>
<form method="post" enctype="multipart/form-data">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>
{% endblock %}
EOF

# files.html
cat > $APP_DIR/templates/files.html <<'EOF'
{% extends "base.html" %}
{% block title %}Available Files{% endblock %}
{% block content %}
<h1>Available Files</h1>
<ul>
    {% for file in files %}
    <li><a href="{{ url_for('uploaded_file', filename=file) }}">{{ file }}</a></li>
    {% endfor %}
</ul>
{% endblock %}
EOF

# chat.html
cat > $APP_DIR/templates/chat.html <<'EOF'
{% extends "base.html" %}
{% block title %}Chat{% endblock %}
{% block content %}
<h1>Chat Room</h1>
<div id="chat-box"></div>
<input type="text" id="username" placeholder="Enter your nickname">
<input type="text" id="message" placeholder="Type your message">
<button id="send-btn">Send</button>
<select id="theme-selector">
    <option value="default">Default</option>
    <option value="neon">Neon</option>
    <option value="dark">Dark</option>
</select>
{% endblock %}
EOF

# Create static files
echo "Creating static files..."

# styles.css
mkdir -p $APP_DIR/static/css
cat > $APP_DIR/static/css/styles.css <<'EOF'
body {
    background-color: #0f0f0f;
    color: #00ff99;
    font-family: 'Courier New', Courier, monospace;
}

a {
    color: #00ccff;
}

nav a {
    margin-right: 15px;
}

input, button, select {
    background-color: #1a1a1a;
    color: #00ff99;
    border: none;
    padding: 10px;
}

#chat-box {
    background-color: #1a1a1a;
    height: 300px;
    overflow-y: scroll;
    padding: 10px;
    margin-bottom: 10px;
}
EOF

# default.css
cat > $APP_DIR/static/css/default.css <<'EOF'
/* Default theme */
EOF

# neon.css
cat > $APP_DIR/static/css/neon.css <<'EOF'
/* Neon theme */
body {
    background-color: #000000;
    color: #39ff14;
}

a {
    color: #ff073a;
}

input, button, select {
    background-color: #000000;
    color: #39ff14;
}
EOF

# dark.css
cat > $APP_DIR/static/css/dark.css <<'EOF'
/* Dark theme */
body {
    background-color: #121212;
    color: #e0e0e0;
}

a {
    color: #bb86fc;
}

input, button, select {
    background-color: #1f1f1f;
    color: #e0e0e0;
}
EOF

# script.js
mkdir -p $APP_DIR/static/js
cat > $APP_DIR/static/js/script.js <<'EOF'
document.addEventListener('DOMContentLoaded', () => {
    var socket = io();

    const sendBtn = document.getElementById('send-btn');
    const messageInput = document.getElementById('message');
    const usernameInput = document.getElementById('username');
    const chatBox = document.getElementById('chat-box');
    const themeSelector = document.getElementById('theme-selector');

    // Load saved theme
    const savedTheme = localStorage.getItem('theme') || 'default';
    themeSelector.value = savedTheme;
    document.getElementById('theme-style').setAttribute('href', `/static/css/${savedTheme}.css`);

    themeSelector.onchange = () => {
        const theme = themeSelector.value;
        document.getElementById('theme-style').setAttribute('href', `/static/css/${theme}.css`);
        localStorage.setItem('theme', theme);
    };

    sendBtn.onclick = () => {
        const message = messageInput.value;
        const username = usernameInput.value || 'Anonymous';
        socket.emit('set_username', {'username': username});
        socket.emit('send_message', {'message': message});
        messageInput.value = '';
    };

    socket.on('receive_message', (data) => {
        const newMessage = document.createElement('p');
        newMessage.innerHTML = `<strong>${data.username}:</strong> ${data.message}`;
        chatBox.appendChild(newMessage);
        chatBox.scrollTop = chatBox.scrollHeight;
    });
});
EOF

# Download Socket.IO client library
echo "Downloading Socket.IO client library..."
wget https://cdnjs.cloudflare.com/ajax/libs/socket.io/2.3.0/socket.io.js -O $APP_DIR/static/js/socket.io.js

# Set permissions
chown -R pi:www-data $APP_DIR
chmod -R 775 $APP_DIR

# Configure uWSGI
echo "Configuring uWSGI..."
cat > $APP_DIR/piratepi.ini <<EOF
[uwsgi]
module = app:app
master = true
processes = 5
socket = /var/www/piratepi/piratepi.sock
chmod-socket = 660
vacuum = true
die-on-term = true
enable-threads = true
plugin = python3
virtualenv = /var/www/piratepi/venv
EOF

# Create systemd service for uWSGI
echo "Creating uWSGI systemd service..."
cat > /etc/systemd/system/uwsgi.service <<EOF
[Unit]
Description=uWSGI instance to serve Pirate Pi
After=network.target

[Service]
User=pi
Group=www-data
WorkingDirectory=/var/www/piratepi
Environment="PATH=/var/www/piratepi/venv/bin"
ExecStart=/var/www/piratepi/venv/bin/uwsgi --ini piratepi.ini

[Install]
WantedBy=multi-user.target
EOF

# Start and enable uWSGI service
systemctl daemon-reload
systemctl start uwsgi
systemctl enable uwsgi

# Configure Nginx
echo "Configuring Nginx..."
rm /etc/nginx/sites-enabled/default

cat > /etc/nginx/sites-available/piratepi <<EOF
server {
    listen 443 ssl;
    server_name 192.168.4.1;

    ssl_certificate /etc/ssl/certs/piratepi.crt;
    ssl_certificate_key /etc/ssl/private/piratepi.key;

    location / {
        include uwsgi_params;
        uwsgi_pass unix:/var/www/piratepi/piratepi.sock;
    }

    location /static {
        alias /var/www/piratepi/static;
    }
}
EOF

ln -s /etc/nginx/sites-available/piratepi /etc/nginx/sites-enabled/

# Generate self-signed SSL certificate
echo "Generating self-signed SSL certificate..."
mkdir -p /etc/ssl/private
openssl req -new -x509 -days 365 -nodes -out /etc/ssl/certs/piratepi.crt -keyout /etc/ssl/private/piratepi.key -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=192.168.4.1"

# Adjust permissions
chmod 600 /etc/ssl/private/piratepi.key

# Restart Nginx
systemctl restart nginx

# Update ClamAV and start the daemon
echo "Updating ClamAV database..."
freshclam

echo "Starting ClamAV daemon..."
systemctl start clamav-daemon
systemctl enable clamav-daemon

# Configure UFW firewall (optional)
echo "Configuring UFW firewall..."
ufw allow 443/tcp
ufw --force enable

# Finalize
echo "Setup complete! Rebooting system..."
reboot
