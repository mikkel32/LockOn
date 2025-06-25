# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.box = "ubuntu/focal64"

  debug_port = ENV.fetch("LOCKON_DEBUG_PORT", "5678")

  config.vm.provision "shell", inline: <<-SHELL
    apt-get update
    apt-get install -y python3 python3-pip
    cd /vagrant
    pip3 install -r requirements.txt || true
    pip3 install debugpy

    cat <<'EOF' >/etc/systemd/system/lockon-debug.service
    [Unit]
    Description=LockOn Debug Server
    After=network.target

    [Service]
    Type=simple
    WorkingDirectory=/vagrant
    ExecStart=/usr/bin/env LOCKON_DEBUG_PORT=#{debug_port} /usr/bin/python3 /vagrant/debug_server.py --port #{debug_port}
    Restart=on-failure

    [Install]
    WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable lockon-debug.service
    systemctl start lockon-debug.service
  SHELL

  config.vm.network "forwarded_port", guest: debug_port, host: debug_port

  config.vm.provider "virtualbox" do |vb|
    vb.memory = 2048
  end
end
