Vagrant.configure("2") do |config|

  config.vm.define "linux" do |linux|
    linux.vm.box = "generic/fedora32"

    linux.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = 2048
      vb.cpus = 2

      # VBoxVGA flickers constantly, use vmsvga instead which doesn't have that problem
      vb.customize ["modifyvm", :id, "--graphicscontroller", "vmsvga"]
    end

    # mount the project into /keyring
    linux.vm.synced_folder ".", "/keyring"

    # install golang
    linux.vm.provision "shell", inline: "sudo dnf install -y go"
  end


  config.vm.define "windows" do |windows|
    windows.vm.box = "StefanScherer/windows_10"

    windows.vm.provider "virtualbox" do |vb|
      vb.gui = true
      vb.memory = 2048
      vb.cpus = 2
    end

    # mount the project into c:\keyring
    windows.vm.synced_folder ".", "/keyring"

    # install chocolately
    windows.vm.provision "shell", privileged: true, inline: <<-SHELL
      Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
      choco feature disable -n=showDownloadProgress
    SHELL

    # install golang
    windows.vm.provision "shell", privileged: true, inline: "choco install -y git golang"
  end

  config.vm.post_up_message = <<-MESSAGE
    There are 2 vagrant boxes:
     - linux
       - OS: Fedora 32
       - The keyring directory is mounted at /keyring
       - Get a shell with 'vagrant ssh linux'
     - windows
       - OS: Windows 10
       - The keyring directory is mounted at C:\keyring
       - Get a shell by starting PowerShell in the GUI
       - You can run commands remotely using 'vagrant winrm -e windows CMD'.

    Automated scripts for running go test on vagrant boxes (run these locally):
     - ./bin/go-test-linux   - Run tests on Linux
     - ./bin/go-test-windows - Run tests on Windows
     - ./bin/go-test         - Run all tests - locally, linux and windows
  MESSAGE
end
