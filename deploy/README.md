## MMT Probe Service Script

* Copy the shell script into 

    sudo cp mmtprobe /etc/init.d

* Initialize the Service 

    sudo update-rc.d mmtprobe defaults

* Remove the service

    sudo update-rc.d -f mmtprobe remove

Then we can use

    sudo service mmtprobe start/stop

