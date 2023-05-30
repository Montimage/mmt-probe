# Configuration File

The configuration of MMT-Probe is defined in a file. This file is given to MMT-Probe via `-c` option of running command. 

If user does not give `-c` option, MMT-Probe will try to  find the configuration in `./mmt-probe.conf` in the current folder (where you are starting MMT-Probe).

If it does not find or there exist (syntax) errors in the file, then MMT-Probe will try to find in `/opt/mmt/probe/mmt-probe.conf`.

If no configuration file is found, MMT-Probe will stop its execution.

# Configuration Parameters

- `nb-thread` : 0 to disable multi-threading. There exists only one worker. The worker will be executed on the main thread.

   otherwise, `n` workers will be executed on `n` separate threads. The main thread will read packets then dispatch the packets to workers.  
   
   
## `socket-output.type`
new from v1.5.11:

- `TCP`
- `UDP`
- `UNIX`
- `BOTH` = `TCP` + `UNIX`


## `event-report`

- `output-format`: Define the format of the output reports. If this parameter is present, then attribute `attributes` must not be present.
For example, if you want to output source and destination of IP addresses in a JSON format, then, you can use the following `event-report`:

```
event-report ip {
	enable = true
	event  = "ip.src"
	output-format = '{"source": "ip.src", "destination": "ip.dst"}'
	output-channel = {socket, stdout}
}
```
MMT-Probe will replace `ip.src` and `ip.dst` by the values of `src` and `dst` attributes of `ip` protocol. The other characters in the `output-format` will be keep as-i in the output message of the reports.

Note: If `output-format` is present, then the format of the output messages do not respect any more to the general structure of the reports, that is, the first field is report ID, the second is probe ID, etc.