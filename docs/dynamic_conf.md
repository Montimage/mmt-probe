This document is applicable when MMT-Probe is built with option `DYNAMIC_CONFIG_MODULE`.

Dynamic configuration is enable or disable by `dynamic-config.enable` option when running in online mode.
It is automatically disabled when starting MMT-Probe in offline mode.


# Architecture

MMT-Probe creates 2 children processes:

- `processing process`: this this main processing of MMT-Probe
- `control process`: it receives control commands via an UNIX domain socket, check them, then broadcast them to the other processes. The location of the UNIX domain socket is defined by `dynamic-config.descriptor` parameter.

There are totally 3 processes: 2 children + dispatcher (main).

The dispatch monitors their children, and re-create a child if it has crashed. It receives also a command from the `control process` to start or stop the `processing process`.

# Commands

The commands are represented using plain text, lower case.
A command is terminated by '\0' character.




## `start`

Start main processing

### Result

- O if successfully
- 1 if main processing is running
- 2 if error

### Example:

```
printf "start\0" | sudo nc -U /tmp/mmt.sock
```

## `stop`

Stop main processing.

### Result

- 0 if successfully
- 1 if main processing is not running
- 2 if error 

```
printf "stop\0" | sudo nc -U /tmp/mmt.sock
```

## `update`

Update parameters.
There are no space between identities.

### Syntax


```
command   := `update{` new_line (parameter)+ new_line `}`
new_line  := `\n`
parameter := identity `=` (string | boolean | number )
boolean   := `true` | `false`
string    := (.+)
number    := [0-9]+
```


### Result:

- 0 if successfully without need to restart the main processing
- 1 if successfully after restarting the main processing
- 2 if syntax error
- 3 if internal error (cannot update) 

### Example:

```
printf 'update{\ninput.source="enp0s3"\ninput.mode=ONLINE\n}\0' | sudo nc -U /tmp/mmt.sock
```

## `ls`

Get the list of parameters

### Example:

```
printf 'ls\0' | sudo nc -U /tmp/mmt.sock
```
