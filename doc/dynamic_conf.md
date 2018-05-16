
#Commands

The commands are represented using plain text, lower case.

## `start`

Start main processing

### Result

- O if successfully
- 1 if main processing is running
- 2 if error

## `stop`

Stop main processing.

### Result

- 0 if successfully
- 1 if main processing is not running
- 2 if error 


## `update`

Update parameters.
There are no space between identities.

### Syntax


command   := `update{` new_line (parameter)+ new_line `}`
parameter := identity `=` (string | boolean | number )
boolean   :=  `true` | `false`
string    :=  `"` (.+) `"`
number    := [0-9]+
   


```
update{
input.source="enp0s3"
input.mode="online"
security.enable=false
file-output.enable=true
file-output.retain-files=40
}
```
### Result:

- 0 if successfully without need to restart the main processing
- 1 if successfully after restarting the main processing
- 2 if syntax error
- 3 if internal error (cannot update) 