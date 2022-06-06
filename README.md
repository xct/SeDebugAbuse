# SeDebugAbuse

Run: `SeDebugAbuse.exe <pid>`. This will inject shellcode (you have to copy it into the source) into a process & run it. 
When targeting a SYSTEM process and you have the SeDebug privilege it will run as SYSTEM even though you normally could not get a handle to a SYSTEM process. Note that some processes are protected (e.g. PID=4) and can not be used as a target. A good alternative is the spool service.
