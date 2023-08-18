lldb-trace
==========

Gives complete trace of a function execution including all sub-calls.

### Example use
* Attach to a process, for example to `SimpleTraceTarget` contained in this repository: ```$ lldb -p `pgrep SimpleTrace` ```
* Import the trace script: ```(lldb) command script import $DIR/trace.py```
* Stop the process execution at the root function you're interested in tracing, e.g. using breakpoints.
* Trace: ```(lldb) function-trace```
* Output: 
```
a + 0x1c ==> b
     b + 0xd ==> usleep
         usleep + 0x0 === usleep + 0x0
         usleep + 0x31 ==> nanosleep
             nanosleep + 0x0 === nanosleep + 0x0
             nanosleep + 0x25 ==> pthread_testcancel
                 pthread_testcancel + 0x0 === pthread_testcancel + 0x0
                 pthread_testcancel + 0x20 === _pthread_testcancel + 0x0
                 _pthread_testcancel + 0x17 ==> OSSpinLockLock
                     OSSpinLockLock + 0x0 === _spin_lock + 0x0
                 _pthread_testcancel + 0x1c <==
                 _pthread_testcancel + 0x22 ==> OSSpinLockUnlock
                     OSSpinLockUnlock + 0x0 === _spin_unlock + 0x0
                 _pthread_testcancel + 0x27 <==
             nanosleep + 0x2a <==
             nanosleep + 0xc3 ==> __semwait_signal
                 __semwait_signal + 0x0 === __semwait_signal + 0x0
                 Syscall 0x000000000200014e
                 __semwait_signal + 0xf === cerror + 0x0
                 cerror + 0x8 ==> _pthread_exit_if_canceled
                     _pthread_exit_if_canceled + 0xa === _pthread_exit_if_canceled + 0x0
                 cerror + 0xd <==
                 cerror + 0xf ==> cerror_nocancel
                 cerror + 0x14 <==
             nanosleep + 0xc8 <==
             nanosleep + 0xcc ==> __error
                 __error + 0x0 === __error + 0x0
             nanosleep + 0xd1 <==
         usleep + 0x36 <==
     b + 0x12 <==
 a + 0x21 <==
 ```
 where `==>` denotes call to a function, `===` jmp to a different symbol, `<==` is a return, `Syscall ID` is where a syscall of a given `ID` is executed.
 
### Help
 `(lldb) function-trace -h` gives a list of options `function-trace` accepts, currently:
 ```
Options:
  -h, --help            show this help message and exit
  -v, --verbose         Produce verbose output, useful for debugging
  -f FILE, --file=FILE  Redirect output to the specified file
  -s, --stdout          Log to stdout directly, which is against lldb policy,
                        but produces incremental output (flush works)
  -m, --module-only     Trace only in the module where root symbol was defined
  ```
 
### More advanced usage
 * `function-trace` can trace any symbol in the current execution backtrace. Select the desired frame with `(lldb) frame select FRAME_ID` before executing `function-trace`
 * Long-running `function-trace` doesn't produce any output by default, until the command execution is finished (seems to be by design). `function-trace` makes it possible to produce incremental output by either outputing to a specified file `(lldb) function-trace -f FILE` or by outputting directly to stdout (this may not always work properly since it's against the LLDB's policy) `(lldb) function-trace -s`
 * If you're not interested in calling external symbols (external to the binary module in which the root symbol is defined) use `(lldb) function-trace -m`. Every time extrenal symbol is detected appropriate message (such as `Not instrumenting since module X isn't the same as Y`) will be printed.
 
### Debugging
* Verbose output is available with `(lldb) function-trace -v`
* If tracing fails, some of the breakpoints established for tracing may be left over. They are usually easy to distinguish from other breakpoinst since they are per thread (`Options: enabled tid: X`). All breakpoints can be deleted with `(lldb) breakpoint delete`
* `Ctrl-C` in LLDB session should stop the tracing, in some circumstances however (if the program managed to break-out from the `function-trace`'s control), tracing may have to be stopped by sending the target process a singnal (e.g. `$ pkill X`).

### TODOs
* `(lldb) function-trace -m` should give an ability to trace over `objc_sendMsg`
* LLDB config for autoimporting
* wrapper script for running from breakpoint command (`breakpoint command add -F trace.trace_wrapper ID`)
 
