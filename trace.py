#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import threading
import time
import sys

options = None
log_file = None

def log(msg):
    global options
    global log_file
    log_file.write(msg)
    log_file.write('\n')

def log_v(msg):
    global options
    global log_file
    if options.verbose:
        log_file.write(msg)
        log_file.write('\n')

def log_flush():
    log_file.flush()

class MyListeningThread(threading.Thread):
    def __init__(self, wait_event, notify_event, listener, process):
        super(MyListeningThread, self).__init__()
        self.wait_event = wait_event
        self.notify_event = notify_event
        self.listener = listener
        self.process = process
        self.exiting = False
        self.wait_timeout = False

    def wait_timed_out(self):
        return self.wait_timeout

    def exit(self):
        self.exiting = True

    def run(self):
        while True:
            self.wait_event.wait()
            self.wait_event.clear()
            if self.exiting:
                log_v('Listener thread was asked to exit, complying')
                self.notify_event.set()
                return
            while True:
                event = lldb.SBEvent()
                wait_result = self.listener.WaitForEvent(10, event)

                if not wait_result:
                    log_v('Listener thread timed out waiting for notification')
                    self.wait_timeout = True
                    self.notify_event.set()
                    break
                if self.process.GetState() == lldb.eStateStopped:
                    break
                log_v('Process not stopped, listening for the next event')
            log_v('Listener thread got event, notifying')
            self.notify_event.set()

class InstrumentedFrame:
    def __init__(self, target, thread, frame):
        self.target = target
        self.thread = thread
        self.frame = frame
        self.return_breakpoint = None
        self.call_breakpoints = {}
        self.jmp_breakpoints = {}
        self.syscall_breakpoints = {}
        self.subsequent_instruction = {}

    def update_frame(self, frame):
        self.frame = frame

    def is_frame_valid(self):
        return self.frame.IsValid()

    def instrument_calls_syscalls_and_jmps(self):
        # TODO: symbols vs functions
        symbol = self.frame.GetSymbol()
        log_v("Instrumenting symbol: {}".format(str(symbol)))
        start_address = symbol.GetStartAddress().GetLoadAddress(self.target)
        end_address = symbol.GetEndAddress().GetLoadAddress(self.target)
        instruction_list = symbol.GetInstructions(self.target)
        previous_breakpoint_address = 0L
        for i in instruction_list:
            address = i.GetAddress().GetLoadAddress(self.target)
            #print >>self.result, '0x%x' % address
            #print >>self.result, '{}, {}, {}'.format(i.GetMnemonic(self.target), i.GetOperands(self.target), i.GetComment(self.target))
            if address in self.call_breakpoints or address in self.jmp_breakpoints:
                continue
            if previous_breakpoint_address != 0L:
                self.subsequent_instruction[previous_breakpoint_address] = address
                previous_breakpoint_address = 0L
            mnemonic = i.GetMnemonic(self.target)
            if mnemonic != None and mnemonic.startswith('call'):
                log_v('Putting breakpoint at 0x%lx' % address)
                breakpoint = self.target.BreakpointCreateByAddress(address)
                breakpoint.SetThreadID(self.thread.GetThreadID())
                self.call_breakpoints[address] = breakpoint
                previous_breakpoint_address = address
            if mnemonic != None and mnemonic.startswith('jmp'):
                try:
                    jmp_destination = int(i.GetOperands(self.target), 16)
                except:
                    jmp_destination = 0L;

                if jmp_destination < start_address or jmp_destination >= end_address:
                    breakpoint = self.target.BreakpointCreateByAddress(address)
                    breakpoint.SetThreadID(self.thread.GetThreadID())
                    self.jmp_breakpoints[address] = breakpoint
            if mnemonic != None and mnemonic.startswith('syscall'):
                breakpoint = self.target.BreakpointCreateByAddress(address)
                breakpoint.SetThreadID(self.thread.GetThreadID())
                self.syscall_breakpoints[address] = breakpoint

    def clear_calls_instrumentation(self):
        for breakpoint in self.call_breakpoints.itervalues():
            self.target.BreakpointDelete(breakpoint.GetID())
        self.call_breakpoints = {}
        self.subsequent_instruction = {}

    def clear_syscall_instrumentation(self):
        for breakpoint in self.syscall_breakpoints.itervalues():
            self.target.BreakpointDelete(breakpoint.GetID())
        self.syscall_breakpoints = {}

    def clear_jmps_instrumentation(self):
        for breakpoint in self.jmp_breakpoints.itervalues():
            self.target.BreakpointDelete(breakpoint.GetID())
        self.jmp_breakpoints = {}

    def clear_return_breakpoint(self):
        self.target.BreakpointDelete(self.return_breakpoint.GetID())
        self.return_breakpoint == None

    def is_stopped_on_call(self, frame):
        if not self.frame.IsValid() or frame.GetFrameID() != self.frame.GetFrameID():
            log_v("A Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID()))
            return False

        stop_address = frame.GetPC()
        return stop_address in self.call_breakpoints

    def is_stopped_on_syscall(self, frame):
        if not self.frame.IsValid() or frame.GetFrameID() != self.frame.GetFrameID():
            log_v("D Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID()))
            return False

        stop_address = frame.GetPC()
        return stop_address in self.syscall_breakpoints

    def is_stopped_on_jmp(self, frame, validate_saved_frame):
        if validate_saved_frame and (not self.frame.IsValid() or frame.GetFrameID() != self.frame.GetFrameID()):
            log_v("B Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID()))
            return False

        stop_address = frame.GetPC()
        return stop_address in self.jmp_breakpoints

    def is_stopped_on_return(self, frame):
        if not self.frame.IsValid() or frame.GetFrameID() != self.frame.GetFrameID():
            log_v("C Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID()))
            return False

        if self.return_breakpoint == None:
            return False

        stop_address = frame.GetPC()
        return self.return_address == stop_address

    def instrument_return(self, return_address):
        self.return_address = return_address
        self.return_breakpoint = self.target.BreakpointCreateByAddress(self.return_address)
        self.return_breakpoint.SetThreadID(self.thread.GetThreadID())

    def clear_calls_syscalls_and_jmps_and_instrument_return(self, frame):
        stop_address = frame.GetPC()
        if not stop_address in self.subsequent_instruction:
            log("Couldn't find subsequent instruction")
            return False
        self.instrument_return(self.subsequent_instruction[stop_address])
        self.clear_calls_instrumentation()
        self.clear_syscall_instrumentation()
        self.clear_jmps_instrumentation()
        return True

    def clear(self):
        if self.call_breakpoints != None:
            self.clear_calls_instrumentation()
        if self.syscall_breakpoints != None:
            self.clear_syscall_instrumentation()
        if self.jmp_breakpoints != None:
            self.clear_jmps_instrumentation()
        if self.return_breakpoint != None:
            self.clear_return_breakpoint()

class TraceOptionParser(optparse.OptionParser):
    def __init__(self, result):
        optparse.OptionParser.__init__(self)
        self.result = result
        self.exited = False

    def get_prog_name(self):
        return "trace"

    def exit(self, status=0, msg=None):
        if msg != None:
            print >>self.result, msg
        self.exited = True

def parse_options(command, result):
    global options
    global log_file
    command_tokens = shlex.split(command)
    parser = TraceOptionParser(result)
    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False, help="Produce verbose output, useful for debugging")
    parser.add_option("-f", "--file", dest="filename", metavar="FILE", help="Redirect output to the specified file")
    parser.add_option("-s", "--stdout", action="store_true", dest="stdout", default=False, help="Log to stdout directly, which is against lldb policy, but produces incremental output (flush works)")
    parser.add_option("-m", "--module-only", action="store_true", dest="module_only", default=False, help="Trace only in the module where root symbol was defined")
    parser.add_option("--follow-symbol", action="append", dest="symbol_whitelist", metavar="SYMBOL_SUBSTRING", help="Trace symbol even if wouldn't be otherwised traced due to other limitations")
    (options, _) = parser.parse_args(command_tokens)
    if options.filename != None:
        log_file = open(options.filename, 'w')
    elif options.stdout:
        log_file = sys.stdout
    else:
        log_file = result
    return parser.exited

def continue_and_wait_for_breakpoint(process, thread, listening_thread, wait_event, notify_event):
    log_v("Process in state: {}".format(str(process.GetState())))
    process.Continue()
    wait_event.set()
    log_v('Process continued, waiting for notification')
    notify_event.wait()
    notify_event.clear()
    log_v('Got notification, process in state: {}, sanity checks follow'.format(str(process.GetState())))
    # Some sanity checking
    if listening_thread.wait_timed_out():
        log_v('Listener thread exited unexpectedly')
        return False
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        log_v("Thread {} didn't stop due to a breakpoint".format(str(thread)))
        return False
    return True

def get_pc_addresses(thread):
    def GetPCAddress(i):
        return thread.GetFrameAtIndex(i).GetPCAddress()

    return map(GetPCAddress, range(thread.GetNumFrames()))

def print_stacktrace(target, thread):
    depth = thread.GetNumFrames()
    addrs = get_pc_addresses(thread)
    for i in range(depth):
        frame = thread.GetFrameAtIndex(i)
        function = frame.GetFunction()

        load_addr = addrs[i].GetLoadAddress(target)
        if not function:
            file_addr = addrs[i].GetFileAddress()
            start_addr = frame.GetSymbol().GetStartAddress().GetFileAddress()
            symbol_offset = file_addr - start_addr
            log_v('  frame #{num}: {addr:#016x} `{symbol} + {offset}'.format(num=i, addr=load_addr, symbol=frame.GetSymbol().GetName(), offset=symbol_offset))
        else:
            log_v('  frame #{num}: {addr:#016x} `{func}'.format(num=i, addr=load_addr, func=frame.GetFunctionName()))

def trace(debugger, command, result, internal_dict):
    """
    Traces execution of the symbol in the currently selected frame.
        trace -h/--help, for full help
    """
    global options
    if parse_options(command, result):
        return

    log_v("arguments: {}".format(str(options)))

    wait_event = threading.Event()
    wait_event.clear()
    notify_event = threading.Event()
    notify_event.clear()

    target = debugger.GetSelectedTarget()
    log_v("Target: {}".format(str(target)))
    process = target.GetProcess()
    log_v("Process: {}".format(str(process)))
    broadcaster = process.GetBroadcaster()
    log_v("Broadcaster: {}".format(str(broadcaster)))
    listener = lldb.SBListener("trace breakpoint listener")
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    if not rc:
        log('Failed to add listener')

    my_thread = MyListeningThread(wait_event, notify_event, listener, process)
    my_thread.start()
    thread = process.GetSelectedThread()
    log_v("Thread: {}".format(str(thread)))

    instrumented_frames = []
    frame = thread.GetSelectedFrame()
    module = frame.GetModule()
    # Instrument parent frame's return, so that we can detect when to terminate tracing
    parent_frame = thread.GetFrameAtIndex(frame.GetFrameID() + 1)
    if parent_frame != None:
        instrumented_frame = InstrumentedFrame(target, thread, parent_frame)
        instrumented_frame.instrument_return(parent_frame.GetPC())
        instrumented_frames.append(instrumented_frame)

    depth = 0
    spacer = '    '
    instrumented_frame = None
    while True:
        if instrumented_frame == None:
            if not options.module_only or frame.GetModule() == module:
                instrumented_frame = InstrumentedFrame(target, thread, frame)
                instrumented_frame.instrument_calls_syscalls_and_jmps()
            else:
                log("symbol: {} in different module".format(frame.GetSymbol().GetName()))

        log_v('Running the process')
        # Continue running until next breakpoint is hit, _unless_ PC is already on a breakpoint address
        if instrumented_frame == None or (not instrumented_frame.is_stopped_on_call(frame) and not instrumented_frame.is_stopped_on_syscall(frame) and not instrumented_frame.is_stopped_on_jmp(frame, True)):
            success = continue_and_wait_for_breakpoint(process, thread, my_thread, wait_event, notify_event)
            if not success:
                log_v("Failed to continue+stop the process")
                break

        frame = thread.GetFrameAtIndex(0)
        log_v("=================== Stopped at: ====================")
        log_v("Frame: {}, symbol: {}, pc: {pc:#x}".format(str(frame), str(frame.GetSymbol()), pc=frame.GetPC()))
        log_flush()
        #print_stacktrace(target, thread)

        if len(instrumented_frames) > 0:
            parent_instrumented_frame = instrumented_frames[-1]
        else:
            parent_instrumented_frame = None

        # Check for return from call first, then for call and finally for jmp.
        # That way, we can be lenient about checking whether the frame saved
        # in the jmp instrumented frame is still valid.
        # This is difficult in case of optimised calls, where call instruction
        # is replaced with:
        #     popq   %rbp
        #     jmpq   $destination
        # (this optimisation is used in tail recursion optimisation and
        #  tail returns of the same type, where the compiler can squash
        #  one frame away)
        # Since this optimisation pops %rbp (which then gets pushed in the
        # preamble of $destination), at the time of jmp, the caller frame
        # isn't really present. This has the effect of invalidating SBFrame
        # stored by the current instrumented_frame.
        # Taking the above into account, the best we can do is to check for
        # return first and if that's not the case, we know we must be in the
        # same logical frame, therefore when checking for jmps, it's enough
        # to verify the address.
        if parent_instrumented_frame != None and parent_instrumented_frame.is_stopped_on_return(frame):
            log_v("Stopped on return, popping a frame")
            depth = depth - 1
            destination = frame.GetSymbol().GetName()
            offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            log("{} {destination} + {offset:#x} <==".format(spacer * depth, destination=destination, offset=offset))
            if instrumented_frame != None:
                instrumented_frame.clear()
            instrumented_frame = instrumented_frames.pop()
            instrumented_frame.clear_return_breakpoint()
            if len(instrumented_frames) == 0:
                log_v("Detected return from the function under trace, exiting")
                break
            instrumented_frame.instrument_calls_syscalls_and_jmps()
        elif instrumented_frame == None:
            if parent_instrumented_frame != None and parent_instrumented_frame.is_frame_valid():
                log_v("Unexpected breakpoint but parent frame still valid, continuing")
                continue
            log_v("Breakpoint expected on return address, but not there, exiting")
            break
        elif instrumented_frame.is_stopped_on_call(frame):
            log_v("Stopped on call")
            success = instrumented_frame.clear_calls_syscalls_and_jmps_and_instrument_return(frame)
            if not success:
                break
            caller = frame.GetSymbol().GetName()
            offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            thread.StepInstruction(False)
            destination = thread.GetFrameAtIndex(0).GetSymbol().GetName()
            log("{} {caller} + {offset:#x} ==> {destination}".format(spacer * depth, caller=caller, offset=offset, destination=destination))
            instrumented_frames.append(instrumented_frame)
            instrumented_frame = None
            frame = thread.GetFrameAtIndex(0)
            depth = depth + 1
            log_v('Entered new frame at: 0x%lx' % frame.GetPC())
        elif instrumented_frame.is_stopped_on_syscall(frame):
            rax = -1L;
            register_sets = frame.GetRegisters()
            for register_set in register_sets:
                if register_set.GetName() == "General Purpose Registers":
                    for register in register_set:
                        if register.GetName() == "rax":
                            rax = register.GetValue()
            log('{} Syscall {}'.format(spacer * depth, rax))
            thread.StepInstruction(False)
        elif instrumented_frame.is_stopped_on_jmp(frame, False):
            log_v("Stopped on jmp")
            caller = frame.GetSymbol().GetName()
            caller_offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            thread.StepInstruction(False)
            frame = thread.GetFrameAtIndex(0)
            destination = frame.GetSymbol().GetName()
            destination_offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            log("{} {caller} + {caller_offset:#x} === {destination} + {destination_offset:#x}".format(spacer * depth, caller=caller, caller_offset=caller_offset, destination=destination, destination_offset=destination_offset))
            instrumented_frame.update_frame(frame)
            if not options.module_only or frame.GetModule() == module:
                instrumented_frame.instrument_calls_syscalls_and_jmps()
            else:
                log("Not instrumenting since module {} isn't same as {}".format(frame.GetModule(), module))
        elif instrumented_frame.is_frame_valid():
            log_v("Unexpected breakpoint but instrumented frame still valid, continuing")
            continue
        else:
            log_v("Failed to detect return, call or jmp. Error exit")
            break

    # TODO: clear instrumented frames, on errors there
    # may be breakpoints left, what needs to be worked out
    # is whether instrumented_frame is set, and whether
    # it needs clearing
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    log_v('Listener thread exited completing')
    log_flush()

# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
