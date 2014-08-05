#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import threading
import time

class MyListeningThread(threading.Thread):
    def __init__(self, wait_event, notify_event, listener, process, result):
        super(MyListeningThread, self).__init__()
        self.wait_event = wait_event
        self.notify_event = notify_event
        self.listener = listener
        self.process = process
        self.result = result
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
                print >>self.result, 'Listener thread was asked to exit, complying'
                self.notify_event.set()
                return
            while True:
                event = lldb.SBEvent()
                #print >>self.result, 'Listener thread waiting for an event'
                wait_result = self.listener.WaitForEvent(10, event)

                if not wait_result:
                    print >>self.result, 'Listener thread timed out waiting for notification'
                    self.wait_timeout = True
                    self.notify_event.set()
                    break
                #print >>self.result, '=== YEY'
                #print >>self.result, 'Event data flavor:', event.GetDataFlavor()
                #print >>self.result, 'Event string:', lldb.SBEvent.GetCStringFromEvent(event)
                if self.process.GetState() == lldb.eStateStopped:
                    break
                print >>self.result, 'Process not stopped, listening for the next event'
            print >>self.result, 'Listener thread got event, notifying'
            self.notify_event.set()

class InstrumentedFrame:
    def __init__(self, target, thread, frame, result):
        self.target = target
        self.thread = thread
        self.frame = frame
        self.result = result
        self.return_breakpoint = None
        self.call_breakpoints = {}
        self.jmp_breakpoints = {}
        self.subsequent_instruction = {}

    def update_frame(self, frame):
        self.frame = frame

    def instrument_calls_and_jmps(self):
        # TODO: symbols vs functions
        print >>self.result, self.frame.GetFunction()
        symbol = self.frame.GetSymbol()
        print >>self.result, "=========> Instrumenting symbol:"
        print >>self.result, symbol
        start_address = symbol.GetStartAddress().GetLoadAddress(self.target)
        #print >>self.result, '0x%x' % start_address
        end_address = symbol.GetEndAddress().GetLoadAddress(self.target)
        #print >>self.result, '0x%x' % end_address
        instruction_list = symbol.GetInstructions(self.target)
        #print >>self.result, instruction_list
        previous_breakpoint_address = 0L
        for i in instruction_list:
            address = i.GetAddress().GetLoadAddress(self.target)
            #print >>self.result, '0x%x' % address
            #print >>self.result, '{}, {}, {}'.format(i.GetMnemonic(self.target), i.GetOperands(self.target), i.GetComment(self.target))
            if address in self.call_breakpoints or address in self.jmp_breakpoints:
                #print >>self.result, 'There already is a breakpoint for this address'
                continue
            if previous_breakpoint_address != 0L:
                self.subsequent_instruction[previous_breakpoint_address] = address
                previous_breakpoint_address = 0L
            mnemonic = i.GetMnemonic(self.target)
            if mnemonic != None and mnemonic.startswith('call'):
                #print >>self.result, 'Putting breakpoint at 0x%lx' % address
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
                    #print >>self.result, 'Non-Local call'
                    breakpoint = self.target.BreakpointCreateByAddress(address)
                    breakpoint.SetThreadID(self.thread.GetThreadID())
                    self.jmp_breakpoints[address] = breakpoint

    def clear_calls_instrumentation(self):
        for breakpoint in self.call_breakpoints.itervalues():
            #print >>self.result, 'Deleting breakpoint %d' % breakpoint.GetID()
            self.target.BreakpointDelete(breakpoint.GetID())
        self.call_breakpoints = {}
        self.subsequent_instruction = {}

    def clear_jmps_instrumentation(self):
        for breakpoint in self.jmp_breakpoints.itervalues():
            #print >>self.result, 'Deleting breakpoint %d' % breakpoint.GetID()
            self.target.BreakpointDelete(breakpoint.GetID())
        self.jmp_breakpoints = {}

    def clear_return_breakpoint(self):
        self.target.BreakpointDelete(self.return_breakpoint.GetID())
        self.return_breakpoint == None

    def is_stopped_on_call(self, frame):
        if frame.GetFrameID() != self.frame.GetFrameID():
            print >>self.result, "A Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID())
            return False

        stop_address = frame.GetPC()
        return stop_address in self.call_breakpoints

    def is_stopped_on_jmp(self, frame, validate_saved_frame):
        if validate_saved_frame and frame.GetFrameID() != self.frame.GetFrameID():
            print >>self.result, "B Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID())
            return False

        stop_address = frame.GetPC()
        return stop_address in self.jmp_breakpoints

    def is_stopped_on_return(self, frame):
        if frame.GetFrameID() != self.frame.GetFrameID():
            print >>self.result, "C Frames don't match, ours: {}, valid: {}, submitted: {}".format(self.frame.GetFrameID(), self.frame.IsValid(), frame.GetFrameID())
            return False

        if self.return_breakpoint == None:
            return False

        stop_address = frame.GetPC()
        return self.return_address == stop_address

    def instrument_return(self, return_address):
        self.return_address = return_address
        self.return_breakpoint = self.target.BreakpointCreateByAddress(self.return_address)
        self.return_breakpoint.SetThreadID(self.thread.GetThreadID())

    def clear_calls_and_jmps_and_instrument_return(self, frame):
        stop_address = frame.GetPC()
        if not stop_address in self.subsequent_instruction:
            print >>self.result, "Couldn't find subsequent instruction"
            return False
        self.instrument_return(self.subsequent_instruction[stop_address])
        self.clear_calls_instrumentation()
        self.clear_jmps_instrumentation()
        return True

    def clear(self):
        if self.call_breakpoints != None:
            self.clear_calls_instrumentation()
        if self.jmp_breakpoints != None:
            self.clear_jmps_instrumentation()
        if self.return_breakpoint != None:
            self.clear_return_breakpoint()


def continue_and_wait_for_breakpoint(process, thread, listening_thread, wait_event, notify_event, result):
    print >>result, process.GetState()
    process.Continue()
    wait_event.set()
    print >>result, 'Process continued, waiting for notification'
    notify_event.wait()
    notify_event.clear()
    print >>result, 'Got notification, sanity checks follow'
    print >>result, process.GetState()
    # Some sanity checking
    if listening_thread.wait_timed_out():
        print >>result, 'Listener thread exited unexpectedly'
        return False
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        print >>result, thread
        print >>result, "Thread under trace didn't stop due to a breakpoint"
        return False
    return True

def get_pc_addresses(thread):
    def GetPCAddress(i):
        return thread.GetFrameAtIndex(i).GetPCAddress()

    return map(GetPCAddress, range(thread.GetNumFrames()))

def print_stacktrace(result, target, thread):
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
            print >>result, '  frame #{num}: {addr:#016x} `{symbol} + {offset}'.format(num=i, addr=load_addr, symbol=frame.GetSymbol().GetName(), offset=symbol_offset)
        else:
            print >>result, '  frame #{num}: {addr:#016x} `{func}'.format(num=i, addr=load_addr, func=frame.GetFunctionName())

def trace(debugger, command, result, internal_dict):
    wait_event = threading.Event()
    wait_event.clear()
    notify_event = threading.Event()
    notify_event.clear()

    target = debugger.GetSelectedTarget()
    print >>result, target
    process = target.GetProcess()
    print >>result, process
    broadcaster = process.GetBroadcaster()
    print >>result, broadcaster
    listener = lldb.SBListener("trace breakpoint listener")
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    if not rc:
        print >>self.result, 'Failed to add listener'

    my_thread = MyListeningThread(wait_event, notify_event, listener, process, result)
    my_thread.start()
    thread = process.GetSelectedThread()
    print >>result, thread

    instrumented_frames = []
    frame = thread.GetSelectedFrame()
    # Instrument parent frame's return, so that we can detect when to terminate tracing
    parent_frame = thread.GetFrameAtIndex(frame.GetFrameID() + 1)
    if parent_frame != None:
        instrumented_frame = InstrumentedFrame(target, thread, parent_frame, result)
        instrumented_frame.instrument_return(parent_frame.GetPC())
        instrumented_frames.append(instrumented_frame)

    instrumented_frame = None
    while True:
        if instrumented_frame == None:
            instrumented_frame = InstrumentedFrame(target, thread, frame, result)
            instrumented_frame.instrument_calls_and_jmps()

        print >>result, 'Running the process'
        # Continue running until next breakpoint is hit, _unless_ PC is already on a breakpoint address
        if not instrumented_frame.is_stopped_on_call(frame) and not instrumented_frame.is_stopped_on_jmp(frame, True):
            success = continue_and_wait_for_breakpoint(process, thread, my_thread, wait_event, notify_event, result)
            if not success:
                print >>result, "Failed to continue+stop the process"
                break

        frame = thread.GetFrameAtIndex(0)
        print >>result, "=================== Stopped at: ===================="
        print >>result, frame
        print >>result, frame.GetSymbol()
        print >>result, "0x%lx" % frame.GetPC()
        print_stacktrace(result, target, thread)
        print >>result, "===="

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
            print >>result, "Stopped on return, popping a frame"
            destination = frame.GetSymbol().GetName()
            offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            print >>result, "T: {destination} + {offset:#x} <==".format(destination=destination, offset=offset)
            instrumented_frame.clear()
            instrumented_frame = instrumented_frames.pop()
            instrumented_frame.clear_return_breakpoint()
            if len(instrumented_frames) == 0:
                print >>result, "Detected return from the function under trace, exiting"
                break
            instrumented_frame.instrument_calls_and_jmps()
        elif instrumented_frame.is_stopped_on_call(frame):
            print >>result, "Stopped on call"
            success = instrumented_frame.clear_calls_and_jmps_and_instrument_return(frame)
            if not success:
                break
            caller = frame.GetSymbol().GetName()
            offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            thread.StepInstruction(False)
            destination = thread.GetFrameAtIndex(0).GetSymbol().GetName()
            print >>result, "T: {caller} + {offset:#x} ==> {destination}".format(caller=caller, offset=offset, destination=destination)
            instrumented_frames.append(instrumented_frame)
            instrumented_frame = None
            frame = thread.GetFrameAtIndex(0)
            print >>result, 'Entered new frame at: 0x%lx' % frame.GetPC()
        elif instrumented_frame.is_stopped_on_jmp(frame, False):
            print >>result, "Stopped on jmp"
            caller = frame.GetSymbol().GetName()
            caller_offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            thread.StepInstruction(False)
            frame = thread.GetFrameAtIndex(0)
            destination = frame.GetSymbol().GetName()
            destination_offset = frame.GetPCAddress().GetFileAddress() - frame.GetSymbol().GetStartAddress().GetFileAddress()
            print >>result, "T: {caller} + {caller_offset:#x} === {destination} + {destination_offset:#16x}".format(caller=caller, caller_offset=caller_offset, destination=destination, destination_offset=destination_offset)
            instrumented_frame.update_frame(frame)
            instrumented_frame.instrument_calls_and_jmps()
        else:
            print >>result, "Failed to detect return, call or jmp. Error exit"
            break

    # TODO: clear instrumented frames, on errors there
    # may be breakpoints left, what needs to be worked out
    # is whether instrumented_frame is set, and whether
    # it needs clearing
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    print >>result, 'Listener thread exited completing'

# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
