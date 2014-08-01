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

    def isExiting(self):
        return self.exiting

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
                print >>self.result, 'Listener thread waiting for an event'
                wait_result = self.listener.WaitForEvent(10, event)

                if not wait_result:
                    print >>self.result, 'Listener thread timed out waiting for notification'
                    self.exiting = True
                    self.notify_event.set()
                    return
                print >>self.result, '=== YEY'
                print >>self.result, 'Event data flavor:', event.GetDataFlavor()
                print >>self.result, 'Event string:', lldb.SBEvent.GetCStringFromEvent(event)
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

    def instrument_calls(self):
        # TODO: symbols vs functions
        print >>self.result, self.frame.GetFunction()
        symbol = self.frame.GetSymbol()
        print >>self.result, symbol
        start_address = symbol.GetStartAddress()
        print >>self.result, start_address
        print >>self.result, '0x%x' % start_address.GetLoadAddress(self.target)
        instruction_list = symbol.GetInstructions(self.target)
        #print >>self.result, instruction_list
        breakpoints = {}
        subsequent_instruction = {}
        previous_breakpoint_address = 0L
        for i in instruction_list:
            address = i.GetAddress().GetLoadAddress(self.target)
            print >>self.result, '0x%x' % address
            print >>self.result, '{}, {}, {}'.format(i.GetMnemonic(self.target), i.GetOperands(self.target), i.GetComment(self.target))
            if previous_breakpoint_address != 0L:
                subsequent_instruction[previous_breakpoint_address] = address
                previous_breakpoint_address = 0L
            mnemonic = i.GetMnemonic(self.target)
            if mnemonic != None and mnemonic.startswith('call'):
                print >>self.result, 'Putting breakpoint at 0x%lx' % address
                breakpoint = self.target.BreakpointCreateByAddress(address)
                breakpoint.SetThreadID(self.thread.GetThreadID())
                breakpoints[address] = breakpoint
                previous_breakpoint_address = address
        print >>self.result, breakpoints
        self.breakpoints = breakpoints
        self.subsequent_instruction = subsequent_instruction

    def clear_calls_instrumentation(self):
        for breakpoint in self.breakpoints.itervalues():
            print >>self.result, 'Deleting breakpoint %d' % breakpoint.GetID()
            self.target.BreakpointDelete(breakpoint.GetID())

    def is_stopped_on_call_and_instrument_return(self):
        frame = self.thread.GetFrameAtIndex(0)
        stop_address = frame.GetPC()
        print >>self.result, 'Stop address: 0x%lx' % stop_address
        if not stop_address in self.breakpoints:
            return False

        breakpoint = self.breakpoints[stop_address]
        print >>self.result, 'Stopped on breakpoint:'
        print >>self.result, breakpoint
        if not stop_address in self.subsequent_instruction:
            print >>self.result, "Couldn't find subsequent instruction"
            return False
        self.return_breakpoint = self.target.BreakpointCreateByAddress(self.subsequent_instruction[stop_address])
        self.return_breakpoint.SetThreadID(self.thread.GetThreadID())
        self.clear_calls_instrumentation()
        return True

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
    if listening_thread.isExiting():
        print >>result, 'Listener thread exited unexpectedly'
        return False
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        print >>result, thread
        print >>result, "Thread under trace didn't stop due to a breakpoint"
        return False
    return True

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
    frame = thread.GetSelectedFrame()

    instrumented_frame = InstrumentedFrame(target, thread, frame, result)
    instrumented_frame.instrument_calls()

    print >>result, 'Instrumented all calls, running the process'
    success = continue_and_wait_for_breakpoint(process, thread, my_thread, wait_event, notify_event, result)
    if not success:
        print >>result, "Failed to continue+stop the process"
        return

    success = instrumented_frame.is_stopped_on_call_and_instrument_return()
    if not success:
        print >>result, "Failed to intrument call"
        return

    thread.StepInto()
    frame = thread.GetFrameAtIndex(0)
    stop_address = frame.GetPC()
    print >>result, 'Entered new frame at: 0x%lx' % stop_address

    second_instrumented_frame = InstrumentedFrame(target, thread, frame, result)
    second_instrumented_frame.instrument_calls()

    success = continue_and_wait_for_breakpoint(process, thread, my_thread, wait_event, notify_event, result)
    if not success:
        print >>result, "Failed to continue+stop the process"
        return

    success = second_instrumented_frame.is_stopped_on_call_and_instrument_return()
    if not success:
        print >>result, "Failed to intrument call"
        return

    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    print >>result, 'Listener thread exited completing'

# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
