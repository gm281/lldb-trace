#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import threading
import time

class MyListeningThread(threading.Thread):
    def __init__(self, wait_event, notify_event, listener, result):
        super(MyListeningThread, self).__init__()
        self.wait_event = wait_event
        self.notify_event = notify_event
        self.listener = listener
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
            print >>self.result, 'Listener thread got event, notifying'
            self.notify_event.set()

def instrument_calls(target, thread, frame, result):
    # TODO: symbols vs functions
    print >>result, frame.GetFunction()
    symbol = frame.GetSymbol()
    print >>result, symbol
    start_address = symbol.GetStartAddress()
    print >>result, start_address
    print >>result, '0x%x' % start_address.GetLoadAddress(target)
    instruction_list = symbol.GetInstructions(target)
    #print >>result, instruction_list
    breakpoints = {}
    for i in instruction_list:
        print >>result, '0x%x' % i.GetAddress().GetLoadAddress(target)
        print >>result, '{}, {}, {}'.format(i.GetMnemonic(target), i.GetOperands(target), i.GetComment(target))
        mnemonic = i.GetMnemonic(target)
        if mnemonic != None and mnemonic.startswith('call'):
            address = i.GetAddress().GetLoadAddress(target)
            print >>result, 'Putting breakpoint at 0x%lx' % address
            breakpoint = target.BreakpointCreateByAddress(address)
            breakpoint.SetThreadID(thread.GetThreadID())
            breakpoints[address] = breakpoint
    print >>result, breakpoints
    return breakpoints

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
 
    my_thread = MyListeningThread(wait_event, notify_event, listener, result)
    my_thread.start()
    thread = process.GetSelectedThread()
    print >>result, thread
    frame = thread.GetSelectedFrame()


    breakpoints = instrument_calls(target, thread, frame, result)
    print >>result, 'Instrumented all calls, running process'
    print >>result, process.GetState()
    process.Continue()
    wait_event.set()
    print >>result, 'Process continued, waiting for notification'
    notify_event.wait()
    notify_event.clear()
    while process.GetState() != lldb.eStateStopped:
        wait_event.set()
        notify_event.wait()
        notify_event.clear()
    print >>result, 'Got notification, sanity checks follow'
    print >>result, process.GetState()
    # Some sanity checking
    if my_thread.isExiting():
        print >>result, 'Listener thread exited unexpectedly'
        return
    if thread.GetStopReason() != lldb.eStopReasonBreakpoint:
        print >>result, thread
        print >>result, "Thread under trace didn't stop due to a breakpoint"
        return
    frame = thread.GetFrameAtIndex(0)
    stop_address = frame.GetPC()
    print >>result, 'Stop address: 0x%lx' % stop_address
    if not stop_address in breakpoints:
        print >>result, "Unexpected stop address"
        return
    breakpoint = breakpoints[stop_address]
    print >>result, 'Stopped on breakpoint:'
    print >>result, breakpoint
    for breakpoint in breakpoints.itervalues():
        print >>result, 'Deleting breakpoint %d' % breakpoint.GetID()
        target.BreakpointDelete(breakpoint.GetID())
    my_thread.exit()
    wait_event.set()
    my_thread.join()
    broadcaster.RemoveListener(listener)
    print >>result, 'Listener thread exited completing'

# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
