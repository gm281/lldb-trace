#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import threading
import time

def trace(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    print >>result, target
    process = target.GetProcess()
    print >>result, process
    thread = process.GetSelectedThread()
    print >>result, thread
    frame = thread.GetSelectedFrame()
    print >>result, frame
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

    event = lldb.SBEvent()
    listener = lldb.SBListener("trace breakpoint listener")
    broadcaster = process.GetBroadcaster()
    rc = broadcaster.AddListener(listener, lldb.SBProcess.eBroadcastBitStateChanged)
    if not rc:
        print >>result, 'Failed to add listener'
        return

    print >>result, '=== a'
    class MyListeningThread(threading.Thread):
        def run(self):
            count = 0
            # Let's only try at most 4 times to retrieve any kind of event.
            # After that, the thread exits.
            while not count > 3:
                print >>result, 'Try wait for event...'
                if listener.WaitForEventForBroadcasterWithType(1,
                                                               broadcaster,
                                                               lldb.SBProcess.eBroadcastBitStateChanged,
                                                               event):
                    print >>result, '=== YEY'
                    print >>result, 'Event data flavor:', event.GetDataFlavor()
                    print >>result, 'Event string:', lldb.SBEvent.GetCStringFromEvent(event)
                    return
                else:
                    print >>result, 'timeout occurred waiting for event...'
                count = count + 1
            return
    print >>result, '=== b'
    my_thread = MyListeningThread()
    print >>result, '=== c'
    my_thread.start()
    print >>result, '=== d'
    process.Continue()
    print >>result, '=== e'
    my_thread.join()
    print >>result, '=== f'
    # Some sanity checking
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




# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
