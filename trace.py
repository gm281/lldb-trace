#!/usr/bin/python

import lldb
import commands
import optparse
import shlex
import threading

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
    breakpoint = None
    for i in instruction_list:
        print >>result, '0x%x' % i.GetAddress().GetLoadAddress(target)
        print >>result, '{}, {}, {}'.format(i.GetMnemonic(target), i.GetOperands(target), i.GetComment(target))
        if i.GetAddress().GetLoadAddress(target) == 0x7fff892d3fcb:
            print >>result, '=== This is the one'
            breakpoint = target.BreakpointCreateByAddress(i.GetAddress().GetLoadAddress(target))
    print >>result, breakpoint

    event = lldb.SBEvent()
    listener = debugger.GetListener()
    broadcaster = process.GetBroadcaster()
    print >>result, '=== a'
    class MyListeningThread(threading.Thread):
        def run(self):
            count = 0
            # Let's only try at most 4 times to retrieve any kind of event.
            # After that, the thread exits.
            while not count > 3:
                print >>result, 'Try wait for event...'
                if listener.WaitForEventForBroadcasterWithType(5,
                                                               broadcaster,
                                                               lldb.SBProcess.eBroadcastBitStateChanged,
                                                               event):
                    print >>result, '=== YEY'
                    event.GetDescription(result)
                    print >>result, 'Event data flavor:', event.GetDataFlavor()
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



# And the initialization code to add your commands
def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f trace.trace trace')
    print 'The "trace" python command has been installed and is ready for use.'
