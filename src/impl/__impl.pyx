#cython: language_level=3
from src.impl.cwindows cimport *
from libc.string cimport memset
from cython.operator import dereference
import psutil

cdef class Debugger:
    cdef dict process

    def __cinit__(self):
        self.process = {}

    def load(self, path):
        cdef STARTUPINFOW si
        cdef PROCESS_INFORMATION pi

        memset(&si, 0, sizeof(si))
        memset(&pi, 0, sizeof(pi))

        si.cb = sizeof(si)
    
        if CreateProcessW(
            path, NULL,
            NULL, NULL, 0, 1, NULL, NULL, &si, &pi) != 0:
            self.process[pi.dwProcessId] = [pi.dwThreadId]
            return True
        else:
            return False

    def attach(self, process):
        if DebugActiveProcess(process) != 0:
            self.process[process] = []
            return True
        else:
            return False

    def detach(self, process):
        if DebugActiveProcessStop(process) != 0:
            del self.process[process]
            return True
        else:
            return False

    def run(self, timeout=INFINITE):
        cdef DEBUG_EVENT event

        if self.process == -1:
            return False

        if WaitForDebugEvent(&event, timeout) != 0:
            if event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                self.handle_exception_event(event.u.Exception)

            elif event.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT:
                self.threads.append(event.dwThreadId)
                self.handle_create_thread_event(event.u.CreateThread)

            elif event.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT:
                self.threads.append(event.dwThreadId)
                self.process = event.dwProcessId
                self.handle_create_process_event(event.u.CreateProcessInfo)

            elif event.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT:
                self.threads.remove(event.dwThreadId)
                self.handle_exit_thread_event(event.u.ExitThread)

            elif event.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT:
                self.threads.remove(event.dwThreadId)
                self.process = -1
                self.handle_exit_process_event(event.u.ExitProcess)

            elif event.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT:
                self.handle_load_dll_event(event.u.LoadDll)

            elif event.dwDebugEventCode == UNLOAD_DLL_DEBUG_EVENT:
                self.handle_unload_dll_event(event.u.UnloadDll)
            
            elif event.dwDebugEventCode == OUTPUT_DEBUG_STRING_EVENT:
                self.handle_output_string_event(event.u.DebugString)
            
            elif event.dwDebugEventCode == RIP_EVENT:
                self.handle_rip_event(event.u.RipInfo)
            
            else:
                print('Unknown Debug Event')
            if self.process != -1:
                ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE)
            
            return True
        else:       
            # timeout, no debug event triggered.
            print("wait for debug event timeout")
            return False

    cdef handle_exception_event(self, EXCEPTION_DEBUG_INFO info):
        record = info.ExceptionRecord
        if record.ExceptionCode == EXCEPTION_ACCESS_VIOLATION:
            print("access violation: addr(0x%x)" % <int>record.ExceptionAddress)
        elif record.ExceptionCode == EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            print("array bounds exceeded: ")
        elif record.ExceptionCode == EXCEPTION_BREAKPOINT:
            print("breakpoint: addr(0x%x)" % <int>record.ExceptionAddress)
        elif record.ExceptionCode == EXCEPTION_DATATYPE_MISALIGNMENT:
            print("datatype misalignment")
        elif record.ExceptionCode == EXCEPTION_FLT_DENORMAL_OPERAND:
            print("float denormal operand")
        elif record.ExceptionCode == EXCEPTION_FLT_DIVIDE_BY_ZERO:
            print("float divide by zero")
        elif record.ExceptionCode == EXCEPTION_FLT_INEXACT_RESULT:
            print("float inexact result")
        elif record.ExceptionCode == EXCEPTION_FLT_INVALID_OPERATION:
            print("float invalid operation")
        elif record.ExceptionCode == EXCEPTION_FLT_OVERFLOW:
            print("float overflow")
        elif record.ExceptionCode == EXCEPTION_FLT_STACK_CHECK:
            print("float stack check")
        elif record.ExceptionCode == EXCEPTION_FLT_UNDERFLOW:
            print("float underflow")
        elif record.ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION:
            print("illegal instruction")
        elif record.ExceptionCode == EXCEPTION_IN_PAGE_ERROR:
            print("in-page error")
        elif record.ExceptionCode == EXCEPTION_INT_DIVIDE_BY_ZERO:
            print("int divide by zero")
        elif record.ExceptionCode == EXCEPTION_INT_OVERFLOW:
            print("int overflow")
        elif record.ExceptionCode == EXCEPTION_INVALID_DISPOSITION:
            print("invalid disposition")
        elif record.ExceptionCode == EXCEPTION_NONCONTINUABLE_EXCEPTION:
            print("noncontinuable exception")
        elif record.ExceptionCode == EXCEPTION_PRIV_INSTRUCTION:
            print("private instruction")
        elif record.ExceptionCode == EXCEPTION_SINGLE_STEP:
            print("single step")
        elif record.ExceptionCode == EXCEPTION_STACK_OVERFLOW:
            print("stack overflow")
        else:
            print('EXCEPTION_DEBUG_EVENT, code(%d), flag(%d), addr(0x%x)' % 
                (record.ExceptionCode, record.ExceptionFlags, <int>record.ExceptionAddress))

    cdef handle_create_thread_event(self, CREATE_THREAD_DEBUG_INFO info):
        print('CREATE_THREAD_DEBUG_EVENT')

    cdef handle_create_process_event(self, CREATE_PROCESS_DEBUG_INFO info):
        print('process create: hFile(0x%x), hProcess(0x%x), hThread(0x%x), base(0x%x)' % 
           (<int>info.hFile, <int>info.hProcess, <int>info.hThread, <int>info.lpBaseOfImage))

    cdef handle_exit_thread_event(self, EXIT_THREAD_DEBUG_INFO info):
        print('EXIT_THREAD_DEBUG_EVENT')

    cdef handle_exit_process_event(self, EXIT_PROCESS_DEBUG_INFO info):
        print('EXIT_PROCESS_DEBUG_EVENT')

    cdef handle_load_dll_event(self, LOAD_DLL_DEBUG_INFO info):
        print('Dll load: handle(%x), base(0x%x), offset(0x%x), size(0x%x), name(0x%x), unicode(0x%x)' %
            (<int>info.hFile, <int>info.lpBaseOfDll, <int>info.dwDebugInfoFileOffset,
             <int>info.nDebugInfoSize, <int>info.lpImageName, <int>info.fUnicode))

    cdef handle_unload_dll_event(self, UNLOAD_DLL_DEBUG_INFO info):
        print('UNLOAD_DLL_DEBUG_EVENT')

    cdef handle_output_string_event(self, OUTPUT_DEBUG_STRING_INFO info):
        print("debug string: string(0x%x), len(%d), unicode(%d)" % 
            (<int>info.lpDebugStringData, info.nDebugStringLength, info.fUnicode))

    cdef handle_rip_event(self, RIP_INFO info):
        print('RIP_EVENT')

    cdef no_process(self):
        return len(self.process.items()) == 0

    cpdef main_loop (self):
        cdef DEBUG_EVENT event
        while not self.no_process():

            c_wait_event(&event)

            c_continue(event.dwProcessId, event.dwThreadId)


