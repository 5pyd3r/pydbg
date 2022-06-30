#include "winhelper.h"

bool c_attach(c_pid_t pid)
{
    return DebugActiveProcess(pid);
}

bool c_detach(c_pid_t pid)
{
    return DebugActiveProcessStop(pid);
}

bool c_start(char* path, char* const argv[])
{
    STARTUPINFO startupInfo = {0};
    PROCESS_INFORMATION processInfo = {0};

    CreateProcess(NULL, path, NULL, NULL, false, DEBUG_PROCESS, NULL, NULL, &startupInfo, &processInfo);
    return true;
}

void c_wait_event(LPDEBUG_EVENT DebugEv)
{
    WaitForDebugEvent(DebugEv, INFINITE);
}

void c_continue(c_pid_t pid, c_tid_t tid)
{
    ContinueDebugEvent(pid, tid, DBG_CONTINUE);
}

void c_main_loop()
{
    DWORD dwContinueStatus; // exception continuation 

    DEBUG_EVENT DebugEv[1];

    bool exitFlag = false;
 
    while(!exitFlag)
    { 
    // Wait for a debugging event to occur. The second parameter indicates
    // that the function does not return until a debugging event occurs. 
        dwContinueStatus = DBG_CONTINUE;
        WaitForDebugEvent(DebugEv, INFINITE); 

        // Process the debugging event code. 
 
        // Resume executing the thread that reported the debugging event. 
 
        ContinueDebugEvent(DebugEv->dwProcessId, 
            DebugEv->dwThreadId, 
            dwContinueStatus);
    }
}