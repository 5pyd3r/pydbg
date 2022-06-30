#ifndef WINHELPER_H
#define WINHELPER_H

#include <Windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef DWORD c_pid_t;
typedef DWORD c_tid_t;

typedef enum {
    BREAKPOINT_SOFTWARE,
    BREAKPOINT_HARDWARE,
    BREAKPOINT_MEMORY,
} BREAKPOINT_TYPE_E;

bool c_attach(c_pid_t pid);
bool c_detach();
bool c_start(char* path, char* const argv[]);
void c_main_loop();
bool c_step(c_pid_t pid, c_tid_t tid);
void c_wait_event(LPDEBUG_EVENT DebugEv);
void c_continue(c_pid_t pid, c_tid_t tid);
bool c_insert_bp(uintptr_t addr, BREAKPOINT_TYPE_E type, uint32_t *id);
bool c_remove_bp(uint32_t id);
bool c_get_context(c_pid_t pid, c_tid_t tid);
bool c_set_context(c_pid_t pid, c_tid_t tid);
bool c_get_mem(c_pid_t pid, uintptr_t addr, int len);
bool c_set_mem(c_pid_t pid, uintptr_t addr, int len);

#endif