# knitter
PoC for Remote Thread Injection in Rust. Leverages Win32 API to carve memory (VirtualAllocEx), write x64 shellcode (WriteProcessMemory), and trigger execution (CreateRemoteThread) inside a target PID.
