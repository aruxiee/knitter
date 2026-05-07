
# 🧵 knitter: In-Memory Remote Thread Injection PoC

Practical implementation of **Remote Thread Injection**, a process injection technique used to execute arbitrary code within the address space of a separate legitimate process. This project shows how to leverage `WinAPI` to achieve code execution while bypassing simple file-based detection by residing purely in memory.

⚠️ **Please Note:** This project is strictly for **Educational and Authorized Penetration Testing**. I am not responsible for any of the shenanigans you guys pull.

---

## ⚔️ How It Works
Remote Thread Injection is a method of executing code in the context of another process. Instead of starting a new process (like `calc.exe` directly), `knitter` borrows the resources of an existing process (like `notepad.exe`) to run its own instructions.

### 🛠️ Behind the Scenes
*   **Process Discovery**: `knitter` identifies a target process using its PID.
*   **Memory Carving**: It requests the Windows Kernel to allocate a new private region of memory inside `notepad.exe`.
*   **Data/Code Transfer**: Writes the payload (the command string) and the shellcode (the logic) into that allocated memory.
*   **Remote Execution**: Commands the OS to create a new thread inside the target process, pointing the CPU's instruction pointer to the newly written shellcode.

**Note**: This is just a demo. Do not execute this script in live engagements as it is pretty loud and **will** trip a lot of alarms.

---

## 🔍 Code Breakdown
`knitter` utilizes several critical Win32 APIs to perform the injection.

### 1️⃣ Opening the Target
```rust
let h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)?;
```
We obtain a handle to the target process with `PROCESS_ALL_ACCESS`, giving us the permissions necessary to modify its memory and create threads.

### 2️⃣ Locating the Target Function
```rust
let winexec = GetProcAddress(..., windows::core::s!("WinExec")).expect("Failed to find WinExec") as u64;
```
Since the address of system functions like `WinExec` can change due to ASLR, we dynamically look up its location so our shellcode knows where to jump.

### 3️⃣ Allocation & Writing
```rust
let remote_str = VirtualAllocEx(h_proc, None, cmd.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
WriteProcessMemory(h_proc, remote_str, cmd.as_ptr() as _, cmd.len(), None)?;
```
We allocate memory for the string `"calc.exe"` and write it into the target. We repeat this for the shellcode using `PAGE_EXECUTE_READWRITE` to make sure the memory can actually run code.

### 4️⃣ Shellcode (x64)
Built the shellcode manually using bytes that represent assembly instructions.
*   **Shadow Space Allocation** (`0x48, 0x83, 0xec, 0x28`): This gives the Windows function space to work without crashing the app.
*   **Argument Setup** (`0x48, 0xb9`): Moves the address of our `"calc.exe"` string into the `RCX` register.
*   **Execution** (`0xff, 0xd0`): **Call RAX**. This executes the `WinExec` function.

### 5️⃣ The Trigger
```rust
let h_exec = CreateRemoteThread(h_proc, None, 0, Some(std::mem::transmute(remote_code)), None, 0, None)?;
```
This is the final step that forces the target process to start a new thread and execute the injected code.

---

## 🚀 Execution Steps

- **Open PowerShell**: Although it did work with an unelevated shell, high-level process access may require elevated privileges.
- **Launch a Target**: Open **Notepad**.
- **Find the PID**:
    ```powershell
    (Get-Process notepad).Id
    ```
- **Build and Run**:
    ```powershell
    cargo build --release
    .\target\release\knitter.exe <PID>
    ```

### 🧐 What to Check
*   **The Terminal**: Look for confirmation that the shellcode was written and the thread was created.
*   **The Target**: A Calculator (`calc.exe`) should appear.
*   **Process Explorer**: You can witness the new thread living inside the Notepad process without crashing it.

---

## 📈 Impact and Use Cases
*   **Red Teaming**: Used to simulate APTs hiding inside trusted system processes.
*   **Evasion**: Bypasses simple security that only monitors for new suspicious `.exe` files starting up.
*   **Education**: For understanding memory protection, stack alignment, and the Windows Calling Convention.

---

## 🗺️ MITRE

| ID | Technique | Use Case |
| :--- | :--- | :--- |
| **T1055** | Process Injection | General method of executing code in a separate address space. |
| **T1055.002** | Portable Executable Injection | Specifically injecting code/strings into the memory of a target process. |
| **T1059** | Command and Scripting Interpreter | Using the target process to execute system commands (via `WinExec`). |

---

## 💡 Improvement Ideas
*   **DLL Injection**: Inject an entire `.dll` file instead of raw shellcode.
*   **Obfuscation**: Encrypt shellcode or strings to avoid detection from static scanners.
*   **Indirect Syscalls**: Use assembly to call kernel functions directly, bypassing security hooks.

---

<p align="center">
  With ❤️ by <b>Aradhya</b>
</p>
