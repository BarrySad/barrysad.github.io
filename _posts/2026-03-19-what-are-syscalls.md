---
title: "What Are Syscalls and Why Do They Matter for Evasion?"
date: 2026-03-19
categories: [Malware Development, Syscalls]
tags: [syscalls, evasion, windows internals, EDR, red team, ntdll, win32]
---

If you've spent any time in the offensive security space, you've probably 
heard the term "syscall" thrown around — usually in the context of EDR 
evasion. Tools like SysWhispers3 make it easy to drop in direct syscalls 
without really understanding what's happening underneath. This series is 
my attempt to fix that. We're starting from scratch and building up to a 
fully custom syscall implementation with no third-party dependencies.

Before we write a single line of assembly though, we need to understand 
what syscalls actually are, where they live in the Windows execution model, 
and why they're such an interesting target for evasion.

## The Windows execution model

When your code calls something like `VirtualAlloc`, it feels like a single 
operation — you call a function, memory gets allocated, done. But under the 
hood that call passes through several distinct layers before it actually 
does anything. Understanding those layers is the whole game.

Here's what that chain looks like:

<div>
<svg width="100%" viewBox="0 0 680 800" xmlns="http://www.w3.org/2000/svg">
<defs>
  <marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
    <path d="M2 1L8 5L2 9" fill="none" stroke="context-stroke" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
  </marker>
</defs>
<rect x="40" y="24" width="420" height="490" rx="16" fill="none" stroke="#888780" stroke-width="0.5" stroke-dasharray="5 3"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#888780" x="56" y="44">User mode</text>
<line x1="40" y1="528" x2="460" y2="528" stroke="#888780" stroke-width="1" stroke-dasharray="6 4"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#888780" x="470" y="532">Privilege boundary</text>
<rect x="40" y="544" width="420" height="110" rx="16" fill="none" stroke="#888780" stroke-width="0.5" stroke-dasharray="5 3"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#888780" x="56" y="564">Kernel mode</text>
<rect x="110" y="54" width="280" height="52" rx="8" fill="#1D9E75" stroke="#0F6E56" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#E1F5EE" x="250" y="75" text-anchor="middle" dominant-baseline="central">Win32 API</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#9FE1CB" x="250" y="95" text-anchor="middle" dominant-baseline="central">kernel32.dll / kernelbase.dll</text>
<line x1="250" y1="106" x2="250" y2="134" stroke="#888780" stroke-width="1.5" marker-end="url(#arrow)"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#888780" x="262" y="124" dominant-baseline="central">e.g. VirtualAlloc()</text>
<rect x="110" y="136" width="280" height="52" rx="8" fill="#1D9E75" stroke="#0F6E56" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#E1F5EE" x="250" y="157" text-anchor="middle" dominant-baseline="central">ntdll.dll</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#9FE1CB" x="250" y="177" text-anchor="middle" dominant-baseline="central">NtAllocateVirtualMemory stub</text>
<line x1="390" y1="162" x2="470" y2="162" stroke="#E24B4A" stroke-width="0.5" stroke-dasharray="4 3" marker-end="url(#arrow)"/>
<rect x="472" y="142" width="166" height="44" rx="6" fill="none" stroke="#E24B4A" stroke-width="0.5" stroke-dasharray="4 3"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#E24B4A" x="555" y="159" text-anchor="middle">EDR hooks live here</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#E24B4A" x="555" y="176" text-anchor="middle">redirect to EDR agent</text>
<line x1="250" y1="188" x2="250" y2="220" stroke="#888780" stroke-width="1.5" marker-end="url(#arrow)"/>
<text font-family="Arial, sans-serif" font-size="12" fill="#888780" x="262" y="208" dominant-baseline="central">loads SSN into eax</text>
<rect x="110" y="222" width="280" height="52" rx="8" fill="#1D9E75" stroke="#0F6E56" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#E1F5EE" x="250" y="243" text-anchor="middle" dominant-baseline="central">Syscall stub</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#9FE1CB" x="250" y="263" text-anchor="middle" dominant-baseline="central">mov eax, SSN / syscall</text>
<line x1="250" y1="274" x2="250" y2="306" stroke="#888780" stroke-width="1.5" marker-end="url(#arrow)"/>
<rect x="110" y="308" width="280" height="52" rx="8" fill="#BA7517" stroke="#854F0B" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#FAEEDA" x="250" y="329" text-anchor="middle" dominant-baseline="central">syscall instruction</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#FAC775" x="250" y="349" text-anchor="middle" dominant-baseline="central">CPU privilege transition</text>
<line x1="250" y1="360" x2="250" y2="392" stroke="#888780" stroke-width="1.5" marker-end="url(#arrow)"/>
<rect x="110" y="394" width="280" height="52" rx="8" fill="#1D9E75" stroke="#0F6E56" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#E1F5EE" x="250" y="415" text-anchor="middle" dominant-baseline="central">Kernel syscall handler</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#9FE1CB" x="250" y="435" text-anchor="middle" dominant-baseline="central">looks up SSN in SSDT</text>
<line x1="250" y1="446" x2="250" y2="568" stroke="#888780" stroke-width="1.5" marker-end="url(#arrow)"/>
<rect x="110" y="572" width="280" height="52" rx="8" fill="#534AB7" stroke="#3C3489" stroke-width="0.5"/>
<text font-family="Arial, sans-serif" font-size="14" font-weight="500" fill="#EEEDFE" x="250" y="593" text-anchor="middle" dominant-baseline="central">Kernel function</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#AFA9EC" x="250" y="613" text-anchor="middle" dominant-baseline="central">executes privileged operation</text>
<rect x="110" y="686" width="280" height="72" rx="8" fill="none" stroke="#E24B4A" stroke-width="0.5" stroke-dasharray="4 3"/>
<text font-family="Arial, sans-serif" font-size="12" font-weight="500" fill="#E24B4A" x="126" y="708">Direct syscalls bypass ntdll entirely</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#E24B4A" x="126" y="726">Skip the hooked ntdll stubs — the EDR</text>
<text font-family="Arial, sans-serif" font-size="12" fill="#E24B4A" x="126" y="744">never sees the call.</text>
</svg>
</div>

At the top you have the **Win32 API** — functions like `VirtualAlloc`, 
`CreateThread`, `WriteProcessMemory`. These live in DLLs like `kernel32.dll` 
and `kernelbase.dll` and are essentially a friendly, documented interface 
over the more complex stuff underneath.

Below that sits **ntdll.dll** — this is where things get interesting. Ntdll 
is the lowest layer of code that still runs in user mode. When `kernel32.dll` 
needs to do something that requires kernel involvement — allocating memory, 
creating threads, opening files — it hands off to ntdll. The functions here 
have the `Nt` or `Zw` prefix you might have seen before: 
`NtAllocateVirtualMemory`, `NtCreateThreadEx`, `NtWriteVirtualMemory`.

At the bottom is the **Windows kernel** itself, running in kernel mode. 
This is where the actual work happens.

## User mode vs kernel mode

Windows splits execution into two privilege levels: **user mode** and 
**kernel mode**.

User mode is where your code runs. It's sandboxed — user mode code can't 
directly touch hardware, can't access arbitrary memory, and can't perform 
privileged operations. If your application crashes in user mode, it takes 
down your process and nothing else.

Kernel mode is where the OS itself runs. Code here has unrestricted access 
to hardware and memory. If something crashes in kernel mode, it takes down 
the entire system — that's your blue screen of death.

The boundary between these two worlds is a hard one. User mode code 
**cannot** simply call kernel mode code like a normal function. There's no 
function pointer to jump to, no DLL to import. The only legitimate way to 
cross from user mode into kernel mode is through a **system call**.

## So what actually is a syscall?

A syscall is the mechanism the CPU provides for safely transitioning from 
user mode to kernel mode. When ntdll needs the kernel to do something, it 
doesn't just call a function — it executes a special CPU instruction 
(`syscall` on x64) that triggers a controlled context switch into kernel mode.

Before executing that instruction, ntdll loads a number into the `eax` 
register — this is the **System Service Number (SSN)**, sometimes called 
the syscall number. The kernel uses this number as an index into a table 
called the **System Service Descriptor Table (SSDT)** to figure out which 
kernel function to actually invoke.

So the full flow for something like `VirtualAlloc` looks like this:

1. Your code calls `VirtualAlloc` in `kernel32.dll`
2. `kernel32.dll` calls `NtAllocateVirtualMemory` in `ntdll.dll`
3. `ntdll.dll` loads the SSN for `NtAllocateVirtualMemory` into `eax`
4. `ntdll.dll` executes the `syscall` instruction
5. The CPU switches to kernel mode and jumps to the kernel's syscall handler
6. The kernel looks up the SSN in the SSDT and calls the corresponding kernel function
7. The kernel does the work, switches back to user mode, and returns the result

If you look at the actual assembly for an ntdll syscall stub, it's 
surprisingly simple:
```nasm
mov r10, rcx          ; required for syscall calling convention
mov eax, <SSN>        ; load the syscall number
syscall               ; transition to kernel mode
ret                   ; return to caller
```

That's four instructions. Everything else — the parameter marshalling, the 
error handling, the friendly API surface — happens in the layers above.

## Where EDR lives in this picture

Now that we understand the call chain, we can talk about why any of this 
matters for evasion.

EDR solutions need to monitor what processes are doing. The most common way 
they do this is by **hooking ntdll** — they patch the syscall stubs in 
`ntdll.dll` at process startup, replacing the first few bytes of functions 
like `NtAllocateVirtualMemory` with a jump to their own monitoring code. 
Your call goes into ntdll, gets redirected to the EDR's code, which logs 
what's happening and then (usually) lets the call continue.

This is called **userland hooking**, and it's the dominant EDR technique 
because it's relatively easy to implement and doesn't require a kernel 
driver for basic monitoring.

The weakness is obvious once you see it: the hooks live in user mode, in 
a DLL that's mapped into your process's address space. If you can make the 
`syscall` instruction execute *without going through ntdll's hooked stubs*, 
the EDR never sees the call.

That's exactly what direct syscalls do — and it's what we'll be building 
from scratch in the next post.

## What's next

In the next post we'll look at how to find SSNs at runtime, write our first 
syscall stub in x64 assembly, and call it from C++ without touching ntdll 
at all. By the end of it we'll have a working `NtAllocateVirtualMemory` 
implementation that completely bypasses userland hooks.

If anything here was unclear feel free to reach out — I'm figuring this 
out as I go too.