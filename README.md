# Prefetch Parser

[![crates.io](https://img.shields.io/crates/v/frnsc-prefetch.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/frnsc-prefetch) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/frnsc-prefetch) [![MIT License](https://img.shields.io/crates/l/frnsc-prefetch?style=for-the-badge)](https://github.com/ForensicRS/frnsc-prefetch/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/ForensicRS/frnsc-prefetch/rust.yml?style=for-the-badge)](https://github.com/ForensicRS/frnsc-prefetch/workflows/Rust/badge.svg?branch=main)

A pure rust parser implementation of the windows prefetch. Works on all platforms.

```rust
use forensic_rs::prelude::*;
use frnsc_prefetch::prelude::*;
let mut fs = ChRootFileSystem::new("./artifacts/17", Box::new(StdVirtualFS::new()));
let prefetch_list : <PrefetchFile> = read_prefetch_form_fs(&mut fs).expect("Must read all prefetch from filesystem");
```

### Into Timeline

A PrefetchFile structure can be converted into [*TimelineData*](https://github.com/ForensicRS/forensic-rs/blob/main/src/traits/forensic.rs) be carefull as a single prefetch can be larger than 45Kb and in the process some data is lost like the MFT file references or the file traces.
```
{ 
    time: 06-11-2023 14:18:00.429, 
    artifact: Unknown, 
    fields: {
        "artifact.host": "", 
        "artifact.name": "Unknown", 
        "artifact.tenant": "", 
        "file.accessed": 06-11-2023 14:18:00.429, 
        "file.path": "POWERSHELL.EXE", 
        "pe.imports": ["\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\NTDLL.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\WOW64.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\WOW64WIN.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\KERNEL32.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSWOW64\\KERNEL32.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\USER32.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSTEM32\\WOW64CPU.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSWOW64\\NTDLL.DLL", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\WINDOWS\\SYSWOW64\\WINDOWSPOWERSHELL\\V1.0\\POWERSHELL.EXE", "..."], "prefetch.execution_times": 2945, 
        "prefetch.version": 30, 
        "prefetch.volume_files": ["\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\$EXTEND", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\PROGRAM FILES", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\PROGRAM FILES\\SECRMM", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\PROGRAM FILES\\SECRMM\\ADMINUTILS", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\PROGRAM FILES\\SECRMM\\ADMINUTILS\\SDK", "\\VOLUME{01d98a6b8e4b1a36-1c2ea44d}\\PROGRAMDATA", "..."]
        } 
    }, 
    time_context: Accessed 
}
```

```rust
let mut fs = StdVirtualFS::new();
let file = fs.open(Path::new(
    "./artifacts/30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
)).unwrap();
let pref = read_prefetch_file_compressed("POWERSHELL.EXE-AE8EDC9B.pf", file).unwrap();
let mut forensic_data = pref.timeline();
let event : TimelineData = forensic_data.next().unwrap();
```

### Into Activity

Transforms a prefetch data into a user activity event in order to know which program the user executed.

`ForensicActivity { timestamp: 06-11-2023 15:18:00.237, user: "WARD", session_id: Unknown, activity: ProgramExecution(\VOLUME{01d98a6b9e4a0a35-1c9e547d}\WINDOWS\SYSWOW64\WINDOWSPOWERSHELL\V1.0\POWERSHELL.EXE) }`

```rust
let mut fs = StdVirtualFS::new();
let file = fs.open(Path::new(
    "./artifacts/30/C/Windows/Prefetch/POWERSHELL.EXE-AE8EDC9B.pf",
)).unwrap();
let pref = read_prefetch_file_compressed("POWERSHELL.EXE-AE8EDC9B.pf", file).unwrap();
let mut forensic_data = pref.activity();
let activity : ForensicActivity = forensic_data.next().unwrap();
```

### Prefetch Format

The references can be found here: [libscca](https://github.com/libyal/libscca/blob/main/documentation/Windows%20Prefetch%20File%20(PF)%20format.asciidoc)

The file format when it's compressed has a MAM signature, followed by the compression algorithm a flag that indicates if it has CRC, the decompressed size, the CRC value and finally the compressed size:

![Compressed prefetch format](./img/compressed_prefetch.svg)

The decompressed file (or the full file when its not compressed) has a header:

* version: The SCCA version used to generate the prefetch.+
    * 17: Windows XP
    * 23: Windows 7
    * 26: Windows 8.1
    * 30: Windows 10
* signature: The signature is "SCCA"
* File Size: The prefetch file size
* Executable name: Name of the executable for which this prefetch was created
* Hash: the prefetch hash. Must be the same as the one in the prefetch file name.

![Prefetch header](./img/uncompressed_prefetch.svg)

After the header comes version-dependent file information data:

* Positions of the metric data: used to know which DLLs/EXEs loaded the executable.
* Positions of the trace chain
* Location of the strings array
* Location of the volume information array
* Number of executions
* Last execution time: in FILETIME format. For modern versions the last 8 times are stored.

![Prefetch information v17](./img/file_information_v17.svg)

![Prefetch information v23](./img/file_information_v23.svg)

![Prefetch information v26](./img/file_information_v26.svg)

![Prefetch information v30-1](./img/file_information_v30_1.svg)

![Prefetch information v30-2](./img/file_information_v30_2.svg)