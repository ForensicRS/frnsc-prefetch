//! Prefetch files of the forensic-testenv corpus, checked against values read with dissect.target 3.25.1
//! (its `Prefetch` parser and its cstruct definitions), an implementation independent of this
//! crate. Each test is skipped unless its artifact is fetched
//! (`forensic-testenv/tools/fetch.py --crate frnsc-prefetch`).
//!
//! dissect's own gaps are left unasserted (`None`), not filled in from this crate:
//! - Format 17: it reads the 64-bit last run time as a `uint32`, which shifts the run count.
//! - Format 30/31 files with the second header variant (metrics array not at offset 304): it
//!   reads the run count at the first variant's offset.
//! - Format 26 isn't registered in dissect.target 3.25.1; its own `FILE_INFORMATION_26` struct
//!   was registered for it.
//!
//! Loaded file names and file references are compared as count, first, last and a CRC32 of the
//! list, so this file stays small.

use frnsc_prefetch::prelude::*;

struct Volume {
    device_path: &'static str,
    serial: u32,
    creation_time: u64,
    directory_strings: usize,
}

struct Expect {
    id: &'static str,
    version: u32,
    executable: &'static str,
    hash: u32,
    size: u32,
    run_count: Option<u32>,
    runs: Option<&'static [u64]>,
    metrics: usize,
    metrics_first: Option<&'static str>,
    metrics_last: Option<&'static str>,
    /// CRC32 of the loaded file names joined by `\n`, as UTF-8.
    metrics_crc: u32,
    /// Loaded files with a nonzero file reference.
    refs: usize,
    /// CRC32 of every entry's raw 64-bit reference (0 when none), in decimal, joined by `,`.
    refs_crc: u32,
    volumes: &'static [Volume],
}

const EXPECTED: &[Expect] = &[
    Expect {
        id: "prefetch-v17-xp-cmd",
        version: 17,
        executable: r"CMD.EXE",
        hash: 0x087B4001,
        size: 11986,
        run_count: None,
        runs: None,
        metrics: 33,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\IE7\SPUNINST\IERESETICONS.EXE"),
        metrics_crc: 0xF424B361,
        refs: 0,
        refs_crc: 0x36198671,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME1",
            serial: 0x24CB074B,
            creation_time: 130073843862343750,
            directory_strings: 10,
        }],
    },
    Expect {
        id: "prefetch-v23-vista-cmd",
        version: 23,
        executable: r"CMD.EXE",
        hash: 0x89305D47,
        size: 6026,
        run_count: Some(3),
        runs: Some(&[130974481955514245]),
        metrics: 7,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME1\WINDOWS\SYSTEM32\MSVCRT.DLL"),
        metrics_crc: 0x99F8DFF1,
        refs: 7,
        refs_crc: 0x3015254F,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME1",
            serial: 0xE8EAB8B5,
            creation_time: 130974511931093750,
            directory_strings: 2,
        }],
    },
    Expect {
        id: "prefetch-v23-win7-calc",
        version: 23,
        executable: r"CALC.EXE",
        hash: 0x77FDF17F,
        size: 23538,
        run_count: Some(2),
        runs: Some(&[130974496211967500]),
        metrics: 37,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\$MFT"),
        metrics_crc: 0xC097EEFE,
        refs: 36,
        refs_crc: 0xF518A002,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0x88008C2F,
            creation_time: 130974525181093750,
            directory_strings: 8,
        }],
    },
    Expect {
        id: "prefetch-v26-win8-calc",
        version: 26,
        executable: r"CALC.EXE",
        hash: 0x77FDF17F,
        size: 22048,
        run_count: Some(2),
        runs: Some(&[130974522260583417, 130974521816609313]),
        metrics: 37,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\SHCORE.DLL"),
        metrics_crc: 0xC099E508,
        refs: 36,
        refs_crc: 0x405327AB,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0xC6EE7444,
            creation_time: 130974554943519546,
            directory_strings: 7,
        }],
    },
    Expect {
        id: "prefetch-v26-taskhost",
        version: 26,
        executable: r"TASKHOST.EXE",
        hash: 0x3AE259FC,
        size: 28766,
        run_count: Some(4),
        runs: Some(&[
            130253748090378333,
            130253740890103565,
            130253411945960606,
            130253406736429375,
        ]),
        metrics: 51,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTASN1.DLL"),
        metrics_crc: 0x18C5704B,
        refs: 48,
        refs_crc: 0xDEC83726,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0x686C4249,
            creation_time: 130253758461465476,
            directory_strings: 10,
        }],
    },
    Expect {
        id: "prefetch-v30-mam-win10-calc",
        version: 30,
        executable: r"CALC.EXE",
        hash: 0x3FBEF7FD,
        size: 47848,
        run_count: Some(2),
        runs: Some(&[130970237009853304, 130968655538095417]),
        metrics: 63,
        metrics_first: Some(r"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d1217a9c4c6779-8c9f49ec}\$MFT"),
        metrics_crc: 0x6187F84D,
        refs: 62,
        refs_crc: 0xE526CFA3,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d1217a9c4c6779-8c9f49ec}",
            serial: 0x8C9F49EC,
            creation_time: 130922674662434681,
            directory_strings: 19,
        }],
    },
    Expect {
        id: "prefetch-v30-mam-win10-chrome",
        version: 30,
        executable: r"CHROME.EXE",
        hash: 0xB3BA7868,
        size: 116042,
        run_count: Some(20),
        runs: Some(&[
            130971820153344577,
            130971808963388424,
            130971802218199213,
            130971794150514040,
            130971776592630726,
            130971774320529811,
            130971761988729609,
            130971758905435594,
        ]),
        metrics: 282,
        metrics_first: Some(r"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d1217a9c4c6779-8c9f49ec}\WINDOWS\FONTS\ARIALI.TTF"),
        metrics_crc: 0x6CB5E7C2,
        refs: 264,
        refs_crc: 0x65A509B9,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d1217a9c4c6779-8c9f49ec}",
            serial: 0x8C9F49EC,
            creation_time: 130922674662434681,
            directory_strings: 23,
        }],
    },
    Expect {
        id: "prefetch-v30-mam-notepad",
        version: 30,
        executable: r"NOTEPAD.EXE",
        hash: 0xD8414F97,
        size: 34286,
        run_count: None,
        runs: Some(&[132042381048777787, 132042361808157052]),
        metrics: 56,
        metrics_first: Some(r"\VOLUME{01d3096ba3a46863-2ca3d1ae}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d3096ba3a46863-2ca3d1ae}\WINDOWS\SYSTEM32\WIN32KFULL.SYS"),
        metrics_crc: 0x05A91C0F,
        refs: 0,
        refs_crc: 0x981BA203,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d3096ba3a46863-2ca3d1ae}",
            serial: 0x2CA3D1AE,
            creation_time: 131459172035487843,
            directory_strings: 9,
        }],
    },
    Expect {
        id: "prefetch-v31-mam-win11",
        version: 31,
        executable: r"AM_DELTA_PATCH_1.443.990.0.EX",
        hash: 0x7037CF86,
        size: 11888,
        run_count: None,
        runs: Some(&[134146862246686325]),
        metrics: 18,
        metrics_first: Some(r"\VOLUME{01dc94cf1f08c4a4-bc1f1bfc}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(
            r"\VOLUME{01dc94cf1f08c4a4-bc1f1bfc}\WINDOWS\APPPATCH\01DC953A090144C0.SYSMAIN.SDB",
        ),
        metrics_crc: 0xE50DD1E2,
        refs: 0,
        refs_crc: 0x1797263E,
        volumes: &[Volume {
            device_path: r"\VOLUME{01dc94cf1f08c4a4-bc1f1bfc}",
            serial: 0xBC1F1BFC,
            creation_time: 134145706214081700,
            directory_strings: 12,
        }],
    },
    Expect {
        id: "prefetch-artemis-win7-verclsid",
        version: 23,
        executable: r"VERCLSID.EXE",
        hash: 0x7C52E31C,
        size: 12432,
        run_count: Some(1),
        runs: Some(&[133116574864749199]),
        metrics: 26,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\SHLWAPI.DLL"),
        metrics_crc: 0x4122D82B,
        refs: 0,
        refs_crc: 0x0AA7397E,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0xB8BDF870,
            creation_time: 130884076352187500,
            directory_strings: 4,
        }],
    },
    Expect {
        id: "prefetch-artemis-win7-mscorsvw",
        version: 23,
        executable: r"MSCORSVW.EXE",
        hash: 0x57D17DAF,
        size: 10818,
        run_count: Some(1),
        runs: Some(&[133116574404817783]),
        metrics: 21,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\MSCTF.DLL"),
        metrics_crc: 0x3CAF0218,
        refs: 0,
        refs_crc: 0xF8E5A2ED,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0xB8BDF870,
            creation_time: 130884076352187500,
            directory_strings: 5,
        }],
    },
    Expect {
        id: "prefetch-artemis-win81-cl",
        version: 26,
        executable: r"CL.EXE",
        hash: 0x08C6C593,
        size: 1000188,
        run_count: Some(57),
        runs: Some(&[
            132231876394889881,
            132231874581932331,
            132231862779352682,
            132231856266220947,
            132231849814400418,
            132231808482512458,
            132231805269925733,
            132231798834693777,
        ]),
        metrics: 2142,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\USERS\BOB\APPDATA\LOCAL\TEMP\_CL_AFBF25EBIN"),
        metrics_crc: 0xFF67421B,
        refs: 1292,
        refs_crc: 0x1D4A5520,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0x7ADCE687,
            creation_time: 132210319819627282,
            directory_strings: 179,
        }],
    },
    Expect {
        id: "prefetch-artemis-win81-wwahost",
        version: 26,
        executable: r"WWAHOST.EXE",
        hash: 0xB72D66AF,
        size: 184414,
        run_count: Some(1),
        runs: Some(&[132210231380021261]),
        metrics: 260,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(
            r"\DEVICE\HARDDISKVOLUME2\USERS\BOB\APPDATA\LOCAL\PACKAGES\WINSTORE_CW5N1H2TXYEWY\LOCALSTATE\CACHE\0\0-PRODUCTTILEEXTENDEDBYPRODUCTGUID-HTTPS∺∯∯NEXT-SERVICES.APPS.MICROSOFT.COM∯BROWSE∯6.3.9600-0∯788∯EN-US_EN-US∯C∯US∯CP∯10005001∯APPS∯073E6AD7-D717-413F-9530-7D072B1863DA.DAT",
        ),
        metrics_crc: 0xB37A3D11,
        refs: 0,
        refs_crc: 0xE6F156A0,
        volumes: &[Volume {
            device_path: r"\DEVICE\HARDDISKVOLUME2",
            serial: 0x7ADCE687,
            creation_time: 132210319819627282,
            directory_strings: 50,
        }],
    },
    Expect {
        id: "prefetch-artemis-win81-svchost",
        version: 26,
        executable: r"SVCHOST.EXE",
        hash: 0x7AC6742A,
        size: 115072,
        run_count: Some(4),
        runs: Some(&[
            132719067467061774,
            132381316818961468,
            132364947222802247,
            132364815355408030,
        ]),
        metrics: 36,
        metrics_first: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\DEVICE\HARDDISKVOLUME2\WINDOWS\PREFETCH\LAYOUT.INI"),
        metrics_crc: 0xB7BBF552,
        refs: 33,
        refs_crc: 0xDB120949,
        volumes: &[
            Volume {
                device_path: r"\DEVICE\HARDDISKVOLUME1",
                serial: 0xF4DC2A38,
                creation_time: 132210319813691853,
                directory_strings: 0,
            },
            Volume {
                device_path: r"\DEVICE\HARDDISKVOLUME2",
                serial: 0x7ADCE687,
                creation_time: 132210319819627282,
                directory_strings: 506,
            },
        ],
    },
    Expect {
        id: "prefetch-artemis-win10-iu14d2n",
        version: 30,
        executable: r"_IU14D2N.TMP",
        hash: 0x136252D4,
        size: 153064,
        run_count: None,
        runs: Some(&[
            132999815644902066,
            132914522918597630,
            132847063973460210,
            132799506618644557,
            132764974653767440,
            132734648226186031,
        ]),
        metrics: 146,
        metrics_first: Some(r"\VOLUME{01d0f9a19c586134-d49d126f}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d0f9a19c586134-d49d126f}\WINDOWS\SYSTEM32\WIN32KFULL.SYS"),
        metrics_crc: 0xD1555397,
        refs: 113,
        refs_crc: 0x736312CE,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d0f9a19c586134-d49d126f}",
            serial: 0xD49D126F,
            creation_time: 130878861701833012,
            directory_strings: 42,
        }],
    },
    Expect {
        id: "prefetch-artemis-win10-am-delta-patch",
        version: 30,
        executable: r"AM_DELTA_PATCH_1.377.757.0.EX",
        hash: 0x0C03AAF4,
        size: 8396,
        run_count: None,
        runs: Some(&[133113118109414525]),
        metrics: 13,
        metrics_first: Some(r"\VOLUME{01d0f9a19c586134-d49d126f}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d0f9a19c586134-d49d126f}\$MFT"),
        metrics_crc: 0x49C11C69,
        refs: 0,
        refs_crc: 0xA66D1905,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d0f9a19c586134-d49d126f}",
            serial: 0xD49D126F,
            creation_time: 130878861701833012,
            directory_strings: 5,
        }],
    },
    Expect {
        id: "prefetch-artemis-win11-svchost",
        version: 30,
        executable: r"SVCHOST.EXE",
        hash: 0x576FFE64,
        size: 517188,
        run_count: None,
        runs: Some(&[133107907424293073, 133101139444733996, 133098370429875888]),
        metrics: 40,
        metrics_first: Some(r"\VOLUME{01d6828290579d13-4290933e}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(r"\VOLUME{01d800f8f40d0d56-34f4146b}\$MFT"),
        metrics_crc: 0xBD8300F0,
        refs: 37,
        refs_crc: 0x665A4C2D,
        volumes: &[
            Volume {
                device_path: r"\VOLUME{01d682828fb0b754-8c8fb0d4}",
                serial: 0x8C8FB0D4,
                creation_time: 132436736322090836,
                directory_strings: 0,
            },
            Volume {
                device_path: r"\VOLUME{01d6828290579d13-4290933e}",
                serial: 0x4290933E,
                creation_time: 132436736333028627,
                directory_strings: 64,
            },
            Volume {
                device_path: r"\VOLUME{01d800f8f40d0d56-34f4146b}",
                serial: 0x34F4146B,
                creation_time: 132857258253815126,
                directory_strings: 0,
            },
        ],
    },
    Expect {
        id: "prefetch-artemis-win11-7z",
        version: 30,
        executable: r"7Z.EXE",
        hash: 0x886612C8,
        size: 51060,
        run_count: None,
        runs: Some(&[133103602650425635]),
        metrics: 64,
        metrics_first: Some(r"\VOLUME{01d6828290579d13-4290933e}\WINDOWS\SYSTEM32\NTDLL.DLL"),
        metrics_last: Some(
            r"\VOLUME{01d6828290579d13-4290933e}\USERS\BOB\APPDATA\LOCAL\TEMP\CHOCOLATEY\PSEXEC.2.40\EULA.TXT",
        ),
        metrics_crc: 0x1B0D3F7C,
        refs: 0,
        refs_crc: 0x189225F1,
        volumes: &[Volume {
            device_path: r"\VOLUME{01d6828290579d13-4290933e}",
            serial: 0x4290933E,
            creation_time: 132436736333028627,
            directory_strings: 15,
        }],
    },
];

/// Files dissect also fails to read.
const DAMAGED: &[&str] = &[
    "prefetch-artemis-bad-compression",
    "prefetch-artemis-malformed",
];

fn crc(text: &str) -> u32 {
    crc32fast::hash(text.as_bytes())
}

#[test]
fn matches_an_independent_parser() {
    let mut checked = 0;
    for want in EXPECTED {
        let Some(path) = forensic_testdata::artifact(want.id) else {
            continue;
        };
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let data = std::fs::read(&path).unwrap();
        let pf = read_prefetch_bytes(&name, &data).unwrap_or_else(|e| panic!("{}: {e:?}", want.id));
        let id = want.id;
        assert_eq!(pf.version, want.version, "{id}");
        assert_eq!(pf.name, want.executable, "{id}");
        assert_eq!(pf.hash, want.hash, "{id}");
        assert_eq!(pf.file_size, want.size, "{id}");
        if let Some(run_count) = want.run_count {
            assert_eq!(pf.run_count, run_count, "{id}");
        }
        if let Some(runs) = want.runs {
            let got: Vec<u64> = pf
                .last_run_times
                .iter()
                .map(|t| t.to_win_filetime().expect("after 1601"))
                .collect();
            assert_eq!(got, runs, "{id}");
        }
        let names: Vec<&str> = pf.metrics.iter().map(|m| m.file.as_str()).collect();
        assert_eq!(names.len(), want.metrics, "{id}");
        assert_eq!(names.first().copied(), want.metrics_first, "{id}");
        assert_eq!(names.last().copied(), want.metrics_last, "{id}");
        assert_eq!(crc(&names.join("\n")), want.metrics_crc, "{id}");
        let refs: Vec<u64> = pf
            .metrics
            .iter()
            .map(|m| {
                m.file_reference
                    .as_ref()
                    .map_or(0, |r| r.mft_entry | (u64::from(r.seq_number) << 48))
            })
            .collect();
        assert_eq!(refs.iter().filter(|r| **r != 0).count(), want.refs, "{id}");
        let joined: Vec<String> = refs.iter().map(u64::to_string).collect();
        assert_eq!(crc(&joined.join(",")), want.refs_crc, "{id}");
        assert_eq!(pf.volume.len(), want.volumes.len(), "{id}");
        for (got, want_v) in pf.volume.iter().zip(want.volumes) {
            assert_eq!(got.device_path, want_v.device_path, "{id}");
            assert_eq!(got.serial_number, want_v.serial, "{id}");
            assert_eq!(got.creation_time, want_v.creation_time, "{id}");
            assert_eq!(
                got.directory_strings.len(),
                want_v.directory_strings,
                "{id}"
            );
        }
        checked += 1;
    }
    eprintln!("checked {checked} of {} prefetch files", EXPECTED.len());
}

#[test]
fn damaged_files_are_errors() {
    for id in DAMAGED {
        let Some(path) = forensic_testdata::artifact(id) else {
            continue;
        };
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let data = std::fs::read(&path).unwrap();
        assert!(read_prefetch_bytes(&name, &data).is_err(), "{id}");
    }
}
