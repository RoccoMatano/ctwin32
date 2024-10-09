# Changelog of ctwin32

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres somewhat to [Semantic Versioning](
http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2024-10-09

### Added

- advapi.RegLoadAppKey
- advapi.enum_event_log
- powrprof.PowerInformationWithPrivileges
- advapi.CreateWellKnownSid
- advapi.SetThreadToken
- advapi.enable_token_privileges
- advapi.enable_privileges
- advapi.AllocateLocallyUniqueId
- advapi.make_token_groups
- secur.LsaDeregisterLogonProcess
- secur.LsaConnectUntrusted
- secur.LsaStrFromStr
- secur.LsaLookupAuthenticationPackage
- secur.LsaLogonUser
- wtypes.wchar_len_sz
- wtypes.UnicodeStrFromStr
- wtypes.UnicodeStrArray
- sample run_s4u.py
- advapi.IsWellKnownSid
- advapi.OpenThreadToken
- advapi.GetCurrentProcessToken
- advapi.GetCurrentThreadToken
- advapi.GetCurrentThreadEffectiveToken
- advapi.running_as_system
- advapi.get_token_elevation_type
- advapi.is_elevated_via_uac
- kernel.GetCurrentThread
- ntdll.NtQueryInformationThread
- ntdll.get_thread_basic_info
- ntdll.NtGetNextThread
- psapi.GetProcessImageFileName

### Changed

- split up module `misc` into `dbghelp`, `powrprof`, `userenv` and
  `wtsapi` (**_not backwards compatible_**)
- replaced MIT license text with SPDX-License-Identifier in python files
- moved LOWORD and HIWORD from `wtypes` to `ctwin32`
- let ctwin32.ns_from_struct work recursively
- adapted sample `uptime_evt.py` to use advapi.enum_event_log
- do not use the windows platform tags anymore when creating wheels as this
  was futile anyway (no more need for setup.py)
- adapted sample `power_requests.py` to use
  powrprof.PowerInformationWithPrivileges
- moved `terminate_on_exception` from user to kernel

## [2.7.1] - 2024-07-15

### Fixed

- fixed several bugs in pemap

## [2.7.0] - 2024-07-09

### Added

- advapi.RegFlushKey
- advapi.get_token_user
- advapi.get_token_groups
- user.GetProcessWindowStation
- user.GetThreadDesktop
- user.GetUserObjectInformation
- user.is_interactive_process
- user.terminate_on_exception
- kernel.ReadFile
- kernel.WriteFile
- kernel.read_file_text
- kernel.write_file_text
- kernel.FlushFileBuffers
- kernel.CreateNamedPipe
- kernel.ConnectNamedPipe
- kernel.DisconnectNamedPipe
- kernel.create_named_pipe
- sample named_pipe.py
- kernel.get_local_tzinfo
- kernel.FindFirstFileName
- kernel.FindNextFileName
- kernel.find_all_filenames
- kernel.GetFileInformationByHandle
- sample hardlinks.py
- kernel.CreateFileMapping
- kernel.MapViewOfFile
- kernel.UnmapViewOfFile
- kernel.GetFileSize
- kernel.GetFileSizeEx
- module pemap
- sample fimex.py

### Changed

- switched to using ctypes' last error shadow copy
- support to supply name, icon and style when creating WndCreateParams
- sample `simple_aes.py` also supports module `cryptography` in addition to
  `pyaes`
- reworked handling of exceptions in callbacks
- reworked advapi.ReadEventLog and secur.LsaGetLogonSessionData to return
  local timestamps with appropriate timezone
- moved class ApiSet from sample api_set.py to module pemap

### Fixed

- fixed string length handling in sample dump_ver_res.py
- fixed result processing in ntdll.get_directory_info


## [2.6.0] - 2024-05-09

### Added

- cfgmgr.CM_Get_Device_Interface_List_Size
- cfgmgr.CM_Get_Device_Interface_List
- ntdll.SYSTEM_BASIC_INFORMATION
- ntdll.SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
- sample cnt_irq.py
- gdi.SetBkColor
- gdi.ExtTextOut
- gdi.fill_solid_rect
- kernel.QueryInformationJobObject
- sample timeit.py
- sample dump_proc_env.py
- wtypes.byte_buffer and wtypes.string_buffer
- python 3.13 in pyproject.toml

### Changed

- let sample 'restart_usb_port.py' use cfgmgr.CM_Get_Device_Interface_List
  instead of setupapi.SetupDiGetDeviceInterfaceDetail
- support for addition and subtraction of FILETIME
- add parameter 'inherit' to CreateEnvironmentBlock and create_env_block_as_dict
- replaced ctypes.create_string|unicode_buffer with wtypes.byte_buffer and
  wtypes.string_buffer

### Fixed

- fixed handling of "\0\0" in ctwin32.multi_str_from_str

## [2.5.0] - 2024-03-11

### Added

- kernel.CreateIoCompletionPort
- kernel.create_io_completion_port
- kernel.GetQueuedCompletionStatus
- kernel.GetCommandLine
- kernel.CreateJobObject
- kernel.AssignProcessToJobObject
- kernel.SetInformationJobObject
- kernel.ResumeThread
- sample wait_for_job.py

## [2.4.0] - 2023-10-03

### Added

- svc_util.running_as_trusted_installer
- ntdll.get_proc_command_line
- ntdll.get_proc_env_blk
- ntdll.get_wow64_proc_env_blk
- kernel.ReadProcessMemory
- kernel.WriteProcessMemory
- kernel.get_proc_env_as_dict
- advapi.EncryptFile
- advapi.DecryptFile
- misc.UnDecorateSymbolName

### Changed

- replaced function argc_argv_from_args by class wtypes.ArgcArgvFromArgs
  (removing shaky manual lifetime mamagement).
- to improve efficiency a little, use `from_buffer` instead of `from_address`
  where approriate
- improve usage of ntdll.NtQuerySystemInformation
- use `id` instead of `pvoid_from_obj`
- renamed wndcls.dlg_item_bytes to dlg_item_template
- renamed wndcls.dlg_bytes to dlg_template

### Fixed

- ntdll.get_handles did not handle the case where new handles were created
  between asking for the required buffer size and actually retrieving the
  handles

## [2.3.0] - 2023-07-04

### Added

- kernel.PowerCreateRequest
- kernel.PowerSetRequest
- kernel.PowerClearRequest
- kernel.create_power_request
- ruff and flake8 config in pyproject.toml
- kernel.GetDriveType
- kernel.GetLogicalDriveStrings
- kernel.FindFirstVolume
- kernel.FindNextVolume
- kernel.FindVolumeClose
- kernel.enum_volumes
- kernel.GetVolumePathNamesForVolumeName
- sample volume_paths.py
- ntdll.RtlGetCurrentPeb
- cfgmgr.CM_Locate_DevNode
- cfgmgr.CM_Get_DevNode_Registry_Property
- sample restart_usb_port.py
- sample api_set.py
- advapi.DuplicateTokenEx
- advapi.SetTokenInformation
- advapi.CreateProcessAsUser
- advapi.create_process_as_user
- advapi.StartServiceCtrlDispatcher
- advapi.RegisterServiceCtrlHandler
- advapi.SetServiceStatus
- sample lsc.py
- advapi.GetTokenInformation
- kernel.dbg_print
- module svc_util with functions
  - func_as_system
  - create_process_in_session_copy_token
  - func_as_trusted_installer
  - proc_as_trusted_installer

### Changed

- extended sample power_requests.py to demonstrate the effect of
  kernel.create_power_request
- 'multi-strings' (strings that represent a list of strings by joining its
  elements with `\0`) are now always returned as a list of plain strings.
- greatly simplified sample lsc.py by using svc_util

### Fixed

- fixed kernel.QueryDosDevice to support `None` as input parameter (returning
  the list of all MS-DOS device names)
- checking the return code of kernel.GlobalUnlock
- member names in the following structures were missing prefixes (hungarian
  notation):
  - advapi.SERVICE_STATUS
  - advapi.SERVICE_STATUS_PROCESS
  - advapi.ENUM_SERVICE_STATUS_PROCESS
  - advapi.QUERY_SERVICE_CONFIG
  - misc.WTS_SESSION_INFO
  - user.WINDOWPLACEMENT
  - wtypes.FILETIME
  - wtypes.SYSTEMTIME

## [2.2.0] - 2023-05-27

### Added

- ntdll.RtlGetVersion
- context manager `suppress_winerr`
- kernel.FindFirstFile
- kernel.FindNextFile
- kernel.iter_dir
- kernel.find_file
- sample print_reparse_points.py
- kernel.GetExitCodeProcess
- user.LoadString
- ntdll.NtPowerInformation
- sample power_requests.py

### Changed

- ctwin32 no longer intends to support Windows versions older than Windows 10.
Upon import ctwin32 now emits a corresponding warning when it is running on
such an old version.
- shell.ShellExecuteEx now returns the exit code of a process when called with
  `wait=True`.

### Fixed

- fixed extraction of SID in advapi.ReadEventLog

## [2.1.0] - 2023-03-27

### Added

- `__eq__ ` for `GUID`
- sample fopa.py
- sample dump_ver_res.py
- the `samples` directory is now included in `sdist`

### Fixed

 - `:=` precedence in advapi

## [2.0.0] - 2023-02-19

### Added

- special method `__str__` for UNICODE_STRING

### Changed

- building ctwin32 is now based on pyproject.toml and setuptools.build_meta
- renamed `ctwin32.version` to `ctwin32.__version__` and `ctwin32.version_info`
  to `ctwin32.version` (**_not backwards compatible_**)
- dropped support for Python 3.6 and 3.7 (**_not backwards compatible_**)

## [1.11.0] - 2022-12-16

### Added

- kernel.GetConsoleMode
- kernel.SetConsoleMode
- kernel.enable_virt_term
- sample virt_term_seq.py
- kernel.SetErrorMode
- kernel.SetThreadErrorMode
- module psapi with EnumProcesses, EnumProcessModules, EnumProcessModulesEx,
  GetMappedFileName, GetModuleFileNameEx and GetModuleInformation
- user.build_wnd_list
- kernel.create_file
- kernel.ProcessIdToSessionId
- kernel.GetCurrentDirectory
- kernel.SetCurrentDirectory
- argc_argv_from_args
- iphlpapi.GetIpNetTable2 and sample arp_table.py
- iphlpapi.ConvertInterfaceGuidToLuid, iphlpapi.ConvertInterfaceIndexToLuid,
  iphlpapi.ConvertInterfaceLuidToAlias and iphlpapi.ConvertInterfaceLuidToName

### Changed

- use new convert functions in sample netifaces.py

### Fixed

- in example remove_drive_by_letter.py the move of the CM_* functions to cfgmgr
  was not yet implemented
- kernel.SECURITY_ATTRIBUTES
- kernel.GetSystemDirectory
- handling of service arguments in advapi.StartService

## [1.10.0] - 2022-10-26

### Added

- kernel.GetStdHandle
- kernel.GetFileType
- kernel.SetConsoleTextAttribute
- kernel.GetConsoleScreenBufferInfo
- kernel.FillConsoleOutputCharacter
- kernel.FillConsoleOutputAttribute
- kernel.SetConsoleCursorPosition
- kernel.clear_screen
- kernel.cls


### Changed

- prettify code
- do not use `from .wtypes import *` anymore

### Fixed

- several missing imports and misspellings

## [1.9.0] - 2022-07-30

### Added

- kernel.GetModuleFileName
- kernel.IsWow64Process and kernel.get_wow64_info
- user.center_wnd
- user.GetDlgItemText
- user.CheckRadioButton
- user.GetDlgCtrlID
- user.DialogBoxIndirectParam
- user.CreateDialogIndirectParam
- user.EndDialog
- classes BaseDlg and InputDlg in wndcls

### Changed

- shell.ShellExecuteEx now accepts PathLike objects for its file argument

### Fixed

- in kernel.load_message_string compare message ID as unsigned value
- wtypes.POINT.as_lparam

## [1.8.0] - 2022-05-06

### Added

- sample endis_bsl_usb.py
- user.SetFocus and BaseWnd.set_focus
- user.GetGUIThreadInfo
- kernel.FreeLibrary
- kernel.LoadLibrary
- kernel.LoadLibraryEx
- kernel.EnumResourceNames
- kernel.FindResource
- kernel.SizeofResource
- kernel.LoadResource
- kernel.get_resource_info
- sample extract_ico.py
- ctwin32.raise_on_zero and wtypes.ScdToBeClosed.raise_on_invalid
- use WinDLL("\<name>") instead of windll.\<name>
- kernel.GlobalGetAtomName
- user.get_prop_dict
- user.GetClipboardFormatName
- user.EnumClipboardFormats
- ctwin32.ns_from_struct
- kernel.GetSystemInfo
- misc.get_system_processor_power_info
- user.\_SystemParametersInfo in order to implement get/set_non_client_metrics,
  get/set_wheel_scroll_lines and get_work_area in user
- module ctwin32.version_info
- sample py_ver.py
- kernel.load_message_string

### Changed

- replaced calls to raise_if with raise_on_zero or raise_on_invalid where
  applicable
- move cfgmgr32.dll functionality from setupapi to new module cfgmgr
- use ns_from_struct where appropriate
- the namespaces returned by WTSEnumerateSessions are now using the standard
  win32 names (camel case instead of snake case)
- moved definition of LOGFONT from gdi to wtypes

### Fixed

- keyboard handling in sample calendar.pyw
- signature of EnumPropsEx callback function (PVOID instead of PWSTR)

## [1.7.12] - 2022-03-10

### Added
- module bcrypt with functions required for creating and verifying signatures
- samples rm_sign_tool.py and test_sign_tool.py
- extended bcrypt for encryption
- sample simple_aes.py
- sample senv.py
- ENDIANNESS in wtypes
- is_registry_string in advapi
- sample stopnow.py
- shell.SHGetFolderPath
- user.CreateIconFromResourceEx
- wndcls.load_py_ico
- kernel.GlobalAddAtom
- kernel.global_add_atom
- kernel.GlobalDeleteAtom
- doc/images/ctwin32.ico and wndcls.load_ctwin32_ico

### Changed

- removed duplicate constants from \_\_init\_\_.py
- since py3.11 will support ARM64 on windows, also build a wheel with the
  corresponding platform tag
- moved virtual disk constants from \_\_init\_\_.py to virtdisk.py
- moved GAA_FLAG_* constants from \_\_init\_\_.py to iphlpapi.py
- removed unused import from keyview.pyw
- allow GetKeyNameText to return an empty string on purpose
- use atom instead of string for SimpleWnd window property
- revised this changelog
- use wndcls.load_ctwin32_ico in samples calendar, hello_wnd and keyview

### Fixed

- fixed wrong \_raise_failed_status import in misc
- fixed and simplified wtypes.ScdToBeClosed.from_param (no more integer overflow)

## [1.6.0] - 2022-02-18

### Added

- gdi.GetTextMetrics
- gdi.GetStockObject
- gdi.SetBkMode
- gdi.TextOut
- user.GetSystemMetrics
- user.ScrollWindow
- user.GetKeyNameText
- sample keyview.pyw
- advapi.QueryServiceConfig
- advapi.LookupAccountSid
- advapi ACL/ACE types
- advapi.GetAce
- advapi.GetSecurityDescriptorDacl
- advapi.GetSecurityDescriptorOwner
- advapi.GetSecurityDescriptorGroup
- advapi.GetSecurityDescriptorLength
- advapi.GetNamedSecurityInfo
- advapi.SetNamedSecurityInfo
- module secur
- secure.LsaFreeReturnBuffer
- secure.LsaGetLogonSessionData
- secure.LsaEnumerateLogonSessions
- sample logonsessions.py
- user.AdjustWindowRectEx
- methods `copy` and `__repr__` for POINT and RECT
- sample calendar.pyw

### Changed

- mostly internal refactorings, but with a small impact on the samples (ctypes
  is now included in ctwin32's namespace)
- improved handling of `None` in ScdToBeClosed
- extend list of SE_\*_NAME constants
- let advapi.OpenProcessToken return a context manager object
- moved definition of LUID and UNICODE_STRING to wtypes
- renamed \_raise_failed_status to raise_failed_status in ntdll
- be more precise about dealing with GUIDs in advapi
- let HDEVINFOs be context managers in setupapi

### Fixed

- fixed BaseWnd.invalidate_rect, BaseWnd.set_pos and BaseWnd.release_dc
- fixed parameter quoting in shell.elevate
- fix splitting strings in kernel.env_str_to_dict
- fixed various return types in ntdll from ULONG to LONG by using LONG's
  alias NTSTATUS, which is now available in wtypes
- fixed BaseWnd.\_\_init\_\_

## [1.5.0] - 2022-01-17

### Added

- sample netifaces.py
- constants in ctwin32 for icons, colors and buttons
- kernel.ExitProcess
- kernel.GetModuleHandle
- kernel.GlobalFree
- kernel.GlobalAlloc
- kernel.GlobalLock
- kernel.GlobalUnlock
- user.SetWindowLong
- user.SetWindowLongPtr
- user.PostQuitMessage
- user.SetWindowText
- user.GetClientRect
- methods from_lparam and as_lparam for POINT
- user.LoadCursor
- user.LoadIcon
- user.DefWindowProc
- user.GetClassInfo
- user.RegisterClass
- user.CreateWindowEx
- user.GetMessage
- user.TranslateMessage
- user.DispatchMessage
- user.ShowWindow
- user.UpdateWindow
- user.DestroyWindow
- user.IsWindow
- user.GetDlgItem
- user.SendDlgItemMessage
- user.SetDlgItemText
- user.EnableWindow
- user.SetForegroundWindow
- user.GetParent
- user.InvalidateRect
- user.WindowFromPoint
- user.MoveWindow
- user.MapWindowPoints
- user.GetCursorPos
- user.GetDC
- user.GetWindowDC
- user.ReleaseDC
- user.SetTimer
- user.KillTimer
- user.CheckDlgButton
- user.IsDlgButtonChecked
- user.BeginPaint
- user.EndPaint
- user.DrawText
- user.SetProp
- user.GetProp
- user.RemoveProp
- user.EnumPropsEx
- user.OpenClipboard
- user.EmptyClipboard
- user.SetClipboardData
- user.GetClipboardData
- user.IsClipboardFormatAvailable
- user.CloseClipboard
- user.txt_to_clip
- user.txt_from_clip
- module gdi
- gdi.GetDeviceCaps
- gdi.CreateFontIndirect
- gdi.SelectObject
- gdi.DeleteObject
- classes BaseWnd, WND_CREATE and SimpleWnd in wndcls.py
- sample hello_wnd.pyw
- module comctl
- comctl.TaskDialog
- comctl.TaskDialogIndirect
- comctl.tsk_dlg_callback
- kernel.GetSystemDirectory
- CreateActCtx, ActivateActCtx, DeactivateActCtx amd ReleaseActCtx in kernel
- comctl.tsk_dlg_centered

### Changed

- sample listpipes.py is using kernel.CreateFile instead of open and
  msvcrt.get_osfhandle.
- moved definition of POINT and RECT from user to wtypes
- simplified definition of PROC_THREAD_ATTRIBUTE constants
- advapi.OpenEventLog returns context manager EHANDLE
- revised sample uptime_evt.py
- advapi.OpenSCManager, advapi.OpenService and advapi.CreateService return
  context manager SC_HANDLE
- moved \_EnumContext and \_EnumContextPtr from user to wtypes and renamed them
  to CallbackContext and CallbackContextPtr
- sample hello_wnd.py now demonstrates comctl.tsk_dlg_callback on right-click
- setup activation context in comctl before loading comctl32.dll

## [1.4.0] - 2021-12-23

### Added

- kernel.PROCESS_INFORMATION, kernel.STARTUPINFO and kernel.STARTUPINFOEX
- kernel.InitializeProcThreadAttributeList, kernel.UpdateProcThreadAttribute,
  kernel.DeleteProcThreadAttributeList and kernel.ProcThreadAttributeList
- kernel.CreateProcess and kernel.create_process
- user.EnumThreadWindows and user.get_thread_window_list
- properties width, height and center of user.RECT
- user.GetWindowRect
- user.SetWindowPos
- user.GetShellWindow
- user.MonitorFromWindow
- user.MONITORINFO and user.GetMonitorInfo
- user.start_centered
- shell.relegate
- shell.CommandLineToArgv
- cmdline_from_args

### Changed

- virtdisk.OpenVirtualDisk returns context manager KHANDLE

## [1.3.0] - 2021-12-06

### Added

- module wtypes as replacement for ctypes.wintypes
- class wtypes.ScdToBeClosed that eases creating context managers for handles
- user.SendMessageTimeout
- kernel.GetEnvironmentVariable
- kernel.SetEnvironmentVariable
- kernel.GetEnvironmentStrings
- kernel.get_env_as_dict
- kernel.SetEnvironmentStrings
- kernel.ExpandEnvironmentStrings
- advapi.RegDeleteValue
- advapi.RegSetKeyValue
- advapi.reg_enum_keys
- advapi.reg_enum_values
- advapi.reg_set_str
- advapi.reg_set_dword
- misc.CreateEnvironmentBlock
- misc.create_env_block_as_dict

### Changed

- advapi: Let predefined keys (e.g. HKCU) be instances of HKEY (i.e they
  can be used in `with` statements like ordinary keys).

## [1.2.0] - 2021-11-29

### Added

- kernel.CreateFile
- kernel.DeviceIoControl
- setupapi.CM_Get_Parent
- setupapi.CM_Request_Device_Eject
- setupapi.SetupDiEnumDeviceInterfaces
- setupapi.enum_dev_interfaces
- setupapi.SetupDiGetDeviceInterfaceDetail
- All the above was added to implement the sample remove_drive_by_letter.py

### Fixed

- Fixed memory allocation race in ntdll.enum_processes
- Fixed unreliable cleanup in setupapi.enum_info_set

## [1.1.0] - 2021-11-06

### Added

- The functions OpenEventLog, CloseEventLog and ReadEventLog were added to
  advapi.
- The sample uptime_evt.py demonstrates a way how these functions can be used.
- The module msi and the accompanying sample exbinmsi.py were added.
- The functions get_directory_info and enum_directory_info were added to
  ntdll. The sample listpipes.py demonstrates a way how these functions can
  be used.

## [1.0.0] - 2021-10-20

### Fixed

- The way ctwin32.GUID was defined led to a wrong alignment requirement. The
  value was 1, now it is 4.
- The sample atta_vdisk.py contained several bugs/problems.

### Added

- Sample sua_enums.py

## [0.1.4] - 2021-10-20

### Added

- Everything. All this happened before the dawn of time (i.e. before the
  existence of this change log).

[Unreleased]: https://github.com/RoccoMatano/ctwin32/compare/3.0.0...master
[3.0.0]: https://github.com/RoccoMatano/ctwin32/compare/2.7.1...3.0.0
[2.7.1]: https://github.com/RoccoMatano/ctwin32/compare/2.7.0...2.7.1
[2.7.0]: https://github.com/RoccoMatano/ctwin32/compare/2.6.0...2.7.0
[2.6.0]: https://github.com/RoccoMatano/ctwin32/compare/2.5.0...2.6.0
[2.5.0]: https://github.com/RoccoMatano/ctwin32/compare/2.4.0...2.5.0
[2.4.0]: https://github.com/RoccoMatano/ctwin32/compare/2.3.0...2.4.0
[2.3.0]: https://github.com/RoccoMatano/ctwin32/compare/2.2.0...2.3.0
[2.2.0]: https://github.com/RoccoMatano/ctwin32/compare/2.1.0...2.2.0
[2.1.0]: https://github.com/RoccoMatano/ctwin32/compare/2.0.0...2.1.0
[2.0.0]: https://github.com/RoccoMatano/ctwin32/compare/1.11.0...2.0.0
[1.11.0]: https://github.com/RoccoMatano/ctwin32/compare/1.10.0...1.11.0
[1.10.0]: https://github.com/RoccoMatano/ctwin32/compare/1.9.0...1.10.0
[1.9.0]: https://github.com/RoccoMatano/ctwin32/compare/1.8.0...1.9.0
[1.8.0]: https://github.com/RoccoMatano/ctwin32/compare/1.7.12...1.8.0
[1.7.12]: https://github.com/RoccoMatano/ctwin32/compare/1.6.0...1.7.12
[1.6.0]: https://github.com/RoccoMatano/ctwin32/compare/1.5.0...1.6.0
[1.5.0]: https://github.com/RoccoMatano/ctwin32/compare/1.4.0...1.5.0
[1.4.0]: https://github.com/RoccoMatano/ctwin32/compare/1.3.0...1.4.0
[1.3.0]: https://github.com/RoccoMatano/ctwin32/compare/1.2.0...1.3.0
[1.2.0]: https://github.com/RoccoMatano/ctwin32/compare/1.1.0...1.2.0
[1.1.0]: https://github.com/RoccoMatano/ctwin32/compare/1.0.0...1.1.0
[1.0.0]: https://github.com/RoccoMatano/ctwin32/compare/0.1.4...1.0.0
[0.1.4]: https://github.com/RoccoMatano/ctwin32/releases/tag/0.1.4
