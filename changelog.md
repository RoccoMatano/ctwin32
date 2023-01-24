# Changelog of ctwin32

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- special method `__str__` for UNICODE_STRING

### Changed

- building ctwin32 is now based on pyproject.toml and setuptools.build_meta
- renamed `ctwin32.version` to `ctwin32.__version__` and `ctwin32.version_info`
  to `ctwin32.version` (**_not_** backwards compatible)

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
- do not use `from .wtypes import \*` anymore

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

[Unreleased]: https://github.com/RoccoMatano/ctwin32/compare/1.11.0...master
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
