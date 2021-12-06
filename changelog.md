# Changelog of ctwin32

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [1.2.0]

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

## [1.1.0]

### Added

 - The functions OpenEventLog, CloseEventLog and ReadEventLog were added to
   advapi.
 - The sample uptime_evt.py demonstrates a way how these functions can be used.
 - The module msi and the accompanying sample exbinmsi.py were added.
 - The functions get_directory_info and enum_directory_info were added to
   ntdll. The sample listpipes.py demonstrates a way how these functions can
   be used.

## [1.0.0]

### Fixed

 - The way ctwin32.GUID was defined led to a wrong alignment requirement. The
   value was 1, now it is 4.
 - The sample atta_vdisk.py contained several bugs/problems.

### Added

 - Sample sua_enums.py

## [0.1.4]

### Added

 - Everything. All this happened before the dawn of time (i.e. before the
   existence of this change log).
