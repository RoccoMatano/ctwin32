# Changelog of ctwin32

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

 - The functions OpenEventLog, CloseEventLog and ReadEventLog were added to
   advapi.
 - The sample uptime_evt.py demonstrates a way how these functions can be used.

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
