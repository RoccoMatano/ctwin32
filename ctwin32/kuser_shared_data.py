################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################

from .wtypes import (
    BOOLEAN,
    BYTE,
    Struct,
    INT,
    LARGE_INTEGER,
    LONG,
    LONGLONG,
    ULONG,
    ULONGLONG,
    USHORT,
    WCHAR,
    )

################################################################################

class KSYSTEM_TIME(Struct):
    _fields_ = (
        ("LowPart", ULONG),
        ("High1Time", LONG),
        ("High2Time", LONG),
        )

class XSTATE_FEATURE(Struct):
    _fields_ = (
        ("Offset", ULONG),
        ("Size", ULONG),
        )

MAXIMUM_XSTATE_FEATURES = 64
PROCESSOR_FEATURE_MAX = 64

class XSTATE_CONFIGURATION(Struct):
    _fields_ = (
        ("EnabledFeatures", ULONGLONG),
        ("EnabledVolatileFeatures", ULONGLONG),
        ("Size", ULONG),
        ("ControlFlags", ULONG),
        ("Features", XSTATE_FEATURE * MAXIMUM_XSTATE_FEATURES),
        ("EnabledSupervisorFeatures", ULONGLONG),
        ("AlignedFeatures", ULONGLONG),
        ("AllFeatureSize", ULONG),
        ("AllFeatures", ULONG * MAXIMUM_XSTATE_FEATURES),
        ("EnabledUserVisibleSupervisorFeatures", ULONGLONG),
        ("ExtendedFeatureDisableFeatures", ULONGLONG),
        ("AllNonLargeFeatureSize", ULONG),
        ("Spare", ULONG),
        )

################################################################################

class KUSER_SHARED_DATA(Struct):
    _fields_ = (
        ("TickCountLowDeprecated", ULONG),
        ("TickCountMultiplier", ULONG),
        ("InterruptTime", KSYSTEM_TIME),
        ("SystemTime", KSYSTEM_TIME),
        ("TimeZoneBias", KSYSTEM_TIME),
        ("ImageNumberLow", USHORT),
        ("ImageNumberHigh", USHORT),
        ("NtSystemRoot", WCHAR * 260),
        ("MaxStackTraceDepth", ULONG),
        ("CryptoExponent", ULONG),
        ("TimeZoneId", ULONG),
        ("LargePageMinimum", ULONG),
        ("AitSamplingValue", ULONG),
        ("AppCompatFlag", ULONG),
        ("RNGSeedVersion", ULONGLONG),
        ("GlobalValidationRunlevel", ULONG),
        ("TimeZoneBiasStamp", LONG),
        ("NtBuildNumber", ULONG),
        ("NtProductType", INT),
        ("ProductTypeIsValid", BOOLEAN),
        ("Reserved0", BOOLEAN),
        ("NativeProcessorArchitecture", USHORT),
        ("NtMajorVersion", ULONG),
        ("NtMinorVersion", ULONG),
        ("ProcessorFeatures", BOOLEAN * PROCESSOR_FEATURE_MAX),
        ("Reserved1", ULONG),
        ("Reserved3", ULONG),
        ("TimeSlip", ULONG),
        ("AlternativeArchitecture", INT),
        ("BootId", ULONG),
        ("SystemExpirationDate", LARGE_INTEGER),
        ("SuiteMask", ULONG),
        ("KdDebuggerEnabled", BOOLEAN),
        ("MitigationPolicies", BYTE),
        ("CyclesPerYield", USHORT),
        ("ActiveConsoleId", ULONG),
        ("DismountCount", ULONG),
        ("ComPlusPackage", ULONG),
        ("LastSystemRITEventTickCount", ULONG),
        ("NumberOfPhysicalPages", ULONG),
        ("SafeBootMode", BOOLEAN),
        ("VirtualizationFlags", BYTE),
        ("Reserved12", BYTE * 2),
        ("SharedDataFlags", ULONG),
        ("DataFlagsPad", ULONG),
        ("TestRetInstruction", ULONGLONG),
        ("QpcFrequency", LONGLONG),
        ("SystemCall", ULONG),
        ("Reserved2", ULONG),
        ("SystemCallPad", ULONGLONG * 2),
        ("TickCountQuad", ULONGLONG),
        ("TickCountPad", ULONGLONG),
        ("Cookie", ULONG),
        ("CookiePad", ULONG),
        ("ConsoleSessionForegroundProcessId", LONGLONG),
        ("TimeUpdateLock", ULONGLONG),
        ("BaselineSystemTimeQpc", ULONGLONG),
        ("BaselineInterruptTimeQpc", ULONGLONG),
        ("QpcSystemTimeIncrement", ULONGLONG),
        ("QpcInterruptTimeIncrement", ULONGLONG),
        ("QpcSystemTimeIncrementShift", BYTE),
        ("QpcInterruptTimeIncrementShift", BYTE),
        ("UnparkedProcessorCount", USHORT),
        ("EnclaveFeatureMask", ULONG * 4),
        ("TelemetryCoverageRound", ULONG),
        ("UserModeGlobalLogger", USHORT * 16),
        ("ImageFileExecutionOptions", ULONG),
        ("LangGenerationCount", ULONG),
        ("Reserved4", ULONGLONG),
        ("InterruptTimeBias", ULONGLONG),
        ("QpcBias", ULONGLONG),
        ("ActiveProcessorCount", ULONG),
        ("ActiveGroupCount", BYTE),
        ("Reserved9", BYTE),
        ("QpcData", USHORT),
        ("TimeZoneBiasEffectiveStart", LARGE_INTEGER),
        ("TimeZoneBiasEffectiveEnd", LARGE_INTEGER),
        ("XState", XSTATE_CONFIGURATION),
        ("FeatureConfigurationChangeStamp", KSYSTEM_TIME),
        ("Spare", ULONG),
        ("UserPointerAuthMask", ULONGLONG),
    )

KUSER_SHARED_DATA_ADDRESS = 0x7FFE0000

################################################################################

def get_ref():
    return KUSER_SHARED_DATA.from_address(KUSER_SHARED_DATA_ADDRESS)

################################################################################

def get_data():
    # have to make a copy in order to actually adopt the data NOW!
    return KUSER_SHARED_DATA.from_buffer_copy(get_ref())

################################################################################

def _validate():
    assert KUSER_SHARED_DATA.TickCountLowDeprecated.offset == 0x0
    assert KUSER_SHARED_DATA.TickCountMultiplier.offset == 0x4
    assert KUSER_SHARED_DATA.InterruptTime.offset == 0x08
    assert KUSER_SHARED_DATA.SystemTime.offset == 0x014
    assert KUSER_SHARED_DATA.TimeZoneBias.offset == 0x020
    assert KUSER_SHARED_DATA.ImageNumberLow.offset == 0x02c
    assert KUSER_SHARED_DATA.ImageNumberHigh.offset == 0x02e
    assert KUSER_SHARED_DATA.NtSystemRoot.offset == 0x030
    assert KUSER_SHARED_DATA.MaxStackTraceDepth.offset == 0x238
    assert KUSER_SHARED_DATA.CryptoExponent.offset == 0x23c
    assert KUSER_SHARED_DATA.TimeZoneId.offset == 0x240
    assert KUSER_SHARED_DATA.LargePageMinimum.offset == 0x244
    assert KUSER_SHARED_DATA.AitSamplingValue.offset == 0x248
    assert KUSER_SHARED_DATA.AppCompatFlag.offset == 0x24c
    assert KUSER_SHARED_DATA.RNGSeedVersion.offset == 0x250
    assert KUSER_SHARED_DATA.GlobalValidationRunlevel.offset == 0x258
    assert KUSER_SHARED_DATA.TimeZoneBiasStamp.offset == 0x25c
    assert KUSER_SHARED_DATA.NtBuildNumber.offset == 0x260
    assert KUSER_SHARED_DATA.NtProductType.offset == 0x264
    assert KUSER_SHARED_DATA.ProductTypeIsValid.offset == 0x268
    assert KUSER_SHARED_DATA.NativeProcessorArchitecture.offset == 0x26a
    assert KUSER_SHARED_DATA.NtMajorVersion.offset == 0x26c
    assert KUSER_SHARED_DATA.NtMinorVersion.offset == 0x270
    assert KUSER_SHARED_DATA.ProcessorFeatures.offset == 0x274
    assert KUSER_SHARED_DATA.Reserved1.offset == 0x2b4
    assert KUSER_SHARED_DATA.Reserved3.offset == 0x2b8
    assert KUSER_SHARED_DATA.TimeSlip.offset == 0x2bc
    assert KUSER_SHARED_DATA.AlternativeArchitecture.offset == 0x2c0
    assert KUSER_SHARED_DATA.SystemExpirationDate.offset == 0x2c8
    assert KUSER_SHARED_DATA.SuiteMask.offset == 0x2d0
    assert KUSER_SHARED_DATA.KdDebuggerEnabled.offset == 0x2d4
    assert KUSER_SHARED_DATA.MitigationPolicies.offset == 0x2d5
    assert KUSER_SHARED_DATA.CyclesPerYield.offset == 0x2d6
    assert KUSER_SHARED_DATA.ActiveConsoleId.offset == 0x2d8
    assert KUSER_SHARED_DATA.DismountCount.offset == 0x2dc
    assert KUSER_SHARED_DATA.ComPlusPackage.offset == 0x2e0
    assert KUSER_SHARED_DATA.LastSystemRITEventTickCount.offset == 0x2e4
    assert KUSER_SHARED_DATA.NumberOfPhysicalPages.offset == 0x2e8
    assert KUSER_SHARED_DATA.SafeBootMode.offset == 0x2ec
    assert KUSER_SHARED_DATA.VirtualizationFlags.offset == 0x2ed
    assert KUSER_SHARED_DATA.Reserved12.offset == 0x2ee
    assert KUSER_SHARED_DATA.SharedDataFlags.offset == 0x2f0
    assert KUSER_SHARED_DATA.TestRetInstruction.offset == 0x2f8
    assert KUSER_SHARED_DATA.QpcFrequency.offset == 0x300
    assert KUSER_SHARED_DATA.SystemCall.offset == 0x308
    assert KUSER_SHARED_DATA.Reserved2.offset == 0x30c
    assert KUSER_SHARED_DATA.SystemCallPad.offset == 0x310
    assert KUSER_SHARED_DATA.TickCountQuad.offset == 0x320
    assert KUSER_SHARED_DATA.Cookie.offset == 0x330
    assert KUSER_SHARED_DATA.ConsoleSessionForegroundProcessId.offset == 0x338
    assert KUSER_SHARED_DATA.TimeUpdateLock.offset == 0x340
    assert KUSER_SHARED_DATA.BaselineSystemTimeQpc.offset == 0x348
    assert KUSER_SHARED_DATA.BaselineInterruptTimeQpc.offset == 0x350
    assert KUSER_SHARED_DATA.QpcSystemTimeIncrement.offset == 0x358
    assert KUSER_SHARED_DATA.QpcInterruptTimeIncrement.offset == 0x360
    assert KUSER_SHARED_DATA.QpcSystemTimeIncrementShift.offset == 0x368
    assert KUSER_SHARED_DATA.QpcInterruptTimeIncrementShift.offset == 0x369
    assert KUSER_SHARED_DATA.UnparkedProcessorCount.offset == 0x36a
    assert KUSER_SHARED_DATA.EnclaveFeatureMask.offset == 0x36c
    assert KUSER_SHARED_DATA.TelemetryCoverageRound.offset == 0x37c
    assert KUSER_SHARED_DATA.UserModeGlobalLogger.offset == 0x380
    assert KUSER_SHARED_DATA.ImageFileExecutionOptions.offset == 0x3a0
    assert KUSER_SHARED_DATA.LangGenerationCount.offset == 0x3a4
    assert KUSER_SHARED_DATA.Reserved4.offset == 0x3a8
    assert KUSER_SHARED_DATA.InterruptTimeBias.offset == 0x3b0
    assert KUSER_SHARED_DATA.QpcBias.offset == 0x3b8
    assert KUSER_SHARED_DATA.ActiveProcessorCount.offset == 0x3c0
    assert KUSER_SHARED_DATA.ActiveGroupCount.offset == 0x3c4
    assert KUSER_SHARED_DATA.Reserved9.offset == 0x3c5
    assert KUSER_SHARED_DATA.QpcData.offset == 0x3c6
    assert KUSER_SHARED_DATA.TimeZoneBiasEffectiveStart.offset == 0x3c8
    assert KUSER_SHARED_DATA.TimeZoneBiasEffectiveEnd.offset == 0x3d0
    assert KUSER_SHARED_DATA.XState.offset == 0x3d8
    assert KUSER_SHARED_DATA.FeatureConfigurationChangeStamp.offset == 0x720
    assert KUSER_SHARED_DATA.UserPointerAuthMask.offset == 0x730
    assert KUSER_SHARED_DATA._size_ == 0x738

################################################################################

def _demo():
    _validate()
    from pprint import pprint # noqa: PLC0415
    from ctwin32 import ns_from_struct # noqa: PLC0415

    pprint(ns_from_struct(get_ref()))

################################################################################
