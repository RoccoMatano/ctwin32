################################################################################
#
# Copyright 2021-2026 Rocco Matano
# SPDX-License-Identifier: MIT
#
################################################################################
#
# This example achieves the same result as 'lsc.py' (i.e., running cmd.exe
# under the system account). It does so in a more direct and simpler way.
# However, it uses implementation details that are not contractually confirmed
# (the 'winlogon.exe' process runs under the system account in the same
# session as the interactively logged-in user).
#
################################################################################

from ctwin32 import advapi, kernel
from ctwin32 import (
    CREATE_NEW_CONSOLE,
    MAXIMUM_ALLOWED,
    SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
    SE_IMPERSONATE_PRIVILEGE,
    SE_TCB_PRIVILEGE,
    SecurityImpersonation,
    TOKEN_DUPLICATE,
    TokenImpersonation,
    )

################################################################################

if __name__ == "__main__":
    required = [SE_TCB_PRIVILEGE, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE]
    advapi.enable_privileges([SE_IMPERSONATE_PRIVILEGE])
    session = kernel.ProcessIdToSessionId(kernel.GetCurrentProcessId())
    with advapi.open_system_token_for_session(TOKEN_DUPLICATE, session) as tok:
        dup_tok_args = (
            tok,
            MAXIMUM_ALLOWED,
            kernel.SECURITY_ATTRIBUTES(),
            SecurityImpersonation,
            TokenImpersonation,
            )
        with advapi.DuplicateTokenEx(*dup_tok_args) as dup:
            advapi.enable_token_privileges(dup, required)
            advapi.SetThreadToken(dup)
            advapi.create_process_as_user(
                dup,
                ["cmd.exe", "/K", "whoami /user"],
                CREATE_NEW_CONSOLE
                )

################################################################################

