; Installer hooks — stop the agent before replacing it.
;
; Tauri's installer knows to close the *panel* before overwriting it, because that is the app it
; built. It has no idea `win-agent.exe` exists: it is shipped as a bundled resource, it is started
; by a logon task, and it is therefore running on exactly the machines you most want to update.
; Windows will not replace a running binary, so the install fails on "cannot modify win-agent.exe" —
; and running as administrator does not help, because it is a file lock rather than a permission.
;
; Killing it here is safe: the agent holds no state that is not already on disk, a viewer simply
; sees the link drop, and the next logon (or the share tab) starts it again.

!macro NSIS_HOOK_PREINSTALL
  DetailPrint "Stopping the hublot agent so it can be replaced..."
  ; /T as well: anything it spawned would hold the same lock.
  nsExec::Exec 'taskkill /F /T /IM win-agent.exe'
  Pop $0
  ; Ignore the result. "not found" is the normal case on a first install and is not a failure.
  Sleep 500
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Stopping the hublot agent..."
  nsExec::Exec 'taskkill /F /T /IM win-agent.exe'
  Pop $0
  Sleep 300
!macroend
