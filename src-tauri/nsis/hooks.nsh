!macro NSIS_HOOK_POSTUNINSTALL
  ${If} $UpdateMode <> 1
    SetShellVarContext current
    ${If} ${FileExists} "$LOCALAPPDATA\SynapseMind\*.*"
      StrCpy $R9 "Verilerimi de sil (%LOCALAPPDATA%\SynapseMind) — Also delete my data?$\r$\n$\r$\nFolder: $LOCALAPPDATA\SynapseMind$\r$\nYour encrypted memory database (memory.db) and DPAPI key (key.bin) will be permanently deleted."
      ${If} $LANGUAGE == ${LANG_TURKISH}
        StrCpy $R9 "Verilerimi de sil (%LOCALAPPDATA%\SynapseMind)?$\r$\n$\r$\nKonum: $LOCALAPPDATA\SynapseMind$\r$\nŞifreli hafıza veritabanınız (memory.db) ve DPAPI anahtarınız (key.bin) kalıcı olarak silinecek."
      ${EndIf}
      MessageBox MB_YESNO|MB_ICONQUESTION|MB_DEFBUTTON2 "$R9" /SD IDNO IDNO _synapse_keep_data_postuninst
      RMDir /r "$LOCALAPPDATA\SynapseMind"
      _synapse_keep_data_postuninst:
    ${EndIf}
  ${EndIf}
!macroend