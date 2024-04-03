# x_wireshark
wireshark lua plugins (DoIP, UDS)
- DOIP: ISO 13400-2:2012, DOIP version 2
- UDS : ISO 14229 protocol

## install
- uncheck default [DoIP] and [UDS] protocol, MENU::Analyse->Enabled Protocols...
  - find: [v] DoIP  and uncheck it
  - find: [v] UDS  and uncheck it
  
- copy synio_doip.lua and synio_uds.lua to the wireshark's [personal plugins directory](https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm.html)
  - find with MENU::Help->About Wireshark->Folders->Peronal Lua Plugins
    - windows: %USERPROFILE%\AppData\Roaming\Wireshark\plugins
    - linux: ~/.local/lib/wireshark/
- restart wireshark
