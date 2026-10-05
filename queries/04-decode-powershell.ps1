# Investigation 04: Decode the two matching lab payloads for inspection.
# These literal Base64 strings are copied from the synthetic CSV records.
# FromBase64String returns bytes; Encoding.Unicode interprets them as UTF-16LE.
# GetString returns text, which is displayed in the console.
# Decoder output was verified in Windows PowerShell on 2026-10-05.
# To reproduce, paste the statements into Windows PowerShell.

'WIN11-02\labadmin:'
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEEAcABwAHIAbwB2AGUAZAAgAG0AYQBpAG4AdABlAG4AYQBuAGMAZQAgAGMAaABlAGMAawAnAA=='))

'WIN11-01\alex:'
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAEsAUQBMAC0ATABhAGIALQBEAGUAbQBvACcA'))
