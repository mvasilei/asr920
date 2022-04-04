#! /usr/bin/env python2.7

version = '17.03.03' #Must be exactly as appeared in show ver
rollback_version = 'V169_1A_ES04' #Must be exactly as appeared in show ver
ios_binary = 'asr920igp-universalk9_npe.17.03.03.SPA.bin' #binary file for target ios version
rommon_binary = 'asr920igp-15_6_43r_s_rommon.pkg' #file used to upgrade rommon if not required leave empty string
rollback_binary = 'asr920igp-universalk9.V169_1A_ES04.SPA.bin' #binary file to use in case of rollback
# commands must always terminate with new line
post_upgrade_commands = [
'snmp-server view q iso included\n',
'snmp-server view q ciscoCefMIB excluded\n',
'snmp-server view IVView iso included\n',
'snmp-server view IVView ciscoCefMIB excluded\n',
'snmp-server view IVUserView iso included\n',
'snmp-server view IVUserView ciscoCefMIB excluded\n',
'snmp-server view SMARTSView iso included\n',
'snmp-server view SMARTSView ciscoCefMIB excluded\n',
'snmp-server view ScriptView iso included\n',
'snmp-server view ScriptView ciscoCefMIB excluded\n',
'no logging host 212.137.2.50 discriminator FAN+TEMP\n',
'no logging host 212.137.2.20 discriminator FAN+TEMP\n',
'no logging host 195.27.67.93 discriminator FAN+TEMP\n',
'no logging host 194.221.227.93 discriminator FAN+TEMP\n',
'logging discriminator FAN+TEMP msg-body drops (Speed: [0-6]|Board.Temperature: [1-4]|compliance violation)\n',
'logging host 212.137.2.50 discriminator FAN+TEMP\n',
'logging host 212.137.2.20 discriminator FAN+TEMP\n',
'logging host 195.27.67.93 discriminator FAN+TEMP\n',
'logging host 194.221.227.93 discriminator FAN+TEMP\n',
'end\n',
'copy run start\n\n'
]
