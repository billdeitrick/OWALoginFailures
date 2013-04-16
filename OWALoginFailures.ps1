# OWALoginFailures: Simple PowerShell script for auditing login failures from Microsoft Outlook Web Access.
# Copyright (C) 2013  William Deitrick

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# ------ Init Constants ------
$error_codes = @{"0xC0000064" = "user name does not exist"; "0xC000006A" = "user name is correct but the password is wrong"; "0xC0000234" = "user is currently locked out"; "0xC0000072" = "account is currently disabled"; "0xC000006F" = "user tried to logon outside his day of week or time of day restrictions"; "0xC0000070" = "workstation restriction"; "0xC0000193" = "account expiration"; "0xC0000071" = "expired password"; "0xC0000133" = "clocks between DC and other computer too far out of sync"; "0xC0000224" = "user is required to change password at next logon"; "0xC0000225" = "evidently a bug in Windows and not a risk"; "0xc000015b" = "The user has not been granted the requested logon type (aka logon right) at this machine";}
# ------ End Init Constants ------

# ------ Set Preferences ------
$ErrorActionPreference = "Stop" # (makes all errors terminating)
# ------ End Set Preferences ------

# ------ Init Data From User ------
$computername = read-host "Enter CAS hostname (leave blank for localhost)":
$username = read-host "Enter username (leave blank for none):"
$hour_offset = read-host "Enter hour offset (0 for none):"

$ms_offset = 60 * 60 * 1000 * $hour_offset

if ($computername.length -eq 0) {
  $computername = 'localhost'
}
# ------ End Init Data From User ------

# ------ Build Query For Event ------
$query = @"
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
    *[System[(EventID=4625)]]
"@

if ($username.length -ne 0) {
    $query = "$query and *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]]"
}

if ($hour_offset -ne 0) {
    $query = "$query and *[System[TimeCreated[timediff(@SystemTime) &lt;= $ms_offset]]]"
}

$query = "$query</Select></Query></QueryList>"
# ------ End Build Query For Event ------

# ------ Iterate Through and Process Events ------
Try {
	$events = Get-WinEvent -ComputerName $computername -FilterXml $query
}
Catch {
	write-host -fore Red -back Black $_.Exception.Message
	exit
}

write-host "Found " @($events).Count " events:"

ForEach($event In $events) {
	$e_xml = [xml]$event.ToXml()
	
	$e_uname = $e_xml.event.eventdata.data | Where-Object {$_.name -eq 'TargetUserName'} | % {$_.InnerText}
    $e_ip = $e_xml.event.eventdata.data | Where-Object {$_.name -eq 'IpAddress'} | % {$_.InnerText}
    $e_proc = $e_xml.event.eventdata.data | Where-Object {$_.name -eq 'LogonProcessName'} | % {$_.InnerText}
    $e_exe = $e_xml.event.eventdata.data | Where-Object {$_.name -eq 'ProcessName'} | % {$_.InnerText}
    
    $e_substatus = $e_xml.event.eventdata.data | Where-Object {$_.name -eq 'SubStatus'} | % {$_.InnerText}
    
    $e_message = "Unknown Error Code: $e_substatus"
    
    if ($error_codes.ContainsKey($e_substatus)) {
        $e_message = $error_codes.Get_Item($e_substatus)
    }

	write-host $event.id "|" $event.TimeCreated "|" $e_uname "|" $e_ip "|" $e_message "|" $e_proc "|" $e_exe
}
# ------ End Iterate Through and Process Events ------
