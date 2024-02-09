# Necessary when self-elevated to restore working directory so index.html is found
$RootPath = $PSScriptRoot
$loaddata = @{
    root = $RootPath
}
Set-Location $RootPath

# # Self-elevate the script if required
if (-Not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

if ( (Get-Module | Where-Object Name -eq 'ThreadJob').Count -lt 1 ) {
    Write-Host "ThreadJob module is required. Adding module..."
    Install-Module ThreadJob -Repository PSGallery | Out-Null
    Import-Module ThreadJob | Out-Null
    Write-Output ""
}

[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices") | Out-Null
[System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.ActiveDirectory") | Out-Null


# Define the base URL and port
$baseURL = "http://localhost"
$port = 9298
$listener = New-Object System.Net.HttpListener
$timemanager = $listener.TimeoutManager;
$timemanager.IdleConnection = '00:10:30';
$timemanager.HeaderWait = '00:10:30';
$url = "$baseURL`:$port/"
$listener.Prefixes.Add($url)

# Start the listener
$listener.Start()

Start-Process "$baseURL`:$port/" # Should open the webpage in your default browser

Write-Host "Listening for incoming connections on $baseURL`:$port/"
Write-Host ""
Write-Host "To exit the server, use the Exit button on the webpage, or execute the following command:"
Write-Host ""
Write-Host 'curl -v -H "Content-Type: application/json" http://localhost:9298/api -d "{\"command\": \"exit\"}"'

$query = @{
    value    = "";
    listener = $listener;
}

$threaddata = @{
    allstatus = [System.Collections.ArrayList]::new();
    isRunning = $False;
}

do {
    # Wait for a request and get the context
    $context = $null;
    try {
        [System.Net.HttpListenerContext]$context = $listener.GetContext()
    }
    catch {}

    # Create a new thread to handle the request
    Start-ThreadJob -ScriptBlock {
        param($context)

        # We have to define the functions/etc inside
        # the scriptblock to be available!!

        $threaddata = $using:threaddata;
        $loaddata = $using:loaddata;
        $RootPath = $loaddata.root;

        class LockState {
            [string]${DC Name};
            [string]$Site;
            [string]${User State};
            [string]${Bad Pwd Count};
            [string]${Last Bad Pwd};
            [string]${Pwd Last Set};
            [string]${Lockout Time};
            [string]${Orig Lock};
        }

        function RunLookup {
            param([string]$user)
            $DCs = [System.DirectoryServices.ActiveDirectory.DomainController]::FindAll([System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Domain)

            $threaddata = $using:threaddata;
            $threaddata.allstatus = [System.Collections.ArrayList]::new();
            $threaddata.isRunning = $True;
            $username = $user;

            # Use this when using SDAD (System.DirectoryServices.ActiveDirectory.DomainController)
            $srvCount = $DCs.Count

            # Use this when using cmdlets
            #$srvCount = (Get-ADDomainController -filter *).Count;

            # Counter so we know when last thread finishes
            $currentCount = 0;

            # Get-ADDomainController -filter * | Select-Object * | ForEach-Object { # cmdlet version
            $DCs | Sort-Object -Property Name | ForEach-Object { # SDAD version
                $currentCount++;
                $dc = @{
                    servername = $_.Name;
                    # site = $_.Site;
                    site       = $_.SiteName;
                    # serverfqdn = $_.HostName;
                    serverfqdn = $_.Name;
                    lockstatus = [LockState]::new();
                    username   = $username;
                    currentDC  = $_;
                }

                Start-ThreadJob -ScriptBlock {
                    param($currentCount, $srvCount)

                    # I don't think this is necessary but I'm doing it anyways
                    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")
                    [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.ActiveDirectory")

                    $dc = $using:dc;
        
                    $serverfqdn = $dc.serverfqdn;
                    $username = $dc.username;
                    $servername = $dc.servername;
        
                    # Write-Host $dc.username;

                    $passwordStatus = get-aduser -identity $username -server $serverfqdn `
                        -properties * | `
                        Select-Object accountexpirationdate, accountexpires, accountlockouttime, `
                        badlogoncount, padpwdcount, lastbadpasswordattempt, lastlogondate, `
                        lockedout, passwordexpired, passwordlastset, pwdlastset, DistinguishedName;

                    
                    $dc.lockstatus.{Orig Lock} = "N/A"; #default value
                    if ($True -eq $passwordStatus.lockedout) {
                        $metadata = $dc.currentDC.GetReplicationMetadata($passwordStatus.DistinguishedName)
                        $dc.lockstatus.{Orig Lock} = $metadata.lockouttime.OriginatingServer.ToUpper().split('.')[0]
                    
                        # This seems alot slower
                        # $LockedObjectPath=$passwordStatus.DistinguishedName; #-Filter 'AttributeName -eq "lockoutTime"' #
                        # $LockoutReplicationRecord=Get-ADReplicationAttributeMetadata -object "$LockedObjectPath" -server $servername -Filter 'AttributeName -eq "lockoutTime"' | Where-Object { $_.AttributeName -eq "lockoutTime" }
                        # $LockoutServer = (((($LockoutReplicationRecord.LastOriginatingChangeDirectoryServerIdentity).split(","))[1]).split("="))[1]
                        # $dc.lockstatus.{Orig Lock} = $LockoutServer;
                    }

                    $dc.lockstatus.{DC Name} = $dc.servername.ToUpper().split('.')[0];
                    $dc.lockstatus.Site = $dc.site;
                    $dc.lockstatus.{Lockout Time} = $passwordStatus.accountlockouttime;
                    $dc.lockstatus.{Bad Pwd Count} = $passwordStatus.badlogoncount;
                    $dc.lockstatus.{Last Bad Pwd} = $passwordStatus.lastbadpasswordattempt;
                    $dc.lockstatus.{User State} = If ($passwordStatus.lockedout) { "Locked" } Else { "Not Locked" };
                    $dc.lockstatus.{Pwd Last Set} = $passwordStatus.passwordlastset;

                    # ConvertTo-Json $dc | Add-Content -Path ".\log1.txt" 
                    # ConvertTo-Json $passwordStatus | Add-Content -Path ".\log2.txt" 
        
                    $threaddata = $using:threaddata;
                    $threaddata.allstatus.Add($dc.lockstatus) | Out-Null;

                    if ($currentCount -eq $srvCount) {
                        $threaddata.isRunning = $False;
                        # Get-Job | Remove-Job -Force
                    }

                } -ArgumentList $currentCount, $srvCount | Out-Null
        
                # Get-Job | Wait-Job | Out-Null; # this will cause premature return
                # Write-Host "Done getting";
            };
        
            # We need to wait for all jobs to finish now
            Get-Job | Wait-Job | Out-Null;
        
        }
        
        $request = $context.Request
        $response = $context.Response

        # Process the request
        $query = $using:query;
        
        $query.value = $($request.Url.PathAndQuery)

        if ($query.value -eq "/") {
            $content = Get-Content  -Path ".\index.html" -Encoding UTF8 -Raw
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)

            # Send the response
            $response.StatusCode = 200;
            $response.ContentType = "text/html";
            $response.ContentLength64 = $buffer.Length
            $output = $response.OutputStream
            $output.Write($buffer, 0, $buffer.Length)
            $output.Close()
        }

        if ($query.value -eq "/api") {
            [System.IO.Stream]$reqstream = $request.InputStream;
            [System.Text.Encoding]$encoding = $request.ContentEncoding;
            [System.IO.StreamReader]$reader = [System.IO.StreamReader]::new($reqstream, $encoding);
            $jsondata = $reader.ReadToEnd();
            $reqdata = ConvertFrom-Json $jsondata;

            $content = @"
"@ # the ending "@ must be first two characters on new line to terminate correctly

            if ($reqdata.command -ne $null) {
                if ($reqdata.command -eq "exit") {
                    $query.value = "/exit"
                    $content = '{"status": "ok"}';
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)

                    # Send the response
                    $response.ContentType = "application/json";
                    $response.ContentLength64 = $buffer.Length
                    $output = $response.OutputStream
                    $output.Write($buffer, 0, $buffer.Length)
                    $output.Close()
                    # $context.Close()
                    $query.listener.Stop();
                }

                if ($reqdata.command -eq "run") {

                    $user = $reqdata.user;
                    RunLookup -user $user
                    # $json = ConvertTo-Json $threaddata.allstatus;
                    $content = '{"status": "ok"}';
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)

                    # Send the response
                    $response.ContentType = "application/json";
                    $response.ContentLength64 = $buffer.Length
                    $output = $response.OutputStream
                    $output.Write($buffer, 0, $buffer.Length)
                    $output.Close()

                }

                if ($reqdata.command -eq "getdata") {

                    $json = ConvertTo-Json $threaddata.allstatus;
                    $content = $json;
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)

                    # Send the response
                    $response.ContentType = "application/json";
                    $response.ContentLength64 = $buffer.Length
                    $output = $response.OutputStream
                    $output.Write($buffer, 0, $buffer.Length)
                    $output.Close()
                }

                if ($reqdata.command -eq "getstate") {
                    $json = '{"status": "ok", "isRunning": false}';

                    if ($threaddata.isRunning) {
                        $json = '{"status": "ok", "isRunning": true}';
                    }
                    
                    $content = $json;
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)

                    # Send the response
                    $response.ContentType = "application/json";
                    $response.ContentLength64 = $buffer.Length
                    $output = $response.OutputStream
                    $output.Write($buffer, 0, $buffer.Length)
                    $output.Close()
                }
            }
        }

    } -ArgumentList $context | Out-Null #| Receive-Job -Wait -AutoRemoveJob
}
while ($query.value -ne "/exit")

$listener.Stop()
