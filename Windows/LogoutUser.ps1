

#C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command "&{try{((( quser | Where-Object {$_ -match 'rdpuser1'}) -split ' +')[2])| ForEach-Object {Where-Object {$_ -match 'rdpuser1'} | logoff $_}}catch{throw $_.Exception.Message}}"

#C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NoExit -Command "

#&{
    
        try
    {
        ((( quser | Where-Object {$_ -match 'rdpuser1'}) -split ' +')[2])| ForEach-Object {Where-Object {$_ -match 'rdpuser1'} | logoff $_}
    
    }
    catch
    {throw $_.Exception.Message}
    

#}"