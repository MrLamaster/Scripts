<#
.SYNOPSIS
Скрипт для автоматической блокировки IP после нескольких неудачных попыток входа
.DESCRIPTION
Мониторит события безопасности (ID 4625) за последние 5 часов, блокирует IP в брандмауэре
и ведет подробное логгирование в файлы.
#>

# Конфигурация
$FailedAttemptsThreshold = 3       # После скольки неудачных попыток блокировать
$HoursToCheck = 5                 # За сколько часов проверять события (по вашему требованию)
$FirewallRulePrefix = "AUTO_BLOCK_" # Префикс для правил брандмауэра

# Пути к файлам логов (в папке со скриптом)
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogFile = Join-Path $ScriptDir "firewall_blocker.log"
$BlockedIPsFile = Join-Path $ScriptDir "blocked_ips_history.txt"

# Функция для записи в лог
function Write-Log {
    param([string]$Message)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$Timestamp] $Message" | Out-File -FilePath $LogFile -Append -Encoding UTF8
    Write-Host "[$Timestamp] $Message"
}

# Функция для записи заблокированных IP
function Write-BlockedIP {
    param([string]$IP, [string]$Username)
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$Timestamp | $IP | $Username" | Out-File -FilePath $BlockedIPsFile -Append -Encoding UTF8
}

# Создаем файлы логов, если их нет
if (-not (Test-Path $LogFile)) { New-Item -Path $LogFile -ItemType File | Out-Null }
if (-not (Test-Path $BlockedIPsFile)) { New-Item -Path $BlockedIPsFile -ItemType File | Out-Null }

Write-Log "=== Запуск скрипта ==="
Write-Log "Проверяем события за последние $HoursToCheck часов..."
Write-Log "Порог блокировки: $FailedAttemptsThreshold неудачных попыток"

try {
    # Получаем события неудачного входа
    $Events = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        ID = 4625
        StartTime = (Get-Date).AddHours(-$HoursToCheck)
    } -MaxEvents 1000 -ErrorAction Stop

    if (-not $Events) {
        Write-Log "События 4625 не найдены за указанный период."
        exit
    }

    Write-Log "Найдено событий: $($Events.Count)"

    # Анализируем события и группируем IP
    $IPsToBlock = $Events | ForEach-Object {
        try {
            $XML = [xml]$_.ToXml()
            $IP = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "IpAddress" }).'#text'
            $Username = ($XML.Event.EventData.Data | Where-Object { $_.Name -eq "TargetUserName" }).'#text'
            
            if ($IP -and $IP -notin @("127.0.0.1", "::1")) {
                [PSCustomObject]@{
                    IP = $IP
                    Username = $Username
                    Time = $_.TimeCreated
                }
            }
        } catch {
            Write-Log "Ошибка обработки события: $_"
        }
    } | Group-Object IP | Where-Object { $_.Count -ge $FailedAttemptsThreshold } | ForEach-Object {
        [PSCustomObject]@{
            IP = $_.Name
            Count = $_.Count
            Username = ($_.Group | Select-Object -First 1).Username
        }
    }

    if (-not $IPsToBlock) {
        Write-Log "Нет IP с $FailedAttemptsThreshold+ неудачными попытками."
        exit
    }

    # Блокируем IP
    foreach ($Item in $IPsToBlock) {
        $IP = $Item.IP
        $RuleName = "$FirewallRulePrefix$IP"

        if (-not (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue)) {
            try {
                New-NetFirewallRule -DisplayName $RuleName -Direction Inbound -RemoteAddress $IP -Action Block -Protocol Any -ErrorAction Stop
                Write-Log "Заблокирован IP: $IP (попыток: $($Item.Count), пользователь: $($Item.Username))"
                Write-BlockedIP -IP $IP -Username $Item.Username
            } catch {
                Write-Log "Ошибка блокировки IP $IP : $_"
            }
        } else {
            Write-Log "IP $IP уже заблокирован (попыток: $($Item.Count))"
        }
    }

} catch {
    Write-Log "КРИТИЧЕСКАЯ ОШИБКА: $_"
    exit 1
}

Write-Log "=== Завершение работы скрипта ==="