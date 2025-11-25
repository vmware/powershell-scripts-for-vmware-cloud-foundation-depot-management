# Copyright (c) 2025 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
#
# =============================================================================
#
# SOFTWARE LICENSE AGREEMENT
#
#
# Copyright (c) CA, Inc. All rights reserved.
#
#
# You are hereby granted a non-exclusive, worldwide, royalty-free license
# under CA, Inc.'s copyrights to use, copy, modify, and distribute this
# software in source code or binary form for use in connection with CA, Inc.
# products.
#
#
# This copyright notice shall be included in all copies or substantial
# portions of the software.
#
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
# DEALINGS IN THE SOFTWARE.
#
# =============================================================================
#
#
# Intended use:
#
# This script is intended to help users transition to the new VMware by Broadcom depot structures.
#
# Last modified: 2025-11-24
#
# KB: https://knowledge.broadcom.com/external/article/389276
#
Param (
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$check,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$connect,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [ValidateLength(32, 32)] [ValidatePattern('^[a-zA-Z0-9]{32}$')] [String]$downloadToken,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$disconnect,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$dryRun,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$endpoint,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$help,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$jsonInput,
    [Parameter (Mandatory = $false)] [ValidateSet("DEBUG", "INFO", "ADVISORY", "WARNING", "EXCEPTION", "ERROR")] [String]$logLevel = "INFO",
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$silence,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$skipSddcManagerTaskCheck,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$update,
    [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$version
)

# Enable strict mode for better error detection
Set-StrictMode -Version Latest

# Script-level constants and variables
$Script:logLevelHierarchy = @{
    "DEBUG" = 0
    "INFO" = 1
    "ADVISORY" = 2
    "WARNING" = 3
    "EXCEPTION" = 4
    "ERROR" = 5
}

$Script:ExitCodes = @{
    SUCCESS = 0
    GENERAL_ERROR = 1
    PARAMETER_ERROR = 2
    CONNECTION_ERROR = 3
    AUTHENTICATION_ERROR = 4
    RESOURCE_NOT_FOUND = 5
    OPERATION_FAILED = 6
    TASK_FAILED = 7
    CONFIGURATION_ERROR = 8
    PRECONDITION_ERROR = 9
    USER_CANCELLED = 10
}

# Set log level from parameter
$Script:configuredLogLevel = $logLevel

Function Show-PowerCliWebOperationTimeOut {
    [CmdletBinding()]
    [OutputType([Int32])]
    <#
        .SYNOPSIS
        Returns the configured PowerCLI web operation timeout value in seconds.

        .DESCRIPTION
        Retrieves the maximum WebOperationTimeoutSeconds setting from PowerCLI configuration.
        This timeout determines how long PowerCLI cmdlets will wait for web operations
        (API calls) to complete before timing out.

        .EXAMPLE
        Show-PowerCliWebOperationTimeOut
        Returns the timeout value, e.g., 300 (for 5 minutes)

        .EXAMPLE
        $timeout = Show-PowerCliWebOperationTimeOut
        Write-Host "Current timeout: $timeout seconds"

        .OUTPUTS
        System.Int32
        The timeout value in seconds.

        .NOTES
        This is useful for informing users how long to wait for operations.
    #>

    $webRequestTimeOut = (Get-PowerCLIConfiguration).WebOperationTimeoutSeconds | Sort-Object Desc | Select-Object -First 1
    return $webRequestTimeOut

}

Function Get-SddcManagerVersion {
    [CmdletBinding()]
    [OutputType([String])]
    <#
        .SYNOPSIS
        Returns the major and minor version of the connected SDDC Manager.

        .DESCRIPTION
        Extracts and returns the major and minor version (e.g., "5.2", "9.0") from the
        SDDC Manager's full product version string. This is necessary because PowerShell's
        [version] type only supports 16-bit integers, so the full version must be truncated.

        .EXAMPLE
        Get-SddcManagerVersion
        Returns "9.0" if connected to SDDC Manager 9.0.0.0

        .EXAMPLE
        $version = Get-SddcManagerVersion
        if ([version]$version -ge [version]"5.2") {
            Write-Host "Running SDDC Manager 5.2 or later"
        }

        .OUTPUTS
        System.String
        The major.minor version string (e.g., "5.2", "9.0")

        .NOTES
        Requires an active connection to SDDC Manager via Connect-SddcManager.
    #>

    # Powershell [version] is only a 16-bit int, so the SDDC Manager version must truncated.
    $patternVersion = '^(\d+\.\d+)'
    $connection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue
    $sddcManagerVersion = $connection.ProductVersion
    $sanitizedSddcManagerVersion = $sddcManagerVersion -replace "(?<=$patternVersion).*", ''

    return $sanitizedSddcManagerVersion

}
Function Test-LogLevel {
    [CmdletBinding()]
    [OutputType([Boolean])]
    <#
        .SYNOPSIS
        Determines if a message should be displayed based on the configured log level.

        .DESCRIPTION
        Compares the message type against the configured log level threshold to determine
        if the message should be displayed on screen. All messages are always written to
        the log file regardless of level.

        The log level hierarchy from lowest to highest is:
        DEBUG < INFO < ADVISORY < WARNING < EXCEPTION < ERROR

        .PARAMETER messageType
        The type/severity of the log message to check.

        .PARAMETER configuredLevel
        The minimum log level configured for screen output.

        .EXAMPLE
        Test-LogLevel -messageType "DEBUG" -configuredLevel "INFO"
        Returns $false because DEBUG is below INFO threshold.

        .EXAMPLE
        Test-LogLevel -messageType "ERROR" -configuredLevel "INFO"
        Returns $true because ERROR is at or above INFO threshold.

        .OUTPUTS
        Boolean
        Returns $true if the message should be displayed, $false otherwise.

    #>
    Param(
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$configuredLevel,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$messageType
    )

    $messageLevel = $Script:logLevelHierarchy[$messageType]
    $configuredLevelValue = $Script:logLevelHierarchy[$configuredLevel]

    return ($messageLevel -ge $configuredLevelValue)
}
Function Show-AnyKey {
    <#
        .SYNOPSIS
        The function Show-AnyKey requires the user press a key before continuing.

        .DESCRIPTION
        When this script is run in interactive mode (rather than headless), this function is called
        to invite the user to press a key and return to the original function or menu, after
        reading an informational message.

        .EXAMPLE
        Show-AnyKey
    #>
    [CmdletBinding()]
    Param()

    # function Show-AnyKey is not required in headless mode
    if ($Headless -eq "disabled") {
        Write-Host "`nPress any key to continue...`n" -ForegroundColor Yellow;
        $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown') | Out-Null
    }
}
Function Get-VcenterVersion {
    [CmdletBinding()]
    [OutputType([String])]
    <#
        .SYNOPSIS
        The function Get-VcenterVersion returns the version of vCenter.

        .DESCRIPTION
        This function expects a vCenter FQDN and returns its version.

        .EXAMPLE
        Get-VcenterVersion -Vcenter m01-vc01.example.com

        .EXAMPLE
        Get-VcenterVersion -Vcenter m01-vc01.example.com -Silence

        .EXAMPLE
        Get-VcenterVersion -Vcenter m01-vc01.example.com -Silence -FullVersion

        .PARAMETER Vcenter
        Specifies the vCenter FQDN.

        .PARAMETER Silence
        Specifies if the result should only be logged.

        .PARAMETER fullVersion
        Specifies if full version should be pulled.

    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$fullVersion,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$silence,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vcenter
    )

    $vcenterVersionArray = ($Global:DefaultVIServers | Where-Object { $_.name -eq $vcenter }).Version  -split "\."
    $vcenterMajorMinorVersion = "$($vcenterVersionArray[0]).$($vcenterVersionArray[1])"

    if (-not $silence) {
        return $vcenterMajorMinorVersion
    } else {
        # Full Version is only used for troubleshooting, and thus it's a log only feature.
        if ($fullVersion) {

            $systemUpdateApiVersionQuery = Get-CisService -Name 'com.vmware.appliance.system.version' -Server $vcenter -ErrorAction SilentlyContinue
            if (-not $systemUpdateApiVersionQuery) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot retrieve full version of vCenter `"$vcenter` : $($Error[0])"
                return
            }
            $policy = $systemUpdateApiVersionQuery.get()
            $vcenterFullVersion = $policy.version
            Write-LogMessage -Type DEBUG -Message "vCenter `"$vcenter`" full version is `"$vcenterFullVersion`"."
        } else {
            Write-LogMessage -Type DEBUG -Message "vCenter `"$vcenter`" is runs `"$vcenterMajorMinorVersion`"."
        }
    }
}
Function Write-LogMessage {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        Writes a severity-based color-coded message to the console and/or log file.

        .DESCRIPTION
        The Write-LogMessage function provides centralized logging functionality with support for
        different message types (INFO, ERROR, WARNING, EXCEPTION, ADVISORY, DEBUG). Messages are displayed
        on the console with color coding based on severity and written to a log file with timestamps.

        Screen output is filtered based on the configured log level threshold (set via the -logLevel
        script parameter). Only messages at or above the configured level are displayed on screen.
        All messages are always written to the log file regardless of their severity level.

        Log level hierarchy (lowest to highest):
        DEBUG < INFO < ADVISORY < WARNING < EXCEPTION < ERROR

        .PARAMETER appendNewLine
        When specified, adds a blank line after displaying the message on the console.

        .PARAMETER prependNewLine
        When specified, adds a blank line before displaying the message on the console.

        .PARAMETER message
        The message content to be logged and/or displayed. Can be an empty string if needed.

        .PARAMETER suppressOutputToScreen
        When specified, prevents the message from being displayed on the console regardless of log level.

        .PARAMETER suppressOutputToFile
        When specified, prevents the message from being written to the log file.

        .PARAMETER type
        The severity level of the message. Valid values are:
        - DEBUG (Gray): Debug information for troubleshooting
        - INFO (Green): General information messages
        - ADVISORY (Yellow): Advisory information for user guidance
        - WARNING (Yellow): Warning conditions that may need attention
        - EXCEPTION (Cyan): Exception details and stack traces
        - ERROR (Red): Error conditions that require attention
        Default value is "INFO".

        .EXAMPLE
        Write-LogMessage -type INFO -message "Process started successfully"

        .EXAMPLE
        Write-LogMessage -type ERROR -message "Failed to connect" -prependNewLine

        .EXAMPLE
        Write-LogMessage -type DEBUG -message "Variable value: $myVar"

        .EXAMPLE
        Write-LogMessage -type WARNING -message "Configuration not found" -suppressOutputToScreen
    #>

    Param (
        [Parameter (Mandatory = $false)] [Switch]$appendNewLine,
        [Parameter (Mandatory = $true)] [AllowEmptyString()] [String]$message,
        [Parameter (Mandatory = $false)] [Switch]$prependNewLine,
        [Parameter (Mandatory = $false)] [Switch]$suppressOutputToFile,
        [Parameter (Mandatory = $false)] [Switch]$suppressOutputToScreen,
        [Parameter (Mandatory = $false)] [ValidateSet("INFO", "ERROR", "WARNING", "EXCEPTION","ADVISORY","DEBUG")] [String]$type = "INFO"
    )

    # Define color mapping for different message types
    $msgTypeToColor = @{
        "INFO" = "Green"
        "ERROR" = "Red"
        "WARNING" = "Yellow"
        "ADVISORY" = "Yellow"
        "EXCEPTION" = "Cyan"
        "DEBUG" = "Gray"
    }

    # Get the appropriate color for the message type
    $messageColor = $msgTypeToColor.$type

    # Create timestamp for log file entries
    $timeStamp = Get-Date -Format "MM-dd-yyyy_HH:mm:ss"

    # Determine if message should be displayed based on log level threshold
    $shouldDisplay = Test-LogLevel -messageType $type -configuredLevel $Script:configuredLogLevel

    # Add blank line before message if requested and not in log-only mode and meets log level threshold
    if ($prependNewLine -and (-not ($Script:LogOnly -eq "enabled")) -and $shouldDisplay) {
        Write-Output ""
    }

    # Display message to console with color coding (unless suppressed, in log-only mode, or below log level threshold)
    if (-not $suppressOutputToScreen -and $Script:LogOnly -ne "enabled" -and $shouldDisplay) {
        Write-Host -ForegroundColor $messageColor "[$type] $message"
    }

    # Add blank line after message if requested and not in log-only mode and meets log level threshold
    if ($appendNewLine -and (-not ($Script:LogOnly -eq "enabled")) -and $shouldDisplay) {
        Write-Output ""
    }

    # Write message to log file (unless suppressed)
    if (-not $suppressOutputToFile) {
        $logContent = '[' + $timeStamp + '] ' + '(' + $type + ')' + ' ' + $message
        try {
            Add-Content -Path $logFile -Value $logContent -ErrorAction Stop
        }
        catch {
            # Handle log file write failures gracefully
            Write-Host "Failed to add content to log file $logFile." -ForegroundColor Red
            Write-Host $_.Exception.Message
        }
    }
}
Function New-LogFile {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        At script launch, the function New-LogFile creates a log file if not already present.

        .DESCRIPTION
        The function New-LogFile creates a log file in logs sub-directory off of the PSScriptRoot directory
        with a timestamp in the format of Year-Month-Day. Should a logs sub-directory already exist, logs
        for this script may be identified by the prefix "DepotChange-"

        .EXAMPLE
        New-LogFile
    #>

    # create one log file for each day the script is run.
    $fileTimeStamp = Get-Date -Format "MM-dd-yyyy"
    $Script:LogFolder = Join-Path -Path $PSScriptRoot -ChildPath 'logs'
    $Script:LogFile = Join-Path -Path $logFolder -ChildPath "DepotChange-$fileTimeStamp.log"
    $logFolderExists = Test-Path $logFolder

    if (-not $logFolderExists) {
        Write-Host "LogFolder not found, creating $logFolder" -ForegroundColor Yellow;
        New-Item -ItemType Directory -Path $logFolder | Out-Null
        if (-not $?) {
            Write-LogMessage -Type ERROR -Message "Failed to create log directory. Exiting."
            Exit-WithCode -exitCode $Script:ExitCodes.GENERAL_ERROR -message "Failed to create log directory"
        }
    }

    # Create the log file if not already present.
    if (-not (Test-Path $logFile)) {
        New-Item -type File -Path $logFile | Out-Null
        Get-EnvironmentSetup
    }
}
Function Get-EnvironmentSetup {

    <#
        .SYNOPSIS
        The function Get-EnvironmentSetup logs user environment details.

        .DESCRIPTION
        The function facilitates troubleshooting by populating each day's log files with useful runtime details.

        .EXAMPLE
        Get-EnvironmentSetup
    #>

    $powerShellRelease = $($PSVersionTable.PSVersion).ToString()

    $vcfPowerCliModule = Get-Module -ListAvailable -Name VCF.PowerCLI -ErrorAction SilentlyContinue | Sort-Object Revision | Select-Object -First 1
    $vcfPowerCliRelease = if ($vcfPowerCliModule) { $vcfPowerCliModule.Version } else { $null }

    $vmwarePowerCliModule = Get-Module -ListAvailable -Name VMware.PowerCLI -ErrorAction SilentlyContinue | Sort-Object Revision | Select-Object -First 1
    $vmwarePowerCliRelease = if ($vmwarePowerCliModule) { $vmwarePowerCliModule.Version } else { $null }

    $operatingSystem = $($PSVersionTable.OS)

    # Work-around for MacOS which displays Darwin kernel release when from $($PSVersionTable.OS).  However, if this call fails, revert to what we know.
    if ($IsMacOS) {
        try {
            $macOsVersion = (system_profiler SPSoftwareDataType -json | ConvertFrom-Json | ForEach-Object spsoftwaredatatype | Where-Object _name -eq os_overview).os_version
        } catch [Exception] {
        }
    }
    if ($macOsVersion) {
        $operatingSystem = $macOsVersion
    }

    Show-Version -Silence
    Write-LogMessage -Type DEBUG -Message "Client PowerShell Version is $powerShellRelease."
    if ($vcfPowerCliRelease) {
        Write-LogMessage -Type DEBUG -Message "Client VCF.PowerCLI Version is $vcfPowerCliRelease."
    }
    if ($vmwarePowerCliRelease) {
        Write-LogMessage -Type DEBUG -Message "Client VMware.PowerCLI Version is $vmwarePowerCliRelease."
    }
    if (-not $vcfPowerCliRelease -and -not $vmwarePowerCliRelease) {
        Write-LogMessage -Type ERROR -SuppressOutputToScreen -Message "Client PowerCLI Version not installed"
    }

    Write-LogMessage -Type DEBUG -Message "Client Operating System is $operatingSystem."
}
Function Invoke-CheckUrl {

    <#
        .SYNOPSIS
        Performs a client-side HTTP check on a URL to validate reachability and token validity.

        .DESCRIPTION
        The Invoke-CheckUrl function validates that a URL is accessible from the script execution
        system by attempting an HTTP GET request. It supports both authenticated (with credentials)
        and unauthenticated requests. The function logs success or detailed error information
        to assist with troubleshooting connectivity issues, invalid tokens, or expired credentials.

        .PARAMETER credential
        Optional PSCredential object for authenticated URL checks. Used primarily for SDDC Manager
        depot URLs that require basic authentication.

        .PARAMETER message
        Optional descriptive message about the URL being checked, displayed in log output for
        better context (e.g., "VMware Certified Async Drivers for ESXi").

        .PARAMETER url
        The full URL to check for reachability (e.g., "https://dl.broadcom.com/...").

        .PARAMETER urlType
        A descriptive type label for the URL being checked (e.g., "SDDC Manager Depot",
        "ESX Host Depot", "vCenter Appliance Depot"). Used in log messages for clarity.

        .EXAMPLE
        Invoke-CheckUrl -urlType "SDDC Manager Depot" -url "https://example.com/path" -credential $cred

        .EXAMPLE
        Invoke-CheckUrl -urlType "ESX Host Depot" -url "https://example.com/index.xml" -message "Main ESX depot"

        .EXAMPLE
        Invoke-CheckUrl -urlType "vCenter Appliance Depot" -url "https://example.com/manifest.xml"
    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [PSCredential]$credential,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$message,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$url,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$urlType
    )

    if ($message) {
        Write-LogMessage -Type INFO -Message "Checking new `"$urlType`" URL ($message) ..."
    } else {
        Write-LogMessage -Type INFO -Message "Checking new `"$urlType`" URL ..."
    }
    try {
        if ($credential) {
            $statusCode=(Invoke-WebRequest $url -Credential $credential -Timeout 10 -UserAgent "VMwareDepotChange-PowershellScript").StatusCode
        } else {
            $statusCode=(Invoke-WebRequest $url -Timeout 10 -UserAgent "VMwareDepotChange-PowershellScript").StatusCode
        }
    }
    catch [Exception] {
        if ($($Error[0]) -match "invalid|expired|Object Not Found") {
            $errorMessage = $($Error[0])
        } else {
            $errorMessage = "Unknown"
        }
        Write-LogMessage -Type WARNING -AppendNewLine -Message "Received `"$errorMessage`" error accessing `"$url`"."
        Write-LogMessage -Type WARNING -SuppressOutputToScreen -Message "Full error message for URL `"$url`" is $($Error[0])"
    }
    if ($statusCode) {
        Write-LogMessage -Type INFO -AppendNewLine -Message "Successfully accessed `"$url`" (it received a HTTP/$statusCode message)."
    }
}
Function New-ChoiceMenu {

    <#
        .SYNOPSIS
        The function New-ChoiceMenu presents a yes/no decision prompt to the user.

        .DESCRIPTION
        The function takes in two mandatory values, a question (which prefaces the choice) and a
        default in the form of "yes" or "no."  The user's answer (in the form of 0 or 1) is
        returned to the source function and then processed.

        .EXAMPLE
        $Decision = New-ChoiceMenu -Question "Would you like to create $logFolder" -DefaultAnswer yes

        .PARAMETER question
        Specifies what question to answer the end user.

        .PARAMETER defaultAnswer
        Specifies what answer (yes or no) is chosen if a user hits enter rather than entering Y/N.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$defaultAnswer,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$question
    )

    $title = ""  # Empty title for cleaner prompt display
    $choices = New-Object Collections.ObjectModel.Collection[Management.Automation.Host.ChoiceDescription]
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&Yes'))
    $choices.Add((New-Object Management.Automation.Host.ChoiceDescription -ArgumentList '&No'))

    if ($defaultAnswer -eq "Yes") {
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)
    }
    else {
        $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)
    }

    return $decision
}
Function Test-VcenterReachability {

     <#
        .SYNOPSIS
        The function Test-VcenterReachability uses a test cmdlet to validate https connectivity to vCenter.

        .DESCRIPTION
        The function tests if vCenter is reachable by the script execution system.

        .EXAMPLE
        Test-VcenterReachability -Vcenter fo-m01-vc01.example.com

        .PARAMETER Vcenter
        Specifies the vCenter FQDN.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vcenter
    )

    $webRequestTimeOut = Show-PowerCliWebOperationTimeOut
    Write-LogMessage -Type DEBUG -Message "Testing vCenter `"$vcenter`" reachability from script execution system (PowerCLI timeout is configured as $webRequestTimeOut seconds)..."

    try {
        # Attempt a privileged, non-mutating operation to validate admin permissions and reachability
        $Response = Get-VIEvent -MaxSamples 1 -Server $vcenter -ErrorAction SilentlyContinue
    }
    catch [Exception] {
        $errorMessage = $Error[0].Exception.message
        switch -Regex ($errorMessage) {
            "timed out" {
                Write-LogMessage -Type WARNING -AppendNewLine -Message "vCenter `"$vcenter`" is unreachable from this connected to this script execution system."
            }
            "Could not find any of the servers" {
            # This likely occurred because we already disconnected the server.
                Write-LogMessage -Type WARNING -SuppressOutputToScreen -Message "vCenter `"$vcenter`" is not connected to this script execution system.  This is likely ignorable."
            }
            Default {
                Write-LogMessage -Type WARNING -SuppressOutputToScreen -Message "vCenter `"$vcenter`" produced unexpected error, but may not be fatal. $errorMessage"
            }
        }
    }
    if (-not $Response) {
        Write-LogMessage -Type DEBUG -Message "Forcibly disconnecting unavailable vCenter `"$vcenter`"."
        try {
            Disconnect-VIServer -Server $vcenter -Confirm:$false -Force -ErrorAction SilentlyContinue
        } catch [Exception] {
        }

        $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global
        if ($vcenterConnections) {
            foreach ($vcenterFqdn in $($vcenterConnections | Where-Object IsConnected).Name) {
                if ($vcenterFqdn -eq $vcenter) {
                    Write-LogMessage -Type WARNING -AppendNewLine -Message "Failed to disconnect from vCenter `"$vcenter`: $($Error[0].Exception.Message)"
                }
            }
        }
        return "Unavailable"
    } else {
        return "Available"
    }
}
Function Test-EndPointConnections {

    <#
        .SYNOPSIS
        The function Test-EndPointConnections checks if SDDC Manager (optionally) or vCenter(s) are connected.

        .DESCRIPTION
        This function will attempt to reconnect to vCenter if an SDDC Manager connection is present, otherwise
        it prompts the user to re-authenticate.

        .EXAMPLE
        Test-EndPointConnections
    #>

    # Checks if the environment is VCF managed.
    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global

    If ($sddcConnection -and $sddcConnection.IsConnected) {

        # menu-driven workflow
        if ($Headless -eq "disabled") {
            if ($sddcConnection.IsConnected -and (-not (($vcenterConnections | Where-Object IsConnected).Name))) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "Attempting to reconnecting to vCenter(s)..."
                Connect-VcfVcenters
            } elseif (-not $sddcConnection.IsConnected) {
                Select-EndpointType
            }
            return
        } else {
            if ($sddcConnection.IsConnected -and (-not (($vcenterConnections | Where-Object IsConnected).Name))) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "Reconnecting to vCenter(s)..."
                Connect-VcfVcenters
            } elseif (-not $sddcConnection.IsConnected) {
                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Not connected to an SDDC Manager, please reconnect"
            }
        }
    }
    # Non-SDDC Managed controlled environments
    $viServers = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if (-not $viServers -or -not (($viServers | Where-Object IsConnected).Name)) {
        if ($Headless -eq "disabled") {
            Select-EndpointType
            return
        }
        Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Not connected to vCenter(s) and/or SDDC Manager, please reconnect"
    }

    # Look for duplicate VI Server connections under different usernames and exit if found.
    if ($viServers) {
        $vcenterServerNames = @($viServers.Name)
        $vcenterServerConnections = $vcenterServerNames.Count
        $vcenterServerUniqueFqdns = @($vcenterServerNames | Select-Object -Unique).Count

        if ([int]$vcenterServerConnections -ne [int]$vcenterServerUniqueFqdns) {
        Write-Output ""
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Error: Script execution system is connected to at least one vCenter using multiple users.  Only one connection per vCenter is supported."
            $vcenterWithMultiConnections = $($viServers | Group-Object -Property Name | Where-Object Count -gt 1).Name
            foreach ($vcenterWithMultiConnection in $vcenterWithMultiConnections) {
                $connectedUsers = ($viServers | Where-Object { $_.Name -eq $vcenterWithMultiConnection }).User
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Connected to vCenter `"$vcenterWithMultiConnection`" with the following accounts: $connectedUsers"
            }
            Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Script execution system is connected to at least one vCenter using multiple users"
        }
    }
}
Function ConvertFrom-JsonSafely {
    [CmdletBinding()]
    [OutputType([PSCustomObject])]
    <#
        .SYNOPSIS
        Safely loads and validates JSON content from a file with comprehensive error handling.

        .DESCRIPTION
        The ConvertFrom-JsonSafely function provides a robust way to load JSON files with
        built-in validation and error handling. The function reads the file content, removes
        empty lines that could cause JSON parsing issues, and converts the content to a
        PowerShell object. If JSON validation fails, the function logs detailed error
        information including the file path and specific parsing error, then exits the
        script to prevent further execution with invalid data.

        .PARAMETER jsonFilePath
        The full path to the JSON file to load and parse.

        .EXAMPLE
        $config = ConvertFrom-JsonSafely -jsonFilePath "C:\configs\settings.json"

        .NOTES
        This function will terminate script execution (exit) if JSON parsing fails.
    #>

    Param (
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$jsonFilePath
    )

    Write-LogMessage -type DEBUG -message "Loading JSON file: $jsonFilePath"

    if ($Script:LogOnly -eq "disabled") {
        Write-Host ""
    }

    try {
        # Read file content as a single string (Raw parameter) to ensure proper JSON parsing
        Write-LogMessage -type DEBUG -message "Reading file with -Raw parameter to preserve JSON structure"
        $fileContent = Get-Content -Path $jsonFilePath -Raw
        Write-LogMessage -type DEBUG -message "File content length: $($fileContent.Length) characters"
        $credentials = $fileContent | ConvertFrom-Json
        Write-LogMessage -type DEBUG -message "JSON successfully parsed into $($credentials.GetType().FullName)"
        Write-LogMessage -type DEBUG -message "Credentials is Array: $($credentials -is [Array]), Count: $(if ($credentials -is [Array]) { $credentials.Count } else { 'N/A' })"

        # Use comma operator to prevent array unrolling on return
        return ,$credentials
    }
    catch {
        # Handle JSON parsing errors with detailed, user-friendly logging
        $errorMessage = $_.Exception.Message

        Write-LogMessage -type ERROR -message "JSON validation failed for file: $jsonFilePath"
        Write-Host ""

        # Extract the specific JSON error and location
        if ($errorMessage -match "Bad JSON escape sequence: \\([A-Za-z])\..*'([^']+)'.*line (\d+).*position (\d+)") {
            $badChar = $matches[1]
            $jsonPath = $matches[2]
            $lineNum = $matches[3]
            $position = $matches[4]

            Write-LogMessage -type ERROR -message "Invalid escape sequence: '\$badChar' in JSON property '$jsonPath'"
            Write-LogMessage -type ERROR -message "Location: Line $lineNum, Position $position"
            Write-Host ""
            Write-LogMessage -type ERROR -message "Common causes:"
            Write-LogMessage -type ERROR -message "  1. Windows file paths must use forward slashes (/) or escaped backslashes (\\\\)"
            Write-LogMessage -type ERROR -message "     Example: `"C:/Users/Admin/file.yml`" or `"C:\\\\Users\\\\Admin\\\\file.yml`""
            Write-LogMessage -type ERROR -message "  2. Backslash (\) is a special character in JSON and must be escaped"
            Write-Host ""
            Write-LogMessage -type ERROR -message "Please correct the JSON syntax in '$jsonFilePath' at line $lineNum and try again."
        }
        elseif ($errorMessage -match "Conversion from JSON failed with error: (.+?)\. Path '([^']+)'.*line (\d+).*position (\d+)") {
            $jsonError = $matches[1]
            $jsonPath = $matches[2]
            $lineNum = $matches[3]
            $position = $matches[4]

            Write-LogMessage -type ERROR -message "JSON parsing error: $jsonError"
            Write-LogMessage -type ERROR -message "Property: '$jsonPath'"
            Write-LogMessage -type ERROR -message "Location: Line $lineNum, Position $position"
            Write-Host ""
            Write-LogMessage -type ERROR -message "Please correct the JSON syntax in '$jsonFilePath' and try again."
        }
        elseif ($errorMessage -match "Conversion from JSON failed with error") {
            Write-LogMessage -type ERROR -message "JSON parsing error: $errorMessage"
            Write-Host ""
            Write-LogMessage -type ERROR -message "Please check the JSON syntax in '$jsonFilePath' and try again."
        }
        else {
            # Fallback for unexpected error formats
            Write-LogMessage -type ERROR -message "JSON parsing error: $errorMessage"
        }

        # Exit script execution to prevent continuing with invalid data
        Exit-WithCode -exitCode $Script:ExitCodes.CONFIGURATION_ERROR -message "JSON validation failed for file: $jsonFilePath"
    }
}
Function Exit-WithCode {

    <#
        .SYNOPSIS
        Exits the script with a standardized exit code and optional final message.

        .DESCRIPTION
        This function provides a centralized exit point that ensures consistent exit code usage,
        optional cleanup operations, and clear logging before script termination. Using this
        function instead of direct 'exit' calls improves automation integration and debugging.

        Exit Code Categories:
        0  - SUCCESS: Operation completed successfully
        1  - GENERAL_ERROR: Unspecified error
        2  - PARAMETER_ERROR: Invalid parameters or validation failure
        3  - CONNECTION_ERROR: Failed to connect to SDDC Manager or vCenter
        4  - AUTHENTICATION_ERROR: Authentication or credential failure
        5  - RESOURCE_NOT_FOUND: Cluster, host, workload domain, or image not found
        6  - OPERATION_FAILED: Operation (transition, import, compliance) failed
        7  - TASK_FAILED: Background task failed or timed out
        8  - CONFIGURATION_ERROR: JSON or configuration file error
        9  - PRECONDITION_ERROR: Prerequisites not met (modules, versions)
        10 - USER_CANCELLED: User cancelled the operation

        .PARAMETER exitCode
        The exit code to return to the shell. Use values from $Script:ExitCodes hashtable.

        .PARAMETER message
        Optional final message to log before exiting. If exitCode is 0, logs as INFO.
        Otherwise logs as ERROR.

        .PARAMETER noCleanup
        Skip optional cleanup operations before exit.

        .EXAMPLE
        Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Invalid cluster name format"

        .EXAMPLE
        Exit-WithCode -exitCode $Script:ExitCodes.SUCCESS -message "Operation completed successfully"

        .NOTES
        This function should be used for all script exits to ensure predictable exit behavior.
    #>
    Param(
        [Parameter(Mandatory = $true)] [ValidateNotNull()] [Int]$exitCode,
        [Parameter(Mandatory = $false)] [AllowEmptyString()] [String]$message,
        [Parameter(Mandatory = $false)] [Switch]$noCleanup
    )

    Write-LogMessage -type DEBUG -message "Entered Exit-WithCode function..."

    # Log final message if provided
    if ($message) {
        if ($exitCode -eq 0) {
            Write-LogMessage -type INFO -message $message
        } else {
            Write-LogMessage -type ERROR -message $message
        }
    }

    # Optional cleanup logic for error exits
    if (-not $noCleanup -and $exitCode -ne 0) {
        Write-LogMessage -type DEBUG -message "Exit code $exitCode indicates failure."
    }

    # Log the exit code for debugging
    Write-LogMessage -type DEBUG -message "Script exiting with code $exitCode"

    # Exit with the specified code
    exit $exitCode
}

Function Get-CredentialFromJsonOrPrompt {
    <#
        .SYNOPSIS
        Gets a credential value from JSON or prompts the user if not provided.

        .DESCRIPTION
        This helper function implements the common pattern of checking if a value exists in JSON,
        and if not, prompting the user for input. Handles both plain text and secure string inputs.

        .PARAMETER jsonValue
        The value from the JSON object (can be $null).

        .PARAMETER promptMessage
        The message to display when prompting the user.

        .PARAMETER asSecureString
        If specified, prompts for a secure string (password).

        .PARAMETER convertToSecureString
        If specified and jsonValue is provided, converts the plain text JSON value to a SecureString.

        .EXAMPLE
        $username = Get-CredentialFromJsonOrPrompt -JsonValue $Line.Username -PromptMessage "Enter username"

        .EXAMPLE
        $password = Get-CredentialFromJsonOrPrompt -JsonValue $Line.Password -PromptMessage "Enter password" -AsSecureString -ConvertToSecureString
    #>

    Param (
        [Parameter(Mandatory = $false)] [Switch]$asSecureString,
        [Parameter(Mandatory = $false)] [Switch]$convertToSecureString,
        [Parameter(Mandatory = $false)] $jsonValue,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$promptMessage
    )

    if (-not $jsonValue) {
        # Prompt user for value
        do {
            if ($asSecureString) {
                $value = Read-Host $promptMessage -AsSecureString
                $isEmpty = $value.Length -eq 0
            } else {
                $value = Read-Host $promptMessage
                $isEmpty = [string]::IsNullOrWhiteSpace($value)
            }
        } while ($isEmpty)
        return $value
                } else {
        # Use JSON value
        if ($convertToSecureString) {
            return ConvertTo-SecureString -String $jsonValue -AsPlainText -Force
        } else {
            return $jsonValue
        }
    }
}
Function Invoke-ConnectionWithRetry {
    <#
        .SYNOPSIS
        Handles connection failure retry logic with user prompts.

        .DESCRIPTION
        This helper function implements the common pattern of prompting users to retry
        a connection in interactive mode, or exiting in headless mode. It calls back
        to the specified function name if the user chooses to retry.

        .PARAMETER connectionSuccessful
        Boolean indicating if the connection was successful.

        .PARAMETER retryFunctionName
        Name of the function to call recursively if user chooses to retry.

        .PARAMETER retryPromptMessage
        The question to ask the user for retry confirmation.

        .PARAMETER isJsonMode
        If true, indicates JSON/headless mode (no retry, just exit).

        .EXAMPLE
        Invoke-ConnectionWithRetry -ConnectionSuccessful $false -RetryFunctionName "Connect-SddcManager" -RetryPromptMessage "Would you like to re-enter your SDDC Manager credentials?"
    #>

    Param (
        [Parameter(Mandatory = $true)] [bool]$connectionSuccessful,
        [Parameter(Mandatory = $false)] [bool]$isJsonMode = $false,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$retryFunctionName,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$retryPromptMessage
    )

    if (-not $connectionSuccessful) {
        if ($Headless -eq "disabled" -and -not $isJsonMode) {
            $decision = New-ChoiceMenu -Question $retryPromptMessage -DefaultAnswer yes

            if ($decision -eq 0) {
                # Retry - call the function recursively and exit current function context
                    Write-Output ""
                & $retryFunctionName
                # Exit current function to prevent further execution
                return
                } else {
                Write-LogMessage -Type INFO -PrependNewLine -Message "Returning to main menu..."
                return
            }
        } else {
            # Headless or JSON mode - exit with error
            Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Connection failed. Please resolve the issue and try again."
        }
    }
}
Function Connect-SddcManager {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        The function Connect-SddcManager authenticates against a user-defined SDDC Manager.

        .DESCRIPTION
        This function can be called interactively from a menu or headless from a commandline
        utilizing a JSON input file. Includes comprehensive error handling and retry logic.

        .EXAMPLE
        Connect-SddcManager -jsonInputFile SddcManagerCredentials.json

        .PARAMETER jsonInputFile
        Specifies the JSON file containing the SDDC Manager FQDN and credential information.
    #>

    Param (
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$jsonInputFile
    )

    Write-LogMessage -Type DEBUG -Message "Entered Connect-SddcManager"

    # For safety, this script only supports a connection to one SDDC Manager at a time.
    # Check if the PowerCLI module variable exists before using it (required for strict mode)
    $existingConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($existingConnection) {

        # Check if there is a valid refresh token by invoking an arbitrary VCF cmdlet.
        $tokenNotFound = $false
        try {
            $response = Invoke-VcfGetDomains -ErrorAction SilentlyContinue
        } catch {
            $errorMessage = $_.Exception.Message
            switch -Regex ($errorMessage) {
                "TOKEN_NOT_FOUND|JWT signature does not match|Unauthorized" {
                    $tokenNotFound = $true
                }
                "is recognized as a name of a cmdlet" {
                    Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "Could not find PowerCLI cmdlet Invoke-VcfGetDomains. Your PowerCLI installation may be incomplete"
                }
                Default {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Error: $errorMessage"
                }
            }
        }

        if ($response) {
            Write-LogMessage -Type ADVISORY -Message "Already connected to SDDC Manager `"$($existingConnection.Name)`"."
            if ($tokenNotFound) {
                Write-LogMessage -Type ADVISORY -Message "Your SDDC Manager token has expired, please re-connect."
            } else {
                return
            }
        }
    }

    if ($jsonInputFile) {
        Write-LogMessage -Type INFO -Message "Preparing to connect to SDDC Manager using inputs provided by `"$jsonInputFile`"..."

        $sddcManagerCredentials = ConvertFrom-JsonSafely -jsonFilePath $jsonInputFile

        Write-LogMessage -Type DEBUG -Message "Raw credentials type: $($sddcManagerCredentials.GetType().FullName)"
        Write-LogMessage -Type DEBUG -Message "Is Array: $($sddcManagerCredentials -is [Array])"

        # Ensure we have an array even if there's only one object
        if ($sddcManagerCredentials -isnot [Array]) {
            $sddcManagerCredentials = @($sddcManagerCredentials)
        }

        Write-LogMessage -Type DEBUG -Message "After array wrap - Count: $($sddcManagerCredentials.Count), Type: $($sddcManagerCredentials.GetType().FullName)"

        foreach ($line in $sddcManagerCredentials) {
            Write-LogMessage -Type DEBUG -Message "Iterating - Object type: $($line.GetType().FullName)"
            Write-LogMessage -Type DEBUG -Message "Object properties: $(($line | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name) -join ', ')"

            # SDDC Manager FQDN is the only required input from the JSON file
            # Check for property using PSObject properties which works better with strict mode
            if (-not ($line.PSObject.Properties.Name -contains "SddcManagerFqdn")) {
                Exit-WithCode -exitCode $Script:ExitCodes.CONFIGURATION_ERROR -message "Required object 'SddcManagerFqdn' not found in `"$jsonInputFile`""
            }

            $sddcManagerFqdn = $line.SddcManagerFqdn

            $sddcManagerUserName = if ($line.PSObject.Properties.Name -contains "SddcManagerUserName") {
                Get-CredentialFromJsonOrPrompt -jsonValue $line.SddcManagerUserName -promptMessage "Enter SDDC Manager SSO Username"
            } else {
                Get-CredentialFromJsonOrPrompt -jsonValue $null -promptMessage "Enter SDDC Manager SSO Username"
                }

            $sddcManagerPassword = if ($line.PSObject.Properties.Name -contains "SddcManagerPassword") {
                Get-CredentialFromJsonOrPrompt -jsonValue $line.SddcManagerPassword -promptMessage "Enter SDDC Manager SSO Password" -asSecureString -convertToSecureString
                } else {
                Get-CredentialFromJsonOrPrompt -jsonValue $null -promptMessage "Enter SDDC Manager SSO Password" -asSecureString -convertToSecureString
                }

            $Global:SddcManagerRootPassword = if ($line.PSObject.Properties.Name -contains "SddcManagerRootPassword") {
                Get-CredentialFromJsonOrPrompt -jsonValue $line.SddcManagerRootPassword -promptMessage "Enter SDDC Manager Root Password" -asSecureString -convertToSecureString
                } else {
                Get-CredentialFromJsonOrPrompt -jsonValue $null -promptMessage "Enter SDDC Manager Root Password" -asSecureString -convertToSecureString
            }
        }
    }

    # If no JSON file was provided and we're in interactive mode, prompt for credentials
    if (-not $jsonInputFile -and $Script:Headless -eq "disabled") {
            Write-Output ""

        # Prompt for SDDC Manager FQDN with validation loop
        do {
            $sddcManagerFqdn = Read-Host "Enter SDDC Manager FQDN"
            if ([String]::IsNullOrWhiteSpace($sddcManagerFqdn)) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager FQDN cannot be empty."
            }
        } while ([String]::IsNullOrWhiteSpace($sddcManagerFqdn))

        # Prompt for SSO username with validation loop
        do {
            $sddcManagerUserName = Read-Host "Enter SDDC Manager SSO username"
            if ([String]::IsNullOrWhiteSpace($sddcManagerUserName)) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager SSO username cannot be empty."
            }
        } while ([String]::IsNullOrWhiteSpace($sddcManagerUserName))

        # Prompt for SSO password with validation loop
        do {
            $sddcManagerPassword = Read-Host "Enter SDDC Manager SSO password" -AsSecureString
            if ($null -eq $sddcManagerPassword -or $sddcManagerPassword.Length -eq 0) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager SSO password cannot be empty."
            }
        } while ($null -eq $sddcManagerPassword -or $sddcManagerPassword.Length -eq 0)

        # Prompt for Root password with validation loop
            # This value will be used to connect to SDDCm for LCM properties updates and as a breadcrumb
            # for SDDCm managed environments in later functions.
        do {
            $Global:SddcManagerRootPassword = Read-Host "Enter SDDC Manager Root User password" -AsSecureString
            if ($null -eq $Global:SddcManagerRootPassword -or $Global:SddcManagerRootPassword.Length -eq 0) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager Root User password cannot be empty."
            }
        } while ($null -eq $Global:SddcManagerRootPassword -or $Global:SddcManagerRootPassword.Length -eq 0)

            Write-Output ""
        }

    # If we still don't have credentials, we need them
    if (-not $sddcManagerFqdn) {
        Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "SDDC Manager FQDN is required. Please provide JSON input file using -JsonInput parameter or run in interactive mode."
    }

    # Display connection progress message
    Write-Host "`nConnecting to SDDC Manager `"$sddcManagerFqdn`" (please wait)..." -ForegroundColor Yellow

    # Attempt connection
    $connectedToSddcManager = $null
    $errorMessage = $null

    try {
        $connectedToSddcManager = Connect-VcfSddcManagerServer -Server $sddcManagerFqdn -User $sddcManagerUserName -Password $sddcManagerPassword -ErrorAction Stop
    } catch {
        $errorMessage = $_.Exception.Message
    }

    # Comprehensive error handling for various connection failure scenarios
    if ($errorMessage) {
        switch -Regex ($errorMessage) {
            "IDENTITY_UNAUTHORIZED_ENTITY" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Failed to connect to SDDC Manager `"$sddcManagerFqdn`" using username `"$sddcManagerUserName`". Please check your credentials."
            }
            "nodename nor servname provided" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot resolve SDDC Manager `"$sddcManagerFqdn`". If this is a valid SDDC Manager FQDN, please check your DNS settings."
            }
            "Invalid URI: The hostname could not be parsed" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Invalid SDDC Manager FQDN `"$sddcManagerFqdn`". Please ensure the hostname is valid and properly formatted (e.g., sddc-manager.example.com)."
            }
            "The requested URL <code>/v1/tokens</code> was not found on this Server" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$sddcManagerFqdn`" did not return a valid response. Please check that `"$sddcManagerFqdn`" is a valid SDDC Manager FQDN and if its services are healthy."
            }
            "The SSL connection could not be established" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SSL Connection error to SDDC Manager `"$sddcManagerFqdn`". Ensure SDDC Manager certificate is trusted or configure PowerCLI to ignore insecure connections: Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:`$false."
            }
            "Permission not found" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Username `"$sddcManagerUserName`" does not have access to SDDC Manager."
            }
            "A task was canceled" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Could not reach https://$sddcManagerFqdn from this script execution system."
            }
            "The term 'Connect-VcfSddcManagerServer' is not recognized as a name of a cmdlet" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot find the cmdlet Connect-VcfSddcManagerServer. Your PowerCLI installation may be incomplete. Please consider reinstalling PowerCLI."
            }
            "The argument is null or empty" {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "No arguments detected."
            }
            "VMware.Binding.OpenApi.Client.ApiException" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Encountered an API exception when connecting to SDDC Manager `"$sddcManagerFqdn`". Please make sure this endpoint is an SDDC Manager and, if so, its services are healthy."
            }
            "but the module could not be loaded" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "VMware.Sdk.Vcf.SddcManager, the module containing the required Connect-VcfSddcManagerServer PowerCLI cmdlet could not be loaded. Your PowerCLI environment may not be configured correctly. Please investigate before re-running this script."
            }
            "not recognized as a name of a cmdlet" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Could not find PowerCLI cmdlet Connect-VcfSddcManagerServer. Your PowerCLI installation may be incomplete."
            }
            Default {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Error Message: $errorMessage"
            }
        }
    }

    # Handle connection failure - prompt to retry in interactive mode
    if (-not $connectedToSddcManager) {
        $isJsonModeValue = -not [string]::IsNullOrEmpty($jsonInputFile)
        Invoke-ConnectionWithRetry -connectionSuccessful $false -retryFunctionName "Connect-SddcManager" -retryPromptMessage "Would you like to re-enter your SDDC Manager FQDN and user credentials?" -isJsonMode $isJsonModeValue

        # If we reach here in interactive mode, user chose not to retry - return to menu
        return
        } else {
        # Check for a minimum SDDC version before declaring success. In order to check for said version, we must first connect to SDDC manager.
        $sddcManagerVersion = Get-SddcManagerVersion

        if ([version]$sddcManagerVersion -lt [version]$minimumVcfRelease) {
            Disconnect-SddcManager -NoPrompt
            Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "SDDC Manager `"$sddcManagerFqdn`" version $sddcManagerVersion is less than minimum version $minimumVcfRelease"
        } elseif ($sddcManagerVersion[0] -eq $vcf9xRelease) {
            Disconnect-SddcManager -NoPrompt
            Exit-WithCode -exitCode $Script:ExitCodes.SUCCESS -message "SDDC Manager `"$sddcManagerFqdn`" is running VCF 9.x which is already compatible with authenticated depots - script not required"
        } else {
            Write-LogMessage -Type INFO -AppendNewLine -Message "Successfully connected to SDDC Manager `"$sddcManagerFqdn`"."
            Write-LogMessage -Type DEBUG -Message "SDDC Manager `"$sddcManagerFqdn`" version is `"$sddcManagerVersion`"."
            Connect-VcfVcenters
        }
    }

    Write-LogMessage -Type DEBUG -Message "Exiting Connect-SddcManager"
}
Function Invoke-SddcManagerServiceCheck {

    <#
        .SYNOPSIS
        The function Invoke-SddcManagerServiceCheck checks that a SDDC Manager service restarts correctly.

        .DESCRIPTION
        This function is used to ensure that the new applications.property file is read properly by the appropriate service.  If the
        service cannot start up properly, the function returns a failed status so that the calling function can take appropriate
        action.

        .EXAMPLE
        Invoke-SddcManagerServiceCheck -guestUser root -guestVm m01-vc01 -guestPassword System.Security.SecureString -service lcm

        .PARAMETER guestUser
        Specifies the shell user VMware Tools will use to login to the VM.

        .PARAMETER guestPassword
        Specifies the password of the guest user VMware Tools will use to login to the VM.

        .PARAMETER guestVm
        Specifies the VM name, in the vCenter inventory, that VMware Tools wil login to using guestUser/guestPassword credentials.

        .PARAMETER service
        Specifies the service name to restart
    #>

	Param (
        [Parameter (Mandatory = $true)] [SecureString]$guestPassword,
        [Parameter (Mandatory = $true)] [String]$guestUser,
        [Parameter (Mandatory = $true)] [String]$guestVm,
        [Parameter (Mandatory = $true)] [String]$service
	)

    # Verify we're connected to the appropriate endpoints before continuing.
    if (-not $DryRun) {
        # Verify we're connected to the appropriate endpoints before continuing.
        Test-EndPointConnections
    }

    Try {
        # Get the SDDC connection once for strict mode compliance
        $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
        $sddcName = if ($sddcConnection) { $sddcConnection.Name } else { "Unknown" }

        $pollLoopCounter = 0
        Do {
            if ($pollLoopCounter % 10 -eq 0) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "Please wait while the SDDC Manager $Service service on `"$sddcName`" is restarted..."
            }
            $scriptCommand = "curl http://localhost/$service/about"
            $results = Invoke-VMScript -VM $guestVm -ScriptText $scriptCommand -GuestUser $guestUser -GuestPassword $guestPassword -ErrorAction SilentlyContinue
            if ($results.ScriptOutput.Contains("<title>502")) {
                if (($pollLoopCounter % 10 -eq 0) -AND ($pollLoopCounter -gt 9)) {
                    Write-LogMessage -Type ADVISORY -Message "The $Service service on SDDC Manager `"$sddcName`" is still restarting."
                }
                Start-Sleep 20
                $pollLoopCounter ++
            }
        }
        While ($results.ScriptOutput.Contains("502"))
        Write-LogMessage -Type INFO -AppendNewLine -Message "The $Service service on SDDC Manager `"$sddcName`" has been restarted successfully."
        return 0 | Out-Null
    }
    Catch {
        $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
        $sddcName = if ($sddcConnection) { $sddcConnection.Name } else { "Unknown" }
        Write-LogMessage -Type ERROR -AppendNewLine -Message "The $Service service on SDDC Manager `"$sddcName`" failed to restart in a timely manner.  Please contact support."
        return 1 | Out-Null
    }
}
Function Invoke-SddcManagerPropertyFilesConfig {

    <#
        .SYNOPSIS
        The function Invoke-LcmPropertyUpdate updates application-prod.properties on SDDC Manager.

        .DESCRIPTION
        This function utilizes Invoke-VMScript to update the LCM properties file to point to the new
        VMware by Broadcom depot location.

        .EXAMPLE
        Invoke-LcmPropertyUpdate -Action Update -downloadToken ABCEFGHIJKLMNOPQRSTUVWXYZ1234567 -newDepotFqdn dl.broadcom.com -newDepotPath /$downloadToken/PROD2

        .EXAMPLE
        Invoke-LcmPropertyUpdate -Action Check

        .PARAMETER action
        Specifies the action to take against the SDDC Manager configuration: check, update

        .PARAMETER downloadToken
        Specifies the download token (used only in update operations).

        .PARAMETER newDepotFqdn
        Specifies the new depot fully qualified domain name (used only in update operations).

        .PARAMETER newDepotPath
        Specifies the new depot path (used only in update operations).

        .PARAMETER newLcmManifestDirValue
        Specifies the Value for the LCM Manifest Directory.

        .PARAMETER newProductCatalogValue
        Specifies the Value for the LCM Catalog.

        .PARAMETER newProxyHttpStatuses
        Specifies the valid proxy http status codes.

        .PARAMETER newRepoDirValue
        Specifies the new repo directory value.

        .PARAMETER serviceRestartWaitSeconds
        Specifies the number of seconds to wait after restarting SDDC Manager services before checking their status. Default is 30 seconds.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateSet("Check","Update")] [String]$action,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$downloadToken,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newDepotFqdn,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newDepotPath,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newLcmManifestDirValue,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newProductCatalogValue,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newProxyHttpStatuses,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newRepoDirValue,
        [Parameter (Mandatory = $false)] [ValidateRange(1, 300)] [Int]$serviceRestartWaitSeconds = 30
    )

    # Verify we're connected to the appropriate endpoints before continuing.
    Test-EndPointConnections

    # Get the SDDC connection once for strict mode compliance
    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if (-not $sddcConnection) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Not currently connected to an SDDC Manager."
        return
    }

    # The SDDC Manager VM will have originally been deployed in its vCenter as the short version of its FQDN
    try {
        $sddcManagerVmName = $sddcConnection.Name.split('.')[0]
    }
    catch [Exception] {
        if ($($Error[0].Exception.Message) -match "You cannot call a method on a null-valued expression") {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "Not currently connected to an SDDC Manager."
        } else {
            Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message $($Error[0].Exception.Message)
        }
    }
    try {
        $sddcManagerVcenter = ((Invoke-VcfGetDomains).elements | Where-Object Type -eq MANAGEMENT).Vcenters.Fqdn
    } catch [Exception] {
         # We use this verb in user output
         $Action = $Action.ToLower()
        if ($($Error[0].Exception.Message) -match "The request was canceled due to the configured HttpClient.Timeout") {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" is not is not reachable from this script execution system. Skipping $Action action..."
        } elseif ($Error[0] -match "TOKEN_NOT_FOUND") {
            Write-LogMessage -Type ADVISORY -AppendNewLine -Message "Your SDDC Manager token has expired, please re-connect."
        } else {
            Write-LogMessage -Type ERROR -AppendNewLine -Message $($Error[0].Exception.Message)
        }
    }
    if (-not $sddcManagerVcenter) {
        return
    }
    $remoteSddcManagerLcmPropertiesFile="/opt/vmware/vcf/lcm/lcm-app/conf/application-prod.properties"
    $remoteSddcManagerOperationPropertiesFile="/etc/vmware/vcf/operationsmanager/application.properties"
    $localSddcManagerPropertiesFile = Join-Path -Path $logFolder -ChildPath "$sddcManagerVmName-lcm-app-application-prod.properties"
    $localSddcManagerOperationPropertiesFile = Join-Path -Path $logFolder -ChildPath "$sddcManagerVmName-operationsmanager-application.properties"

    $depotLcmManifestDir="lcm.depot.adapter.remote.lcmManifestDir"
    $depotLcmProductVersionCatalogDir="lcm.depot.adapter.remote.lcmProductVersionCatalogDir"
    $depotPathConfig="lcm.depot.adapter.remote.rootDir"
    $depotRepoDir="lcm.depot.adapter.remote.repoDir"

    $defaultDepotPath="/PROD2"
    $defaultLcmManifestDirValue="/evo/vmw/lcm/manifest"
    $defaultRepoDirValue="/evo/vmw"

    $depotFqdnConfig="lcm.depot.adapter.host"
    $defaultDepotFqdn="depot.vmware.com"

    $proxyConfigValidationHttpCodeParameter="proxy.configuration.validation.expected.http.statuses"
    $proxyConfigValidationTestUrlParameter="proxy.configuration.validation.test.url"

    $proxyConfigValidationHttpCodeValue=$newProxyHttpStatuses
    $proxyConfigValidationTestUrlValue="https://$newDepotFqdn"

    $backupSddcManagerLcmPropertiesFile="/tmp/lcm-app.application-prod.properties.backup"
    $backupSddcManagerOperationPropertiesFile="/tmp/operationsmanager.application.properties.backup"

    # SDDC Manager 5.2.0.0 and above require one additional parameter be set.
    $sddcManagerVersion = Get-SddcManagerVersion
    if ([version]$sddcManagerVersion -eq [version]$vcf52Release) {
        $vcf52=$true
    }

    # The "-n" flag in the backup command ensure we only run the backup if the file doesn't exist already.
    # The "-a flag ensures that file permissions and ownership is preserved"
    $lcmPropertiesBackupConfigCommand = "cp -an $remoteSddcManagerLcmPropertiesFile $backupSddcManagerLcmPropertiesFile"

    # Applies only to VCF 5.2.x
    $operationsPropertiesBackupConfigCommand = "cp -an $remoteSddcManagerOperationPropertiesFile $backupSddcManagerOperationPropertiesFile"

    # SDDC Manager functions depend in MGMT vCenter reachability.
    $vcenterReachability = Test-VcenterReachability -Vcenter $sddcManagerVcenter

    if ($vcenterReachability -eq "Unavailable") {
        # We use this verb in user output
        $Action = $Action.ToLower()
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot complete $Action against SDDC Manager `"$($sddcConnection.Name)`" as vCenter `"$sddcManagerVcenter`" is unreachable from this script execution system. Skipping SDDC Manager action $Action."
        return
    }

    # Ensure a backup of application-prod.properties exists on SDDC manager.
    $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $lcmPropertiesBackupConfigCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

    if (-not $results) {
        $errorMessage = $Error[0]
        switch -Regex ($errorMessage) {
            "Value cannot be found for the mandatory parameter VM" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "No SDDC Manager VM named `"$sddcManagerVmName`" found in `"$sddcManagerVcenter`".  Please revert to the run book."
            }
            "Failed to authenticate with the guest operating system using the supplied credentials" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "The root password provided for SDDC Manager `"$sddcManagerVmName`" is not correct.  Please reauthenticate and try again."
            }
            "The guest operations agent could not be contacted" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "VMware Tools is not running on `"$sddcManagerVmName`" Please restart the service.  If the service must remain disabled due to a security policy, please revert to the run book."
            }
            "The SSL connection could not be established, see inner exception" {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Your system does not trust SDDC Manager `"$sddcManagerVmName`"'s certificate.  If this is expected, please run: Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -confirm:`$false"
            }
            Default {
            Write-LogMessage -Type Error -AppendNewLine -Message "Unexpected error backing up configuration on SDDC Manager: $($Error[0].Exception.Message)"
            }
        }
        return
    }

    # Keep the check results clean of all progress output.
    if ($Action -ne $Check) {
        Write-LogMessage -Type INFO -AppendNewLine -Message "Beginning SDDC Manager `"$($sddcConnection.Name)`" depot configuration check..."
    }

    # Copy relevant SDDC manager configuration files to logs directory for easy parsing.
    Copy-VMGuestFile -VM $sddcManagerVmName -Server $sddcManagerVcenter -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -Source $remoteSddcManagerLcmPropertiesFile -Destination $localSddcManagerPropertiesFile -GuestToLocal -ErrorAction SilentlyContinue
    Copy-VMGuestFile -VM $sddcManagerVmName -Server $sddcManagerVcenter -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -Source $remoteSddcManagerOperationPropertiesFile -Destination $localSddcManagerOperationPropertiesFile -GuestToLocal -ErrorAction SilentlyContinue

    # First check if the configuration is default
    $defaultLcmConfigMatch0 = Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotPathConfig`=$defaultDepotPath$"
    $defaultLcmConfigMatch1 = Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotFqdnConfig`=$defaultDepotFqdn$"
    $defaultLcmConfigMatch2 = Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotRepoDir`=$defaultRepoDirValue$"
    $defaultLcmConfigMatch3 = Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotLcmManifestDir`=$defaultLcmManifestDirValue$"

    $proxyConfigMatch0 = Select-String -Path $localSddcManagerOperationPropertiesFile -Pattern "^$proxyConfigValidationHttpCodeParameter"
    $proxyConfigMatch1 = Select-String -Path $localSddcManagerOperationPropertiesFile -Pattern "^$proxyConfigValidationTestUrlParameter"

    if ($defaultLcmConfigMatch0 -and $defaultLcmConfigMatch1) {
        $sddcManagerConfig="$defaultDepotFqdn$defaultDepotPath"
    } else {
        $fullString = (Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotPathConfig").line
        $depotPath = $fullString -replace "^.*=", ""
        $fullString = (Select-String -Path $localSddcManagerPropertiesFile -Pattern "^$depotFqdnConfig").line
        $depotFqdn = $fullString -replace "^.*=", ""
        $sddcManagerConfig = "$depotFqdn$depotPath"
    }

    if ($Action -eq "Check") {
        if ($defaultLcmConfigMatch0 -and $defaultLcmConfigMatch1 -and $defaultLcmConfigMatch2 -and $defaultLcmConfigMatch3) {
            Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has the default depot configuration."
        } else {
            Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has depot configuration: `"$sddcManagerConfig`"."
        }
        if ($vcf52) {
            if ($proxyConfigMatch0 -and $proxyConfigMatch1) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" supports optional proxy configurations in operations manager."
            } else {
                Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has the default operations manager configuration (does not support optional proxy configurations)."
            }
        }

    } elseif ($Action -eq "Update")  {
        # Initialize flags
        $runningTasks = $null
        $skipLcmUpdate = $false

        # determine if an update is required.
        if ( ($depotFqdn -eq $newDepotFqdn) -and ($depotPath -eq $newDepotPath) ) {
            Write-LogMessage -Type WARNING -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has already been updated with depot `"$newDepotFqdn$newDepotPath`". No LCM changes are required."
                # Only VCF 5.2 have a relevant proxy configuration.
                if ($vcf52) {
                    if ($proxyConfigMatch0 -and $proxyConfigMatch1) {
                        Write-LogMessage -Type WARNING -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" supports optional proxy configurations in operations manager. No operations manager changes are required"
                        return
                    } else {
                        Write-LogMessage -Type DEBUG -Message "SDDC Manager `"$($sddcConnection.Name)`" does not support optional proxy configurations, update required."
                        $skipLcmUpdate = $true
                    }
                } else {
                    return
                }
        }

        # Check for running tasks before proceeding.
        try {
            $tasksResult = Invoke-VcfGetTasks
            if ($tasksResult -and $tasksResult.Elements) {
                $inProgressTasks = $tasksResult.Elements | Where-Object {$_.Status -eq "IN_PROGRESS" -or $_.Status -eq "In Progress"}
                if ($inProgressTasks) {
                    $runningTasks = $inProgressTasks.Name
                }
            }
        } catch [Exception] {
            if ($($Error[0].Exception.Message) -match "not currently connected to any servers" ) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Not connected to SDDC Manager, please reconnect."
            } else {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Unexpected error retrieving VCF Tasks: $($Error[0].Exception.Message)"
            }
        }

        if ($runningTasks) {
            if ($skipSddcManagerTaskCheck) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has running tasks.  User has chosen to override safety and proceed. "
            } else {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has the following running tasks: $($runningTasks -join ', '))."
                Write-LogMessage -Type INFO -AppendNewLine "Please wait until these tasks complete and try again."
                return
            }
        }

        if (-not $skipLcmUpdate) {

            Write-LogMessage -Type INFO -AppendNewLine -Message "Beginning SDDC Manager `"$($sddcConnection.Name)`" depot update..."

            # Make the new Depots are regex safe.
            $results = $newDepotPath.Replace("/", "\/")
            $newDepotPath = $results

            $results = $newRepoDirValue.Replace("/", "\/")
            $newRepoDirValue = $results

            $results = $newLcmManifestDirValue.Replace("/", "\/")
            $newLcmManifestDirValue = $results

            $results = $newProductCatalogValue.Replace("/", "\/")
            $newProductCatalogValue = $results

            $scriptCommand = "sed -i -e `"s/^$depotLcmProductVersionCatalogDir=.*/$depotLcmProductVersionCatalogDir=$newProductCatalogValue/`" $remoteSddcManagerLcmPropertiesFile && sed -i -e `"s/^$depotFqdnConfig=.*/$depotFqdnConfig=$newDepotFqdn/`" $remoteSddcManagerLcmPropertiesFile && sed -i -e `"s/^$depotPathConfig=.*/$depotPathConfig=$newDepotPath/`" $remoteSddcManagerLcmPropertiesFile && sed -i -e `"s/^$depotRepoDir=.*/$depotRepoDir=$newRepoDirValue/`" $remoteSddcManagerLcmPropertiesFile && sed -i -e `"s/^$depotLcmManifestDir=.*/$depotLcmManifestDir=$newLcmManifestDirValue/`" $remoteSddcManagerLcmPropertiesFile"

            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

            if ($vcf52) {
                $scriptCommand = "egrep `"^$depotLcmProductVersionCatalogDir=$newProductCatalogValue|^$depotFqdnConfig=$newDepotFqdn|^$depotFqdnConfig=$newDepotFqdn|^$depotRepoDir=$newRepoDirValue|^$depotLcmManifestDir=$newLcmManifestDirValue|^$depotPathConfig=$newDepotPath`" $remoteSddcManagerLcmPropertiesFile | wc -l"
                $expectedResults="5"
            } else {
                $scriptCommand = "egrep `"^$depotFqdnConfig=$newDepotFqdn|^$depotRepoDir=$newRepoDirValue|^$depotLcmManifestDir=$newLcmManifestDirValue|^$depotPathConfig=$newDepotPath`" $remoteSddcManagerLcmPropertiesFile | wc -l"
                $expectedResults="4"
            }

            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
            # Check to see if exactly $expectedResults matches for our precise configuration were found in the new configuration before proceeding.
            if ([int]$results.ScriptOutput -ne [int]$expectedResults) {
                $scriptCommand = "cp -an $backupSddcManagerLcmPropertiesFile $remoteSddcManagerLcmPropertiesFile"
                $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" configuration was not updated.  Automatically reverting to backup.  Please contact support."
                return
            } else {
                # Restart LCM service.
                $scriptCommand = 'systemctl restart lcm'
                $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

                # Wait before checking if the service has restarted correctly.
                Write-LogMessage -Type DEBUG -Message "Waiting $serviceRestartWaitSeconds seconds for LCM service to restart..."
                Start-Sleep $serviceRestartWaitSeconds

                # Verify that the LCM service has restarted properly before continuing.
                Invoke-SddcManagerServiceCheck -GuestVm $sddcManagerVmName -GuestUser root -GuestPassword $sddcManagerRootPassword -Service lcm

                if ($?) {
                    # Revert regex on directory for human readable output
                    $results = $newDepotPath.Replace("\/", "/")
                    $newDepotPath = $results
                    Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has been successfully updated with the new depot location `"$newDepotFqdn$newDepotPath`"."
                }
            }
        }

        # Operations manager Specific Operations (VCF 5.2X required)
        if ($vcf52) {

            # Look to see if the properties have already been updated.
            $scriptCommand = "egrep `"^$proxyConfigValidationHttpCodeParameter|^$proxyConfigValidationTestUrlParameter`" $remoteSddcManagerOperationPropertiesFile | wc -l"
            $expectedResults="2"

            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
                if ([int]$results.ScriptOutput -eq [int]$expectedResults) {
                    Write-LogMessage -Type WARNING -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" does not require an update to the operations manager service."
                } else {
                    Write-LogMessage -Type INFO -AppendNewLine -Message "Beginning SDDC Manager `"$($sddcConnection.Name)`" operations manager update..."

            # Ensure a backup of operations manager property file exists on SDDC manager.
            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $operationsPropertiesBackupConfigCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

            if (-not $results) {
                Write-LogMessage -Type Error -AppendNewLine -Message "Unexpected error backing up configuration on SDDC Manager: $($Error[0].Exception.Message)"
                return
            }

            # Update the operations manager configuration.
            $scriptCommand = "grep -q `"^$proxyConfigValidationHttpCodeParameter`" $remoteSddcManagerOperationPropertiesFile || echo `"$proxyConfigValidationHttpCodeParameter=$proxyConfigValidationHttpCodeValue`" >> $remoteSddcManagerOperationPropertiesFile"
            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

            $scriptCommand = "grep -q `"^$proxyConfigValidationTestUrlParameter`" $remoteSddcManagerOperationPropertiesFile || echo `"$proxyConfigValidationTestUrlParameter=$proxyConfigValidationTestUrlValue`" >> $remoteSddcManagerOperationPropertiesFile"
            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

            # Verify the exact configuration is in place.
            $scriptCommand = "egrep `"^$proxyConfigValidationHttpCodeParameter=$proxyConfigValidationHttpCodeValue|^$proxyConfigValidationTestUrlParameter=$proxyConfigValidationTestUrlValue`" $remoteSddcManagerOperationPropertiesFile | wc -l"
            $expectedResults="2"

            $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
            if ([int]$results.ScriptOutput -eq [int]$expectedResults) {
                # The configuration was successfully applied, we can restart operations manager.
                $scriptCommand = 'systemctl restart operationsmanager'
                $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue

                # Wait before checking if the service has restarted correctly.
                Write-LogMessage -Type DEBUG -Message "Waiting $serviceRestartWaitSeconds seconds for operationsmanager service to restart..."
                Start-Sleep $serviceRestartWaitSeconds

                # Verify that the operationsmanager service has restarted properly before continuing.
                Invoke-SddcManagerServiceCheck -GuestVm $sddcManagerVmName -GuestUser root -GuestPassword $sddcManagerRootPassword -Service operationsmanager

                if ($?) {
                    Write-LogMessage -Type INFO -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" has been successfully updated to support optional proxy configurations."
                }
            } else {
                # Encountering unexpected results should trigger a revert to the backup file.
                $scriptCommand = "cp -an $backupSddcManagerOperationPropertiesFile $remoteSddcManagerOperationPropertiesFile"
                $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
                Write-LogMessage -Type ERROR -AppendNewLine -Message "SDDC Manager `"$($sddcConnection.Name)`" operations manager configuration was not updated successfully. Automatically reverting to backup.  Please contact support."
                return
            }
        }

        # Remove backup file(s).
        if ($vcf52) {
            $scriptCommand = "rm -f $backupSddcManagerLcmPropertiesFile ; rm -f $backupSddcManagerOperationPropertiesFile"
        } else {
            $scriptCommand = "rm -f $backupSddcManagerLcmPropertiesFile"
        }
        $results = Invoke-VMScript -VM $sddcManagerVmName -Server $sddcManagerVcenter -ScriptText $scriptCommand -GuestUser root -GuestPassword $Global:SddcManagerRootPassword -ErrorAction SilentlyContinue
        Write-LogMessage -Type INFO -AppendNewLine -Message "Please wait 5-10 minutes and then you may validate that you can download VCF packages using the new depot."
        return
    }
    }
}
Function Disconnect-Vcenter {

    <#
        .SYNOPSIS
        Safely disconnects from vCenter or ESX host instances with support for individual or bulk disconnection.

        .DESCRIPTION
        The Disconnect-Vcenter function provides a safe and reliable way to disconnect from
        vCenter and/or ESX host instances. It includes comprehensive error handling
        to ensure that disconnection failures are properly logged and handled. The function
        supports both individual server disconnection and bulk disconnection from all active
        connections, making it flexible for various cleanup scenarios.

        The function uses forced disconnection with confirmation suppression to ensure
        reliable cleanup in automated scenarios, making it ideal for script cleanup
        operations and error handling routines. After disconnection, it verifies that
        all connections have been properly terminated by checking $Global:DefaultVIServer.

        Key features:
        - Individual or bulk disconnection management for vCenter and ESX hosts
        - Safe disconnection with comprehensive error handling
        - Post-disconnection verification to ensure clean state
        - Forced disconnection to handle active operations gracefully
        - Confirmation suppression for automated execution
        - Integration with logging infrastructure

        .PARAMETER allServers
        Optional switch parameter that disconnects from all active vCenter and ESX host connections.
        When specified, the function uses wildcard disconnection (Disconnect-VIServer -Server *)
        to terminate all active PowerCLI sessions.

        .PARAMETER serverName
        Optional. The fully qualified domain name (FQDN) or IP address of a specific server to disconnect from.
        This can be either a vCenter or an ESX host.

        .PARAMETER serverType
        Optional. Specifies the type of server being disconnected from. Valid values are "vCenter" or "ESX".
        This parameter is used for logging context.

        .PARAMETER silence
        Optional switch parameter that suppresses console output for disconnection success messages.

        .EXAMPLE
        Disconnect-Vcenter -allServers

        Disconnects from all active vCenter and ESX host connections with verification.

        .EXAMPLE
        Disconnect-Vcenter -allServers -silence

        Quietly disconnects from all active connections with suppressed console output.

        .EXAMPLE
        Disconnect-Vcenter -serverName "vcenter.example.com" -serverType "vCenter"

        Disconnects from a specific vCenter with error handling and logging.

        .NOTES
        - The function uses Force parameter to ensure disconnection even with active operations
        - Post-disconnection verification checks $Global:DefaultVIServer to ensure clean state
        - Proper disconnection prevents resource leaks and ensures clean session management
    #>

    Param (
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$allServers,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$serverName,
        [Parameter(Mandatory = $false)] [ValidateSet("vCenter", "ESX")] [String]$serverType,
        [Parameter(Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$silence
    )

    # Disconnect from vCenter. Stop on error.
    try {
        if ($allServers) {
            Disconnect-VIServer -Server * -Force -Confirm:$false -ErrorAction:Stop | Out-Null
        } else {
            Disconnect-VIServer -Server $serverName -Force -Confirm:$false -ErrorAction:Stop | Out-Null
        }
    } catch {
        # Silently handle disconnection errors
    }

    # Double check that all servers are disconnected.
    if ($null -eq $Global:DefaultVIServer) {
        if ($silence) {
            Write-LogMessage -Type DEBUG -Message "Successfully disconnected from all vCenter and ESX hosts"
                } else {
            Write-LogMessage -Type INFO -Message "Successfully disconnected from all vCenter and ESX hosts"
            }
        } else {
        Write-LogMessage -Type INFO -Message "Failed to disconnect all vCenter and ESX hosts: $Global:DefaultVIServer"
        Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Failed to disconnect from all vCenter and ESX hosts"
    }
}
Function Invoke-VcenterApplianceDepotConfig {

     <#
        .SYNOPSIS
        The function Invoke-VcenterApplianceDepotConfig performs one of three actions against a vCenter.

        .DESCRIPTION
        The function manages the custom depot settings of the vCenter Appliance.

        .EXAMPLE
        Invoke-VcenterApplianceDepotConfig -Action Check -Vcenter m01-vc01.example.com -NewDepotSuffix manifest/file.xml

        .EXAMPLE
        Invoke-VcenterApplianceDepotConfig -Action Rollback -Vcenter m01-vc01.example.com

        .EXAMPLE
        Invoke-VcenterApplianceDepotConfig -Action Update -Vcenter m01-vc01.example.com -NewDepotPrefix https://example.com

        .PARAMETER action
        Specifies the action to perform against the specified vCenter.

        .PARAMETER newDepotPrefix
        Specifies the prefix for the new vCenter Appliance depot.

        .PARAMETER newDepotSuffix
        Specifies the suffix for the new vCenter Appliance suffix.

        .PARAMETER totVcenterVersions
        Specifies an array of Top of Tree (ToT) vCenter releases to use as a static version

        .PARAMETER vcenter
        Specifies the vCenter to perform the specified action against.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateSet("Check","Update")] [String]$action,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newDepotPrefix,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$newDepotSuffix,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Array]$totVcenterVersions,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vcenter
    )

    # Verify token on connected endpoints before continuing.
    Test-EndPointConnections

    # Performing deeper check on vCenter availability
    $vcenterReachability = Test-VcenterReachability -Vcenter $Vcenter

    # Only continue if vCenter is available
    if ($vcenterReachability -eq "Unavailable") {
        # We use this verb in user output
        $Action = $Action.ToLower()
        Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" is not reachable from this script execution system.  Skipping $Action action for `"$Vcenter`" appliance depot..."
        return
    }

    try {
        $systemUpdateApi = Get-CisService -Name 'com.vmware.appliance.update.policy' -Server $Vcenter -ErrorAction Stop
    } catch {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot retrieve com.vmware.appliance.update.policy for vCenter `"$Vcenter`"."
        Write-LogMessage -Type DEBUG -Message "Error details: $($_.Exception.Message)"

        # Check if we have a valid vCenter connection
        $vcenterConnection = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global | Where-Object { $_.Name -eq $Vcenter -and $_.IsConnected }
        if (-not $vcenterConnection) {
            Write-LogMessage -Type ERROR -Message "No active connection to vCenter `"$Vcenter`". Please reconnect."
        } else {
            Write-LogMessage -Type INFO -Message "Connection to vCenter exists. This may be a permissions issue or the vCenter version may not support this API."
            Write-LogMessage -Type INFO -Message "Connected as user: $($vcenterConnection.User)"
        }
        return
    }

    if (-not $systemUpdateApi) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot retrieve com.vmware.appliance.update.policy for vCenter `"$Vcenter`"."
        return
    }

    try {
        $existingVcenterApplianceUpdatePolicy = $systemUpdateApi.get()
    } catch [Exception] {
        if ($($Error[0].Exception.Message) -match "Unable to authorize user") {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "User does not have the necessary permissions `"$Vcenter`" to update the vCenter Appliance depot."
            Write-LogMessage -Type INFO -Message "Please re-run this script with a user with `"com.vmware.appliance.update.policy.get (operator)`""
            Write-LogMessage -Type INFO -AppendNewLine -Message "and `"com.vmware.appliance.update.policy.set (administrator) permissions.`""
        } else {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "Error checking system update policy for vCenter `"$Vcenter`" : $($Error[0].Exception.Message)"
        }
    }
    if (-not $existingVcenterApplianceUpdatePolicy) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "`"$Vcenter`" vCenter Appliance could not be updated."
        return
    }

    if ($Action -eq "Check") {

            if ($null -eq $existingVcenterApplianceUpdatePolicy.custom_url) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "vCenter Appliance `"$Vcenter`" is configured with the default depot."
            } else {
                Write-LogMessage -Type INFO -AppendNewLine -Message "vCenter Appliance `"$Vcenter`" is configured with with custom depot `"$($existingVcenterApplianceUpdatePolicy.custom_url)`"."
            }
        } elseif ($Action -eq "Update") {

            $newVcenterApplianceUpdatePolicy = $systemUpdateApi.help.set.policy.Create()

            if ($Action -eq "Update") {

                # Derive full version to complete URL
                $systemUpdateApiVersionQuery = Get-CisService -Name 'com.vmware.appliance.system.version' -Server $Vcenter -ErrorAction SilentlyContinue

                if (-not $systemUpdateApiVersionQuery) {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Could not retrieve vCenter Appliance management policy for vCenter `"$Vcenter`"."
                    Exit-WithCode -exitCode $Script:ExitCodes.OPERATION_FAILED -message "Could not retrieve vCenter Appliance management policy"
                }

                $policy = $systemUpdateApiVersionQuery.get()
                $vcenterFullVersion = $policy.version

                # Each major version of vCenter will match a ToT version, thus we can just match the first
                # character of each string.
                foreach ($totVcenterVersion in $totVcenterVersions) {
                    if ($totVcenterVersion[0] -match $vcenterFullVersion[0]) {
                        $fullDepotPath = "$newDepotPrefix/$totVcenterVersion"
                        $versionMatch=$true
                    }
                }

                if (-not $versionMatch) {
                    $fullDepotPath = "$newDepotPrefix/$vcenterFullVersion"
                }

                if ($existingVcenterApplianceUpdatePolicy.custom_url -eq $fullDepotPath) {
                    Write-LogMessage -Type WARNING -AppendNewLine -Message "`"$Vcenter`" vCenter Appliance is already configured for `"$fullDepotPath`".  No changes are required."
                    return
                }
                $newVcenterApplianceUpdatePolicy.custom_url = $fullDepotPath
            }

            # All other elements of the existing policy may be carried over.
            $newVcenterApplianceUpdatePolicy.username = $existingVcenterApplianceUpdatePolicy.username
            # Only set password if the property exists in the existing policy
            if (Get-Member -InputObject $existingVcenterApplianceUpdatePolicy -Name "password" -MemberType Properties) {
                if ($null -ne $existingVcenterApplianceUpdatePolicy.password) {
                    $newVcenterApplianceUpdatePolicy.password = $existingVcenterApplianceUpdatePolicy.password
                }
            }
            $newVcenterApplianceUpdatePolicy.check_schedule = $existingVcenterApplianceUpdatePolicy.check_schedule
            $newVcenterApplianceUpdatePolicy.auto_stage = $existingVcenterApplianceUpdatePolicy.auto_stage

            # Publish the new policy.
            try {
                $systemUpdateApi.set($newVcenterApplianceUpdatePolicy)
            } catch [Exception] {
                if ($($Error[0].Exception.Message) -match "Unable to authorize user") {
                    Write-LogMessage -Type ERROR -Message "User does not have the necessary permission on vCenter `"$Vcenter`" to update the vCenter Appliance depot."
                    Write-LogMessage -Type INFO -Message "Please re-run this script with a user with `"com.vmware.appliance.update.policy.get`" and"
                    Write-LogMessage -Type INFO -AppendNewLine -Message "`"com.vmware.appliance.update.policy.set permissions`"."
                } else {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Error checking system update policy for vCenter `"$Vcenter`" : $($Error[0].Exception.Message)"
                }
            }

            $vcenterApplianceUpdatePolicy = $systemUpdateApi.get()

            if ($($vcenterApplianceUpdatePolicy.custom_url)) {
                Write-LogMessage -Type INFO -AppendNewLine -Message "`"$Vcenter`" vCenter Appliance has been configured to use depot `"$($vcenterApplianceUpdatePolicy.custom_url)`"."
                Write-LogMessage -Type INFO -AppendNewLine -Message "Please wait 5-10 minutes and check the vCenter Appliance for new updates."
            }
        }
    }
Function Update-DefaultVcenterSystemDepots {

    <#
        .SYNOPSIS
        The function Update-DefaultVcenterSystemDepots disables vCenter ESX system depots.

        .DESCRIPTION
        This function disables the default system reports which are hard-coded to point at the now-defunct
        hostupdate.vmware.com depots.

        .EXAMPLE
        Update-DefaultVcenterSystemDepots -Vcenter m01-vc01.example.com

        .PARAMETER Vcenter
        Specifies the vCenter FQDN.
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vcenter
    )

    # Verify we're connected to the appropriate endpoints before continuing.
    Test-EndPointConnections

    # Performing deeper check on vCenter availability
    $vcenterReachability = Test-VcenterReachability -vcenter $vcenter
        # Only continue if vCenter is available
        if ($vcenterReachability -eq "Unavailable") {
            # We use this verb in user output
            $Action = $Action.ToLower()
            Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" is not reachable from this script execution system.  Skipping $Action action for `"$Vcenter`" default ESX depots."
            return
    }

    # We use this verb in user output
    $Action = $Action.ToLower()

    # Disable built-in depots.
    $settingsDepotsOnlineUpdateSpec = Initialize-EsxSettingsDepotsOnlineUpdateSpec -Enabled $false
    $depotStatus = $false

    # Get a list of Depot IDs for a given vCenter.
    try {
        $depots = Invoke-ListDepotsOnline -ErrorAction SilentlyContinue -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter} )
    } catch [Exception] {
        Write-LogMessage -Type ERROR -SuppressOutputToScreen -Message "Error invoking Invoke-ListDepotsOnline -Server on vCenter `"$Vcenter`" : $($Error[0])"
    }

    if (-not $depots) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Unable to list ESX depots on vCenter `"$Vcenter`". Error message: $($Error[0].Exception.Message)"
        Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" ESX host depots could not be updated."
        return
    } else {
        # iterate through all repos, looking for system_defined repos and apply settings property (enabled/disable)
        foreach ($depot in $depots.GetEnumerator()) {
            if ($($($depot.Value).SystemDefined)) {
                if ($($($depot.Value).Enabled) -eq ([bool]$depotStatus)) {
                    Write-LogMessage -SuppressOutputToScreen -Type WARNING -Message "The default ESX depot `"$($($depot.Value).Description)`" has already been disabled on vCenter `"$Vcenter`", No changes are required."
                } else {
                    Write-LogMessage -Type INFO -AppendNewLine -Message "Changing default ESX depot `"$($($depot.Value).Description)`" to disabled on vCenter `"$Vcenter`"."
                    Invoke-UpdateDepotOnline -Depot $($depot.Key) -EsxSettingsDepotsOnlineUpdateSpec $settingsDepotsOnlineUpdateSpec -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter } )
                }
            }
        }
    }
}
Function Invoke-VcenterHostDepotConfig {

     <#
        .SYNOPSIS
        The function Invoke-VcenterHostDepotConfig changes the status of the system ESX Depots
        in vCenter for host updates.

        .DESCRIPTION
        If the overall script is called with $Restore, the system depots will be enabled, otherwise
        they will be disabled.

        .EXAMPLE
        Invoke-VcenterHostDepotConfig -Vcenter m01-vc01.example.com -Action Check

        .EXAMPLE
        Invoke-VcenterHostDepotConfig -Vcenter m01-vc01.example.com -Action Update -NewDepots [Array of Depots] -LcmDomains [Array of LCM Domains] -DownloadToken $ABCEFGHIJKLMNOPQRSTUVWXYZ1234567

        .EXAMPLE
        Invoke-VcenterHostDepotConfig -vcenter m01-vc01.example.com -action Restore

        .PARAMETER downloadToken
        Specifies the user's Download Token.

        .PARAMETER vcenter
        Specifies the vCenter FQDN.

        .PARAMETER newDepots
        Specifies the array of new ESX host depots.

        .PARAMETER lcmDomains
        Specifies the allow list of VMware by Broadcom domains.

        .PARAMETER action
        Specifies the action to take: check, update
    #>

    Param (
        [Parameter (Mandatory = $true)] [ValidateSet("Check","Update")] [String]$action,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$downloadToken,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Array]$lcmDomains,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Array]$newDepots,
        [Parameter (Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$vcenter
    )

    # Verify we're connected to the appropriate endpoints before continuing.
    Test-EndPointConnections

    # Performing deeper check on vCenter availability
    $vcenterReachability = Test-VcenterReachability -Vcenter $Vcenter

    # Only continue if vCenter is available
    if ($vcenterReachability -eq "Unavailable") {
         # We use this verb in user output
        $Action = $Action.ToLower()
        Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" is not reachable from this script execution system.  Skipping $Action action for `"$Vcenter`" ESX depots."
        return
    }
    try {
        $allDepots = Invoke-ListDepotsOnline -ErrorAction SilentlyContinue -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter} )
    } catch [Exception] {
        Write-LogMessage -Type DEBUG -Message "Exception in Invoke-ListDepotsOnline: $($_.Exception.Message)"
    }

    if (-not $allDepots) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Unable to list ESX depots on vCenter `"$Vcenter`". Error message: $($Error[0].Exception.Message)"
        Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" ESX host depots could not be updated."
        return
    }

    if ( $Action -eq "Check" ) {
        $depotsEnabled=0

        foreach ($depot in $allDepots.GetEnumerator()) {
            if ($($($depot.Value).SystemDefined)) {
                if ([bool]$(($depot.Value).enabled)) {
                    Write-LogMessage -Type INFO -AppendNewLine -Message "vCenter `"$Vcenter`" host depot on `"$($($depot.Value).Description)`" is configured with the default URL."
                    $depotsEnabled++
                }
            } else {
                Write-LogMessage -Type INFO -AppendNewLine -Message "vCenter `"$Vcenter`" host depot on `"$($($depot.Value).Description)`" and is configured with the custom URL `"$($($depot.Value).Location)`"."
                $depotsEnabled++
            }
        }

        if ([int]$depotsEnabled -eq 0 ) {
            Write-LogMessage -Type WARNING -AppendNewLine -Message "vCenter `"$Vcenter`" has no enabled default or custom VMware depots."
        }
    } elseif ( $Action -eq "Update" ) {
        # Method itself is idempotent, and thus will only try to change host state if
        # not already in desired stated.
        Update-DefaultVcenterSystemDepots -Vcenter $Vcenter

        # Initialize sync flag
        $syncNeeded = $false

        foreach ($newDepot in $newDepots) {
            # Initialize flags for each depot
            $depotActionsComplete = $false

            # To ensure only one custom depot per ESX Depot type exists per vCenter, we need to ensure that changing the download token
            # results in replacing, the custom depot by calling the update, rather than create cmdlet (through a delete/insert operation)

            foreach ($depot in $allDepots.GetEnumerator()) {
                # Only perform check against non-system URLs
                if (-not $($($depot.Value).SystemDefined)) {
                    # Fast-fail if the custom depot has already been configured
                    if ($($($depot.Value).Location) -match $downloadToken) {
                        if ( $($($depot.Value).Location) -eq $($newDepot.Url)) {
                            Write-LogMessage -Type WARNING -AppendNewLine -Message "$($newDepot.Url) has already been added as an ESX Depot to `"$Vcenter`".  No changes are required."
                            $depotActionsComplete = $true
                        }
                    } else {
                        # Check if an existing non-system depot matches the description of the repo we're adding, but with a
                        # different URL, although one within the allow-list of LCM Domains
                        if (($($depot.Value).Description) -eq $($newDepot.Description)) {

                        foreach ($lcmDomain in $lcmDomains) {
                            if ($($depot.Value.Location) -match "^https://$lcmDomain") {
                                Write-LogMessage -Type INFO -AppendNewLine -Message "Older custom depot detected on `"$Vcenter`". Deleting custom repo `"$($depot.Value.Description)`" with URL `"$($depot.Value.Location)`"."
                                Invoke-DeleteDepotOnline  -Confirm:$false -Depot $($depot.Key) -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter} )
                            }
                        }
                    }
                }
            }
        }
        if (-not $depotActionsComplete) {

            # Proceed with create new repo step
            # Create a depot settings spec for create/delete operations.
            $settingsDepotsOnlineCreateSpec = Initialize-EsxSettingsDepotsOnlineCreateSpec -Location $($newDepot.Url) -Description $($newDepot.Description) -ErrorAction SilentlyContinue
            if (-not $settingsDepotsOnlineCreateSpec) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Unable to run create a settings spec for for $($newDepot.Url) on vCenter `"$Vcenter` due to error: due to Error: $($Error[0].Exception.Message)."
                return
            }
            try {
                $response = Invoke-CreateDepotsOnline  -ErrorAction SilentlyContinue -EsxSettingsDepotsOnlineCreateSpec $settingsDepotsOnlineCreateSpec -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter} )
            } catch [Exception] {
                Write-LogMessage -Type DEBUG -Message "Exception in Invoke-CreateDepotsOnline: $($_.Exception.Message)"
            }

            if (-not $response) {
                # vCenter will self-validate not only URL reachability, but the validity of the XML.
                $errorMessage = $Error[0].Exception.Message
                switch -Regex ($errorMessage) {
                    "is not valid or cannot be reached now" {
                        Write-LogMessage -Type ERROR -AppendNewLine -Message "$($newDepot.Url)` is invalid.  Please make sure your token is correct and re-try."
                    }
                    "configured HttpClient.Timeout" {
                        Write-LogMessage -Type ERROR -AppendNewLine -Message "vCenter `"$Vcenter`" timed out when attempting to configure depot `"$($newDepot.Description)`" with URL `"$($newDepot.Url)`".  Please make sure your token is correct and re-try."
                    }
                    Default {
                        Write-LogMessage -Type ERROR -AppendNewLine -Message "Exiting, cannot add $($newDepot.Url) to `"$Vcenter`" due to Error: $errorMessage"
                    }
                }
                return
            } else {
                Write-LogMessage -Type INFO -AppendNewLine -Message "Adding `"$($newDepot.Description)`" to `"$Vcenter`" from `"$($newDepot.Url)`"."
                $syncNeeded = $true
            }
        }
    }
        if ($syncNeeded) {
            $taskId = Invoke-SyncDepotsAsync -Server $($Global:DefaultViServers | Where-Object { $_.Name -eq $Vcenter } )
            Write-LogMessage -Type INFO -AppendNewLine -Message "Beginning sync of new ESX host depots for vCenter `"$Vcenter`" (This will complete in the background)."
            Write-LogMessage -Type DEBUG -Message "If required for debugging, the task ID for vCenter `"$Vcenter`" depot sync is `"$taskId`"."
        }
    }
}
Function Select-DownloadToken {

     <#
        .SYNOPSIS
        The function Select-DownloadToken allows menu-interface users to enter their download token.

        .DESCRIPTION
        The function, after checking if the user hits 'c' to cancel, verifies the function is in the correct form.
        If not, the function repeats.

        .EXAMPLE
        Select-DownloadToken
    #>

    if ($Headless -eq "disabled") {
        Do {
            Test-EndPointConnections
            $Script:DownloadTokenMenuInterface = Read-Host "Enter your Broadcom download token or press 'c' to cancel"
            if ($Script:DownloadTokenMenuInterface -eq "c") {
                Show-AnyKey
                Show-MainMenu
            }
            if ($Script:DownloadTokenMenuInterface.Length -ne $downloadTokenLength) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "DownloadToken $Script:DownloadTokenMenuInterface is an invalid length `($($Script:DownloadTokenMenuInterface.Length)`), it must be $downloadTokenLength characters long.  Please verify it's the correct value and try again."
                $badToken=$true
            } elseif ($Script:DownloadTokenMenuInterface -match '[^a-zA-Z0-9]') {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "DownloadToken $Script:DownloadTokenMenuInterface may only contains characters [A-Z], [a-z], and [0-9], please check your token and try again."
                $badToken=$true
            } else {
                $badToken=$false
            }
        } While ($badToken)
        Write-LogMessage -Type INFO -PrependNewLine -Message "Token format validated for token $Script:DownloadTokenMenuInterface"
    }
}
Function Set-DepotConfiguration {
    [CmdletBinding()]
    <#
        .SYNOPSIS
        The function Set-DepotConfiguration updates vCenter ESX depots, vCenter Appliance depots, and SDDC manager depots if applicable.

        .DESCRIPTION
        This function wraps around mutating functions, with the user input of a Download Token, and fixed parameters
        of the depot transformations (new domains, URL structures, etc.)  It always updates vCenter host depots and vCenter
        appliance, but only update SDDC manager if a user has connected to a VCF managed environment

        .EXAMPLE
        Set-DepotConfiguration -DownloadToken ABCEFGHIJKLMNOPQRSTUVWXYZ1234567
    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$downloadToken,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$dryRun,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$skipSddcManagerTaskCheck
    )

    Write-LogMessage -Type DEBUG -Message "Entered Set-DepotConfiguration"

    # If downloadToken wasn't provided as a parameter, prompt for it
    if (-not $downloadToken) {
        # Only call Select-DownloadToken if we haven't already prompted in the menu
        if (-not $Script:DownloadTokenMenuInterface) {
            Select-DownloadToken
        }
        $downloadToken = $Script:DownloadTokenMenuInterface
    }

    $depotConfig = @{
        # Sddc Manager
        SddcManagerBasePath       = "/$downloadToken/PROD"
        SddcManagerLcmManifestDir = "/COMP/SDDC_MANAGER_VCF/lcm/manifest"
        SddcManagerRepoDir        = "/COMP/SDDC_MANAGER_VCF"
        SddcManagerProductCatalog = "/COMP/SDDC_MANAGER_VCF/lcm/productVersionCatalog"
        SddcManagerProxyStatuses  = "401,403,404"
        # ESX host Depots
        EsxCommonPath             = "PROD/COMP/ESX_HOST"
        EsxIndexFile              = "vmw-depot-index.xml"
        LcmDomains                = @(".*broadcom.com", ".*vmware.com")
        TotVcenterVersions        = @("7.0.3.02200","8.0.3.00400")
        # vCenter Appliance Management
        VcenterApplianceProductId = "8d167796-34d5-4899-be0a-6daade4005a3"
        VcenterApplianceRepoDir   = "PROD/COMP/VCENTER/vmw"
        # Expected Download Token Length
        DownloadTokenLength       = 32
        # Depot fully qualified domain names
        DepotFqdn                 = "dl.broadcom.com"
    }

    # Verify we're connected to the appropriate endpoints before continuing.
    Test-EndPointConnections

    $newVcenterApplianceDepotPrefix = "https://$($depotConfig.DepotFqdn)/$downloadToken/$($depotConfig.VcenterApplianceRepoDir)/$($depotConfig.VcenterApplianceProductId)"

    $hostDepotArray = @(
        [PSCustomObject]@{ Url = "https://$($depotConfig.DepotFqdn)/$downloadToken/$($depotConfig.EsxCommonPath)/addon-main/$($depotConfig.EsxIndexFile)"; Description = "Partner provided Addons for ESXi" }
        [PSCustomObject]@{ Url = "https://$($depotConfig.DepotFqdn)/$downloadToken/$($depotConfig.EsxCommonPath)/main/$($depotConfig.EsxIndexFile)"; Description = "Download vSphere ESXi and ESX patches" }
        [PSCustomObject]@{ Url = "https://$($depotConfig.DepotFqdn)/$downloadToken/$($depotConfig.EsxCommonPath)/iovp-main/$($depotConfig.EsxIndexFile)"; Description = "VMware Certified Async Drivers for ESXi" }
        [PSCustomObject]@{ Url = "https://$($depotConfig.DepotFqdn)/$downloadToken/$($depotConfig.EsxCommonPath)/vmtools-main/$($depotConfig.EsxIndexFile)"; Description = "VMware Async Releases for VM-tools on ESXi" }
    )

    # Basic token validation
    if ($downloadToken.Length -ne $depotConfig.DownloadTokenLength) {
        Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "DownloadToken $downloadToken is an invalid length ($($downloadToken.Length)), it must be $($depotConfig.DownloadTokenLength) characters long"
    }

    if ($downloadToken -match '[^a-zA-Z0-9]') {
        Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "DownloadToken $downloadToken contains invalid characters (only A-Z, a-z, 0-9 allowed)"
    }

    # Perform DryRun check for all updates, but only return from function if DryRun flag is used.

    $scriptExecutionSystem=[System.Net.Dns]::GetHostName()

    Write-LogMessage -Type INFO -Message "Checking new URL reachability and token validity from script execution machine `"$scriptExecutionSystem`"..."
    Write-LogMessage -Type INFO -AppendNewLine -Message "For additional troubleshooting, please visit https://knowledge.broadcom.com/external/article/395322"

    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($sddcConnection -and $sddcConnection.IsConnected) {
        $sddcManagerMockUserName  = (New-Guid).Guid
        $sddcManagerMockPassword  = (New-Guid).Guid
        $secureSddcManagerPassword = ConvertTo-SecureString $sddcManagerMockPassword -AsPlainText -Force
        $sddcManagerMockCredential = New-Object System.Management.Automation.PSCredential($sddcManagerMockUserName, $secureSddcManagerPassword)
        Invoke-CheckUrl -UrlType "SDDC Manager Depot" -Url "https://$($depotConfig.DepotFqdn)$($depotConfig.SddcManagerBasePath)$($depotConfig.SddcManagerRepoDir)/index.v3" -Credential $sddcManagerMockCredential
    }

    foreach ($depot in $hostDepotArray) {
        Invoke-CheckUrl -UrlType "ESX Host Depot" -Url $($depot.Url) -Message $($depot.Description)
    }

    Invoke-CheckUrl -UrlType "vCenter Appliance Depot" -Url "$newVcenterApplianceDepotPrefix/$($($depotConfig.TotVcenterVersions[1]))/manifest/manifest-latest.xml"

    # This completes the non-mutating portion of the function call.
    if ($dryRun) {
        return
    }

    Write-LogMessage -Type INFO -AppendNewLine -Message "Beginning depot update operations..."

    $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($vcenterConnections) {
        foreach ($vcenter in ($vcenterConnections | Where-Object IsConnected)) {
            Invoke-VcenterApplianceDepotConfig -Vcenter $vcenter -Action Update -NewDepotPrefix $newVcenterApplianceDepotPrefix -TotVcenterVersions $($depotConfig.TotVcenterVersions)
            if ($Script:LogOnly -eq "disabled") {
            Write-Output "==========`n"
        }

            Invoke-VcenterHostDepotConfig -Vcenter $vcenter -Action Update -NewDepots $hostDepotArray -LcmDomains $($depotConfig.LcmDomains) -DownloadToken $downloadToken
            if ($Script:LogOnly -eq "disabled") {
            Write-Output "==========`n"
            }
        }
    }

    # Only Update SDDC Manager if connected to SDDC Manager
    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($sddcConnection -and $sddcConnection.IsConnected) {
        $sddcManagerVersion = Get-SddcManagerVersion
        if ([version]$sddcManagerVersion -le [version]$vcf52Release) {
            Invoke-SddcManagerPropertyFilesConfig -Action Update -NewDepotFqdn $($depotConfig.DepotFqdn) -NewDepotPath $($depotConfig.SddcManagerBasePath) -NewRepoDirValue $($depotConfig.SddcManagerRepoDir) -NewLcmManifestDirValue $($depotConfig.SddcManagerLcmManifestDir) -NewProductCatalogValue $($depotConfig.SddcManagerProductCatalog) -DownloadToken $downloadToken -NewProxyHttpStatuses $($depotConfig.SddcManagerProxyStatuses)
            if ($Script:LogOnly -eq "disabled") {
                Write-Output "==========`n"
            }
        } else {
            Write-LogMessage -Type INFO -AppendNewLine -Message "Please use the UI or API on SDDC Manager `"$($sddcConnection.Name)`" to configure its depot to use a download token."
        }
    }

    Write-LogMessage -Type DEBUG -Message "Exiting Set-DepotConfiguration"
}
Function Show-DepotConfiguration {

    <#
        .SYNOPSIS
        The function Show-DepotConfiguration checks the depot configurations of all endpoints.

        .DESCRIPTION
        This function checks to vCenter and the vCenter Appliance endpoint, and optionally SDDC
        manager (if the environment if SDDCm managed). It is a non-mutating function.

        .EXAMPLE
        Show-DepotConfiguration
    #>

    # Verify we're connected to the appropriate endpoints before continuing.
    Test-EndPointConnections

    # This suffix allows for a client-side check of the vCenter Appliance depot.
    $newVcenterApplianceDepotSuffix="/manifest/manifest-latest.xml"

    # Catches the edge case where vC is outside the minimum version and we're disconnected instantly.
    $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($vcenterConnections | Where-Object IsConnected) {
        Write-LogMessage -Type INFO -PrependNewLine -AppendNewLine -Message "Scanning depot configuration state..."
    }

    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($sddcConnection -and $sddcConnection.IsConnected) {
        $sddcManagerVersion = Get-SddcManagerVersion
        if ([version]$sddcManagerVersion -le [version]$vcf52Release) {
            Invoke-SddcManagerPropertyFilesConfig -Action Check
            if ($Script:LogOnly -eq "disabled") {
                Write-Output "==========`n"
            }
        }
    }

    $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    if ($vcenterConnections) {
        foreach ($vcenter in ($vcenterConnections | Where-Object IsConnected)) {

            Invoke-VcenterApplianceDepotConfig -Vcenter $vcenter -Action Check -NewDepotSuffix $newVcenterApplianceDepotSuffix
            if ($Script:LogOnly -eq "disabled") {
            Write-Output "==========`n"
        }
            Invoke-VcenterHostDepotConfig -Vcenter $vcenter -Action Check
            if ($Script:LogOnly -eq "disabled") {
            Write-Output "==========`n"
            }
        }
    }
}
Function Connect-Vcenter {

    <#
        .SYNOPSIS
        Establishes a secure connection to vCenter or ESX host instances with unified connection management.

        .DESCRIPTION
        The Connect-Vcenter function creates a secure connection to either vCenter or ESX host
        using PSCredential objects for authentication. It provides unified connection management for both
        server types with intelligent duplicate connection detection and comprehensive error handling.

        Key features:
        - Unified connection management for both vCenter and ESX hosts
        - Secure credential handling using PSCredential objects
        - Intelligent duplicate connection detection with existing session details
        - Comprehensive error handling and structured logging
        - Connection state validation to prevent duplicate connections

        .PARAMETER serverName
        The fully qualified domain name (FQDN) or IP address of the server to connect to.
        This can be either a vCenter or an ESX host, depending on the serverType parameter.

        .PARAMETER serverCredential
        A PSCredential object containing the username and password for authentication to the target server.
        For vCenter: Supports both local vCenter accounts and SSO domain accounts.
        For ESX: Typically uses root account or other local ESX user accounts.

        .PARAMETER serverType
        Specifies the type of server being connected to. Valid values are "vCenter" or "ESX".
        - "vCenter": Connects to a vCenter instance for centralized management
        - "ESX": Connects directly to an ESX host for host-specific operations

        .PARAMETER noExit
        When specified, prevents the function from calling exit on connection failure.
        Instead, the function returns $false on failure and $true on success.
        This allows calling code to implement custom retry logic or error handling.

        .EXAMPLE
        $credential = Get-Credential -Message "Enter vCenter credentials"
        Connect-Vcenter -serverCredential $credential -serverName "vcenter.example.com" -serverType "vCenter"

        Connects to a vCenter using credentials obtained from Get-Credential cmdlet.

        .EXAMPLE
        $securePassword = Read-Host "Enter ESX password" -asSecureString
        $credential = New-Object System.Management.Automation.PSCredential("root", $securePassword)
        Connect-Vcenter -serverCredential $credential -serverName "esx-host.example.com" -serverType "ESX"

        Connects to an ESX host using a PSCredential object.

        .EXAMPLE
        $connected = Connect-Vcenter -noExit -serverCredential $cred -serverName $esxHost -serverType "ESX"
        if (-not $connected) {
            # Handle connection failure with custom retry logic
        }

        Uses -noExit to implement custom retry logic on connection failure.

        .NOTES
        - By default, connection failures terminate script execution with exit code 1 unless -noExit is specified
        - When -noExit is used, the function returns $true on success and $false on failure
        - Both server types use the same underlying VMware PowerCLI Connect-VIServer cmdlet
    #>

    Param (
        [Parameter(Mandatory = $false)] [Switch]$noExit,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [PSCredential]$serverCredential,
        [Parameter(Mandatory = $true)] [ValidateNotNullOrEmpty()] [String]$serverName,
        [Parameter(Mandatory = $true)] [ValidateSet("vCenter", "ESX")] [String]$serverType
    )

    Write-LogMessage -Type DEBUG -Message "Entered Connect-Vcenter for $serverType '$serverName'"

    # Check if we're already connected to this vCenter to avoid duplicate connections
    $connectedVcenter = $Global:DefaultViServers | Where-Object {$_.name -eq $serverName -and $_.IsConnected}

    if (-not $connectedVcenter) {
        # Attempt to establish a new connection with progress indicator
        try {
            # Show progress while connecting (connection must happen in current runspace to persist global state)
            $progressId = (Get-Random)
            Write-Progress -Id $progressId -Activity "Connecting to $serverType `"$serverName`"" -Status "Please wait..." -PercentComplete -1

            Connect-VIServer -Server $serverName -Credential $serverCredential -ErrorAction Stop | Out-Null

            # Clear the progress bar
            Write-Progress -Id $progressId -Activity "Connecting to $serverType `"$serverName`"" -Completed
            Write-Output ""
        } catch [System.TimeoutException] {
            Write-LogMessage -Type ERROR -Message "Cannot connect to $serverType `"$serverName`" due to network/timeout issues."
            if ($noExit) {
                return $false
            } else {
                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Cannot connect to $serverType `"$serverName`""
            }
        }
        catch {
            # Extract clean error message
            $errorMessage = $_.Exception.Message

            # Provide user-friendly error messages based on error type
            switch -Regex ($errorMessage) {
                "SSL connection could not be established|SSL|certificate" {
                    Write-LogMessage -Type ERROR -Message "SSL connection error to $serverType `"$serverName`". Ensure certificate is trusted or configure PowerCLI to ignore invalid certificates: Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:`$false."
                }
                "incorrect user name or password|authentication|credentials" {
                    Write-LogMessage -Type ERROR -Message "Failed to authenticate to $serverType `"$serverName`" with username `"$($serverCredential.UserName)`". Please check your credentials."
                }
                "nodename nor servname provided" {
                    Write-LogMessage -Type ERROR -Message "Cannot resolve $serverType `"$serverName`". If this is a valid hostname or IP address, please check your DNS settings."
                }
                "The request channel timed out|timed out" {
                    Write-LogMessage -Type ERROR -Message "Connection to $serverType `"$serverName`" timed out. Please verify network connectivity and that the host is reachable."
                }
                Default {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Failed to connect to $serverType `"$serverName`"."
                    Write-LogMessage -Type ERROR -Message "Error details: $errorMessage"
                }
            }

            if ($noExit) {
                return $false
            } else {
                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Cannot connect to $serverType `"$serverName`""
            }
        }

        # Verify the connection was actually established by checking $Global:DefaultVIServers
        $verifyConnection = $Global:DefaultVIServers | Where-Object {$_.Name -eq $serverName -and $_.IsConnected}
        if (-not $verifyConnection) {
            Write-LogMessage -Type ERROR -Message "Connection to $serverType `"$serverName`" appeared successful but server not found in connected servers list."
            if ($noExit) {
                return $false
            } else {
                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Cannot connect to $serverType `"$serverName`""
            }
        }

        # For vCenter connections, also establish CIS server connection for vSphere Automation API access
        if ($serverType -eq "vCenter") {
            try {
                Write-LogMessage -Type DEBUG -Message "Establishing CIS server connection for vCenter `"$serverName`""
                Connect-CisServer -Server $serverName -Credential $serverCredential -ErrorAction Stop | Out-Null
                Write-LogMessage -Type DEBUG -Message "CIS server connection established successfully"
            } catch {
                Write-LogMessage -Type WARNING -Message "Could not establish CIS server connection to `"$serverName`". Some advanced features may not be available."
                Write-LogMessage -Type DEBUG -Message "CIS connection error: $($_.Exception.Message)"
            }
        }

        Write-LogMessage -Type INFO -Message "Successfully connected to $serverType `"$serverName`"."

        if ($noExit) {
            return $true
                        }
                    } else {
        # Connection already exists. Surface the data on what user the connection is using
        $existingUsername = ($Global:DefaultVIServers | Where-Object {$_.Name -eq $serverName }).User
        if ($existingUsername) {
            Write-LogMessage -Type WARNING -Message "Already connected to $serverType `"$serverName`" as `"$existingUsername`"."
                        } else {
            Write-LogMessage -Type WARNING -Message "Already connected to $serverType `"$serverName`"."
        }

        if ($noExit) {
            Write-LogMessage -Type DEBUG -Message "Exiting Connect-Vcenter - Already connected"
            return $true
        }
    }

    Write-LogMessage -Type DEBUG -Message "Exiting Connect-Vcenter - Success"
}
Function Connect-VcfVcenters {

    <#
        .SYNOPSIS
        The function Connect-VcfVcenters establishes a connection to one or more Workload Domain vCenter(s).

        .DESCRIPTION
        This function connects to each vCenter using credentials sourced from SDDC Manager. Different credentials
        are used depending if the Workload Domain vCenter is using isolated or MGMT SSO credentials. These
        credentials are never exposed to the end user.

        .EXAMPLE
        Connect-VcfVcenters
    #>

    # Get SDDC connection for strict mode compliance
    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
    $vcenterConnections = Get-Variable -Name DefaultViServers -ValueOnly -ErrorAction SilentlyContinue -Scope Global

    # List all connected vCenter(s).
    $connectedVcenters = $null
    if ($vcenterConnections) {
        $connectedVcenterObjects = $vcenterConnections | Where-Object IsConnected
        if ($connectedVcenterObjects) {
            $connectedVcenters = $connectedVcenterObjects.Name
        }
    }

    if ($connectedVcenters) {
        foreach ($vcenterName in $connectedVcenters) {
            Write-LogMessage -Type ADVISORY -AppendNewLine -Message "Already connected to vCenter `"$vcenterName`"."
        }
    }

    # Collect details of VCF domains to get vCenter FQDN and WLD name.
    try {
        $response = (Invoke-VcfGetDomains).Elements | Sort-Object
    } catch [Exception] {
        if ($Error[0].Exception.Message -match "TOKEN_NOT_FOUND") {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "Not connected to an SDDC Manager, please reconnect."
        } else {
            Write-LogMessage -Type ERROR -AppendNewLine "Unexpected error retrieving VCF Domain List: $($Error[0].Exception.Message)"
        }
    }
    if (-not $response) {
        Exit-WithCode -exitCode $Script:ExitCodes.OPERATION_FAILED -message "Failed to retrieve VCF domains"
    }

    # This is very unlikely, but the remaining calls in this function depend on properly-formed.
    # VCF WLD output.
    if ([String]::IsNullOrEmpty($response)) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Unable to list VCF Workload Domains: $($Error[0])"
        Show-AnyKey
        break
    }

    # Determine the management SSO domain.
    $mgmtDomain = (Invoke-VcfGetDomains -type MANAGEMENT).Elements

    # Verify the user has sufficient permissions to pull vCenter credentials from SDDC Manager.
    # Operator and Viewer do not have access to SSO credentials.
    try {
        $mgmtSsoDomainElements = (Invoke-VcfGetCredentials -accountType SYSTEM -ResourceType PSC).Elements | Where-Object { $_.Resource.DomainName -eq $($mgmtDomain.Name) -and $_.Username -match "@$($mgmtDomain.SsoName)" }
    }
    catch {
        if ($($Error[0]) -match "Forbidden") {
            $accessDenied = 'true'
        }
    }
    if (-not $mgmtSsoDomainElements) {
        if ($accessDenied -eq 'true') {
            Write-LogMessage -Type ERROR -AppendNewLine -Message "Your SDDC Manager SSO user does not have sufficient access. Please reconnect to SDDC Manager as a user with the ADMIN role."
        } else {
            $sddcName = if ($sddcConnection) { $sddcConnection.Name } else { "Unknown" }
            Write-LogMessage -Type ERROR -AppendNewLine -Message "Cannot retrieve vCenter credentials from SDDC Manager `"$sddcName`"."
        }
        Show-AnyKey
        if ($Headless -eq "disabled") {
            Show-MainMenu
        } else {
            Exit-WithCode -exitCode $Script:ExitCodes.AUTHENTICATION_ERROR -message "Insufficient permissions to retrieve vCenter credentials"
        }
    }

    $mgmtSsoDomainUsername = $($mgmtSsoDomainElements).Username
    $mgmtSsoDomainPassword = ConvertTo-SecureString -String $($mgmtSsoDomainElements).Password -AsPlainText -Force
    $mgmtSsoDomainCredentials = New-Object System.Management.Automation.PSCredential($mgmtSsoDomainUsername, $mgmtSsoDomainPassword)
    Clear-Variable -Name mgmtSsoDomainElements

    $workloadDomainNames = (Invoke-VcfGetDomains).Elements

    # Connect to each workload domain's vCenter using MGMT or isolated SSO credentials.
    foreach ($workloadDomainName in $workloadDomainNames) {
        $vcenter = $($workloadDomainName.Vcenters.fqdn)
        $disconnectedVcenter = $false  # Initialize for each vCenter in loop

        if ($workloadDomainName.IsManagementSsoDomain) {
            $vcenterCredential = $mgmtSsoDomainCredentials
        } else {
            $isolatedWldDomain = (Invoke-VcfGetDomains).Elements | Where-Object Name -eq $workloadDomainName.Name
            $isolatedWldSsoDomainElements = (Invoke-VcfGetCredentials -accountType SYSTEM -ResourceType PSC).Elements | Where-Object { $_.Resource.DomainName -eq $($isolatedWldDomain.Name) -and $_.Username -match "@$($isolatedWldDomain.SsoName)" }
            $isolatedWldSsoDomainUsername = $($isolatedWldSsoDomainElements).Username
            $isolatedWldSsoDomainPassword = ConvertTo-SecureString -String $($isolatedWldSsoDomainElements).Password -AsPlainText -Force
            # Destroy the variable that contains the non-secured password, now that it's no longer needed.
            Clear-Variable -Name isolatedWldSsoDomainElements
            $vcenterCredential = New-Object System.Management.Automation.PSCredential($isolatedWldSsoDomainUsername, $isolatedWldSsoDomainPassword)
        }

        $connectedToVcenterServer = Connect-VIServer -Server $vcenter -Credential $vcenterCredential -ErrorAction SilentlyContinue
        if (-not $connectedToVcenterServer) {
            if ($($Error[0].Exception.InnerException.Message) -match "The request channel timed out attempting" ) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Attempted connection to `"$vcenter`" request timed out.  Please verify you have access to `"https://$vcenter`" from this system and vCenter services are healthy."
            } else {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "`"$vcenter`": $($Error[0].Exception.InnerException.Message)"
            }
        }

        if ($connectedToVcenterServer) {
            $vcenterVersion = Get-VcenterVersion $vcenter
            if ([double]$vcenterVersion -lt [double]$minimumVcenterRelease) {
                Write-LogMessage -Type ERROR -PrependNewLine -AppendNewLine -Message "`"$vcenter`" is at $vcenterVersion which is less than the minimum release of $minimumVcenterRelease required by this script"
                Write-LogMessage -Type INFO -AppendNewLine -Message "Disconnecting from incompatible vCenter `"$vcenter`"."
                Disconnect-Vcenter -Vcenter $vcenter
                $disconnectedVcenter = $true
            }
        }
        # rare case where SOAP connections fail even though JSON ones succeed.
        if (-not $disconnectedVcenter) {

            $response = Connect-CisServer -Server $vcenter -Credential $vcenterCredential -ErrorAction SilentlyContinue

            if (-not $response) {
                Write-LogMessage -Type INFO -PrependNewLine -Message "Failed to connect to vCenter `"$vcenter`" through Connect-CisServer: $($Error[0].Exception.InnerException.Message)"
                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Failed to connect to vCenter through Connect-CisServer"
            }

        }

        if (($connectedToVcenterServer) -and (-not $disconnectedVcenter)) {
            Write-LogMessage -Type INFO -AppendNewLine -Message "Successfully connected to vCenter `"$vcenter`"."
            # Log information on vCenter version.
            Get-VcenterVersion -Vcenter $vcenter -Silence -FullVersion
        }
    }
}
Function Show-Version {

    <#
        .SYNOPSIS
        The function Show-Version shows the version of the script.

        .DESCRIPTION
        The function provides version information.

        .EXAMPLE
        Show-Version

        .EXAMPLE
        Show-Version -Silence

        .PARAMETER Silence
        Specifies the option to not display the output to screen.
    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$silence
    )

    if (-not $silence) {
        Write-LogMessage -type INFO -message "Version: $scriptVersion"
    } else {
        Write-LogMessage -Type DEBUG -message "Version: $scriptVersion"
    }
}
Function Select-EndpointType {

    <#
        .SYNOPSIS
        The function Select-EndpointType enables a user to a deployment type.

        .DESCRIPTION
        The function assists a user in selecting a VCF managed environment or vCenter-environment
        through menu-driven operations.

        .EXAMPLE
        Select-EndpointType
    #>

    $decision = New-ChoiceMenu -Question "Is this a VCF Deployment?" -DefaultAnswer no

    if ($decision -eq 0) {
        Connect-SddcManager
    } else {
        Write-Output ""
        # Loop to allow multiple vCenter connections
        $addAnotherVcenter = $true
        do {
            # Inner loop for connection retry
            $connectionSuccessful = $false
            do {
                # Prompt for vCenter connection details with validation loop
                do {
                    $vcenterFqdn = Read-Host "Enter vCenter FQDN"
                    if ([String]::IsNullOrWhiteSpace($vcenterFqdn)) {
                        Write-LogMessage -Type ERROR -Message "vCenter FQDN cannot be empty."
                    }
                } while ([String]::IsNullOrWhiteSpace($vcenterFqdn))

                # Prompt for username with validation loop
                do {
                    $vcenterUsername = Read-Host "Enter vCenter username"
                    if ([String]::IsNullOrWhiteSpace($vcenterUsername)) {
                        Write-LogMessage -Type ERROR -Message "vCenter username cannot be empty."
                    }
                } while ([String]::IsNullOrWhiteSpace($vcenterUsername))

                # Prompt for password with validation loop
                do {
                    $vcenterPassword = Read-Host "Enter vCenter password" -AsSecureString
                    if (-not $vcenterPassword -or $vcenterPassword.Length -eq 0) {
                        Write-LogMessage -Type ERROR -Message "vCenter password cannot be empty."
                    }
                } while (-not $vcenterPassword -or $vcenterPassword.Length -eq 0)

                # Create PSCredential object from username and password
                $vcenterCredential = New-Object System.Management.Automation.PSCredential($vcenterUsername, $vcenterPassword)

                # Attempt connection with noExit flag to handle failure gracefully
                $connectionSuccessful = Connect-Vcenter -noExit -serverName $vcenterFqdn -serverCredential $vcenterCredential -serverType "vCenter"

            } while (-not $connectionSuccessful)

            # After successful connection, ask if user wants to add another vCenter
            Write-Output ""
            $addMoreDecision = New-ChoiceMenu -Question "Would you like to connect to another vCenter?" -DefaultAnswer no
            $addAnotherVcenter = ($addMoreDecision -eq 0)

            if ($addAnotherVcenter) {
                Write-Output ""
            }
        } while ($addAnotherVcenter)
    }
}
Function Disconnect-SddcManager {

    <#
        .SYNOPSIS
        The function Disconnect-SddcManager disconnects from SDDC Manager.

        .DESCRIPTION
        The function assists disconnecting from SDDC Manager. It's called in the following ways: automatically when
        exiting the interactive mode, and through a prompt when a user wishes to Switch SDDC managers through the
        interactive and headless mode.

        .EXAMPLE
        Disconnect-SddcManager -OverrideQuestion "Do you really want to disconnect?"

        .EXAMPLE
        Disconnect-SddcManager -NoPrompt

        .EXAMPLE
        Disconnect-SddcManager -silence

        .PARAMETER overrideQuestion
        Specifies an override prompt for disconnecting from SDDC Manager.

        .PARAMETER noPrompt
        Specifies the option to disconnect without confirmation.

        .PARAMETER silence
        Specifies the option to not display the output to screen.
    #>

    Param (
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$noPrompt,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [String]$overrideQuestion,
        [Parameter (Mandatory = $false)] [ValidateNotNullOrEmpty()] [Switch]$silence
    )

    # Get SDDC connection for strict mode compliance
    $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global

    if (-not ($sddcConnection -and $sddcConnection.IsConnected))  {
        if (-not $Silence) {
            Write-LogMessage -Type INFO -Message "No SDDC Manager connection was detected."
        }
    } else {
        # Declare SDDC Manager variable so the name can be logged after disconnection.
        $sddcManagerFqdn = $sddcConnection.Name
        $decision = 1  # Default to "No" if noPrompt

        if (-not $noPrompt) {
            if ($overrideQuestion) {
                $decision = New-ChoiceMenu -Question "$overrideQuestion" -DefaultAnswer no
            } else {
                $decision = New-ChoiceMenu -Question "Would you like to disconnect from `"$sddcManagerFqdn`"" -DefaultAnswer no
            }
        }

        # Check if the user chose option 0, yes do disconnect from vCenter.
        if (($decision -eq 0) -or ($noPrompt)) {
            try {
                Disconnect-VcfSddcManagerServer -Server $sddcConnection.Name
            } catch [Exception] {
                Write-LogMessage -Type DEBUG -Message "Exception during SDDC Manager disconnect: $($_.Exception.Message)"
            }
            if ($?) {
                if ($silence) {
                    Write-LogMessage -Type DEBUG -Message "Successfully disconnected from SDDC Manager `"$sddcManagerFqdn`"."
                } else {
                    Write-LogMessage -Type INFO -AppendNewLine -Message "Successfully disconnected from SDDC Manager `"$sddcManagerFqdn`"."
                }
            } else {
                if ( ($Error[0].Exception.Message) -match "The request was canceled due to the configured HttpClient.Timeout") {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Failed to disconnect from SDDC Manager `"$sddcManagerFqdn`", as it is not reachable from this script execution system."
                } else {
                    Write-LogMessage -Type ERROR -AppendNewLine -Message "Failed to disconnect from SDDC Manager `"$sddcManagerFqdn`" : $($Error[0].Exception.Message)."
                }
            }
        } else {
            Write-LogMessage -Type DEBUG -Message "User chose not to disconnect from `"$sddcManagerFqdn`"."
        }
    }
}
Function Show-Help {

    <#
       .SYNOPSIS
       The function Show-Help shows available headless operations.

       .DESCRIPTION
       The function provides guidance for headless operations.

       .EXAMPLE
       Show-Help
   #>

    Write-Output "`nIf no parameters are specified, a menu-driven interface is presented.`n"
    Write-Output "Options:`n"
    Write-Output "-Check:                               # Check Current Depot Settings for all connected vCenter(s) and the SDDC Manager (if utilized)."
    Write-Output "   -Silence                           #   * Optional parameter: Silence.`n"
    Write-Output "-Connect                              # Connect to SDDC Manager or vCenter"
    Write-Output "   -Endpoint                          #   * Required parameter: VCF or vCenter"
    Write-Output "   -JsonInput <credential file>       #   * Optional parameter: override for credential file (default: SddcManagerCredentials.json)."
    Write-Output "   -Silence                           #   * Optional parameter: Silence.`n"
    Write-Output "-Disconnect                           # Disconnect from all connected vCenter and SDDC Manager endpoints."
    Write-Output "   -Silence                           #   * Optional parameter: Silence.`n"
    Write-Output "-DryRun                               # Validate that the new URLs with your download token are reachable from your system."
    Write-Output "   -Silence                           #   * Optional parameter: Silence.`n"
    Write-Output "-Update                               # Update Depots."
    Write-Output "    -DownloadToken                    #   * Required parameter: DownloadToken."
    Write-Output "    -Silence                          #   * Optional parameter: Silence.`n"
    Write-Output "-Help                                 # Get Help (show this Message).`n"
    Write-Output "-Version                              # Show script version.`n"
}
Function Get-Preconditions {

    <#
       .SYNOPSIS
       The function Get-Preconditions checks to if the script's preconditions are met.

       .DESCRIPTION
       The function provides will exit if any conditions it not met.

       .EXAMPLE
        Get-Preconditions
   #>

    # Check Powershell release
    $currentPsVersion = ($PSVersionTable.PSVersion.Major),($PSVersionTable.PSVersion.Minor) -join "."

    if ( $currentPsVersion -lt $psVersionMinVersion) {
       Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "Powershell $psVersionMinVersion or higher is required (current: $currentPsVersion)"
    }

    # PowerCLI Module and Version Check
    $vcfModuleName = "VCF.PowerCLI"

    $vcfPowerCliModule = (Get-Module -ListAvailable -Name $vcfModuleName -ErrorAction SilentlyContinue) | Sort-Object Revision | Select-Object -First 1

    if (-not $vcfPowerCliModule) {
        Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "VCF.PowerCLI module not found. Please install it"
    }

    # PowerCLI Configuration Check
    try {
        $Response = Get-PowerCLIConfiguration | Where-Object -Property DefaultVIServerMode -eq "Multiple" | Where-Object -Property Scope -in ("User","Session")
    } catch [Exception] {
        if ($_.Exception.Message -match "is not recognized as a name of a cmdlet") {
            Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "Cannot find Get-PowerCLIConfiguration. You may need to reinstall PowerCLI"
        } else {
            Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "Get-PowerCLIConfiguration Error: $($_.Exception.Message)"
        }
    }

    if (-not $Response) {
        Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "PowerCLI must be configured to connect to multiple vCenters simultaneously. Run: Set-PowerCLIConfiguration -DefaultVIServerMode Multiple"
    }

    # Windows 2012 and below do not support the default TLS cyphers required for recent
    # versions of Powershell.
    if ($IsWindows) {
        if ([Environment]::OSVersion.Version.Major -lt 10) {
          Exit-WithCode -exitCode $Script:ExitCodes.PRECONDITION_ERROR -message "Windows Server 2016+ or Windows 10+ required"
        }
    }
}
Function Show-MainMenu {

    <#
        .SYNOPSIS
        The function Show-MainMenu shows the interactive menu.

        .DESCRIPTION
        The function facilitates a guided, interactive workflow.

        .EXAMPLE
        Show-MainMenu
    #>

    Do {
        # Initialize error message variable
        $errout = ""

        # Check for environment override for colors
        if ($env:OverrideMenuForegroundColor) {
            $validColors = [enum]::GetValues([System.ConsoleColor])
            foreach ($validColor in $validColors) {
                if ($validColor -eq ($env:OverrideMenuForegroundColor)) {
                    $foregroundColor = $env:OverrideMenuForegroundColor
                }
            }
            if (-not $foregroundColor) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "`"$env:OverrideMenuForegroundColor`" is an invalid system console color choice.  Please run `"[enum]::GetValues([System.ConsoleColor])`" to see a list of valid colors.  Exiting."
                Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Invalid menu foreground color"
            }
        } else {
            $foregroundColor = "White"
        }

        Write-Host -Object "`nVMware Depot Update Menu.`n" -ForegroundColor Cyan
        Write-Host -Object " 1. Choose deployment type and connect."  -ForegroundColor $foregroundColor
        Write-Host -Object " 2. Enter your download token."  -ForegroundColor $foregroundColor
        Write-Host -Object " 3. Check depot configurations." -ForegroundColor $foregroundColor
        Write-Host -Object " 4. Update depot configurations." -ForegroundColor $foregroundColor
        Write-Host -Object " 5. (Optional) Dry run (validate token)" -ForegroundColor $foregroundColor
        Write-Host -Object " 6. (Optional) Disconnect from endpoints." -ForegroundColor $foregroundColor
        Write-Host -Object " 7. (Optional) Show Version." -ForegroundColor $foregroundColor
        Write-Host -Object " Q. Press Q to Quit" -ForegroundColor Cyan;
        Write-Host -Object $errout
        $menuInput = Read-Host -Prompt '(1-7 or Q)'
        $menuInput = $menuInput -replace "`t|`n|`r",""
        Switch ($menuInput)
        {
            1
            {
                Clear-Host
                Select-EndpointType
                Show-AnyKey
                Show-MainMenu
            }
            2
            {
                Clear-Host
                Select-DownloadToken
                Show-AnyKey
                Show-MainMenu
            }
            3
            {
                Clear-Host
                Show-DepotConfiguration
                Show-AnyKey
                Show-MainMenu
            }
            4
            {
                Clear-Host
                if (-not $Script:DownloadTokenMenuInterface) {
                    Select-DownloadToken
                }
                Set-DepotConfiguration -DownloadToken $Script:DownloadTokenMenuInterface
                Show-AnyKey
                Show-MainMenu
            }
            5
            {
                Clear-Host
                if (-not $Script:DownloadTokenMenuInterface) {
                    Select-DownloadToken
                }
                Set-DepotConfiguration -DownloadToken $Script:DownloadTokenMenuInterface -DryRun
                Show-AnyKey
                Show-MainMenu
            }

            6
            {
                Clear-Host
                $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
                If ($sddcConnection -and $sddcConnection.IsConnected) {
                    Disconnect-SddcManager -NoPrompt
                    Remove-Variable -ErrorAction SilentlyContinue -Name SddcManagerRootPassword -Scope Global
                }
                Disconnect-Vcenter -AllServers
                Show-AnyKey
                Show-MainMenu
            }
            7
            {
                Clear-Host
                Show-Version
                Show-AnyKey
                Show-MainMenu
            }
            Q
            {
                $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
                If ($sddcConnection -and $sddcConnection.IsConnected) {
                    Disconnect-SddcManager -NoPrompt -Silence
                    Remove-Variable -ErrorAction SilentlyContinue -Name SddcManagerRootPassword -Scope Global
                }
                Disconnect-Vcenter -AllServers -Silence
                Remove-Variable -ErrorAction SilentlyContinue -Name DownloadTokenMenuInterface -Scope Global
                Exit
            }
            Default
            {
                $errout = 'Invalid option please try again...'
            }
        }
    }
    Until ($menuInput -eq 'q')
}

# Variables and Constants
$ConfirmPreference = "None"
$Global:ProgressPreference = 'SilentlyContinue'  # Must be Global for PowerShell to respect it
$scriptVersion = '1.1.0.0.51'
$psVersionMinVersion = '7.2'
$downloadTokenLength = '32'
$minimumVcenterRelease = '7.0'
$minimumVcfRelease = '4.5'
$vcf52Release = '5.2'
$vcf9xRelease = '9'

$Script:LogOnly = "disabled"

New-LogFile
if (-not $env:SkipChecks) {
    Get-Preconditions
}

if ($Help) {
    Show-Help
    Exit-WithCode -exitCode $Script:ExitCodes.SUCCESS -message "Help displayed"
}

# assume headless mode until all conditions have been checked
$Script:Headless = 'enabled'

if ($Silence) {
    $Script:LogOnly = "enabled"
}

switch ($true) {
    $check {
    Show-DepotConfiguration
    }
    $connect {
        if ((-not $jsonInput) -or (-not $endpoint)) {
            Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Required parameters to follow -Connect are -JsonInput <File> -Endpoint <Vcf|Vcenter>"
        }

        if ($jsonInput) {
            $jsonInputExists = Test-Path $jsonInput
        # We can only proceed if the JsonInput file exists.
            if ($jsonInputExists) {
                switch ($endpoint) {
                    "Vcenter" {
                        Write-LogMessage -Type INFO -Message "Preparing to connect to vCenter(s) using inputs provided by `"$jsonInput`"..."

                        $vcenterCredentials = ConvertFrom-JsonSafely -jsonFilePath $jsonInput

                        # Ensure we have an array even if there's only one object
                        if ($vcenterCredentials -isnot [Array]) {
                            $vcenterCredentials = @($vcenterCredentials)
                        }

                        foreach ($vcenterEntry in $vcenterCredentials) {
                            # Validate required properties
                            if (-not ($vcenterEntry.PSObject.Properties.Name -contains "VcenterFqdn")) {
                                Exit-WithCode -exitCode $Script:ExitCodes.CONFIGURATION_ERROR -message "Required property 'VcenterFqdn' not found in `"$jsonInput`""
                            }
                            if (-not ($vcenterEntry.PSObject.Properties.Name -contains "VcenterUsername")) {
                                Exit-WithCode -exitCode $Script:ExitCodes.CONFIGURATION_ERROR -message "Required property 'VcenterUsername' not found in `"$jsonInput`""
                            }
                            if (-not ($vcenterEntry.PSObject.Properties.Name -contains "VcenterPassword")) {
                                Exit-WithCode -exitCode $Script:ExitCodes.CONFIGURATION_ERROR -message "Required property 'VcenterPassword' not found in `"$jsonInput`""
                            }

                            $vcenterFqdn = $vcenterEntry.VcenterFqdn
                            $username = $vcenterEntry.VcenterUsername
                            $password = ConvertTo-SecureString $vcenterEntry.VcenterPassword -AsPlainText -Force
                            $credential = New-Object System.Management.Automation.PSCredential($username, $password)

                            # Connect to vCenter
                            $connectionResult = Connect-Vcenter -serverName $vcenterFqdn -serverCredential $credential -serverType "vCenter" -noExit

                            if (-not $connectionResult) {
                                Exit-WithCode -exitCode $Script:ExitCodes.CONNECTION_ERROR -message "Failed to connect to vCenter `"$vcenterFqdn`""
                            }
                        }
                    }
                    "Vcf" {
                        Connect-SddcManager -JsonInputFile $jsonInput
                    }
                    Default {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Endpoint must be specified and be of value Vcf or Vcenter."
                    }
            }
        } else {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "JsonInput file `"$jsonInput`" not found."
                if (($endpoint -ne "Vcenter") -and ($endpoint -ne "Vcf")) {
                Write-LogMessage -Type ERROR -AppendNewLine -Message "Endpoint must be specified and be of value Vcf or Vcenter."
            }
                Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "JsonInput file not found"
        }
    }
        if (-not $jsonInput) {
        Write-LogMessage -Type ERROR -AppendNewLine -Message "Required parameter -JsonInput <JsonFile> not found."
            Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Required parameter -JsonInput not found"
    }
    }
    $disconnect {
        Disconnect-Vcenter -AllServers
        $sddcConnection = Get-Variable -Name DefaultSddcManagerConnections -ValueOnly -ErrorAction SilentlyContinue -Scope Global
        If ($sddcConnection -and $sddcConnection.IsConnected) {
        Disconnect-SddcManager -NoPrompt
        Remove-Variable -ErrorAction SilentlyContinue -Name SddcManagerRootPassword -Scope Global
    }
    }
    $dryRun {
        if (-not $downloadToken) {
            Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Required parameter -DownloadToken not found"
    } else {
            Set-DepotConfiguration -DownloadToken $downloadToken -DryRun
        }
    }
    $update {
        if (-not $downloadToken) {
            Exit-WithCode -exitCode $Script:ExitCodes.PARAMETER_ERROR -message "Required parameter -DownloadToken not found"
        } elseif ($skipSddcManagerTaskCheck) {
            Set-DepotConfiguration -DownloadToken $downloadToken -SkipSddcManagerTaskCheck
        } else {
            Set-DepotConfiguration -DownloadToken $downloadToken
        }
    }
    $version {
    Show-Version
    }
    Default {
    # Clear DownloadTokenMenuInterface before continuing, in case a user didn't quit using "q" from the main menu.
    Remove-Variable -ErrorAction SilentlyContinue -Name DownloadTokenMenuInterface -Scope Global
    $Script:Headless = 'disabled'
    Show-MainMenu
    }
}