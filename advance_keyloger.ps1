# ==============================
# Full Global Key Detector (PowerShell 7+ GUI)
# Detects ALL keys (0-255), duplicate-free, optional file log
# ==============================

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Path to log file (optional)
$logFile = "$env:USERPROFILE\Desktop\KeyLog.txt"
if (-not (Test-Path $logFile)) { New-Item -Path $logFile -ItemType File | Out-Null }

# Import GetAsyncKeyState from user32.dll
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class KeyState {
    [DllImport("user32.dll")]
    public static extern short GetAsyncKeyState(int vKey);
}
"@

# Hashtable to track pressed state
$pressed = @{}
0..255 | ForEach-Object { $pressed[$_] = $false }

# --- Create GUI ---
$form = New-Object System.Windows.Forms.Form
$form.Text = "Global Key Detector"
$form.Size = New-Object System.Drawing.Size(600,400)
$form.StartPosition = "CenterScreen"

# Label for log file
$label = New-Object System.Windows.Forms.Label
$label.Text = "Logging to: $logFile"
$label.AutoSize = $true
$label.Location = New-Object System.Drawing.Point(10,10)
$form.Controls.Add($label)

# Listbox for keys
$listBox = New-Object System.Windows.Forms.ListBox
$listBox.Location = New-Object System.Drawing.Point(10,40)
$listBox.Size = New-Object System.Drawing.Size(560,300)
$form.Controls.Add($listBox)

# Clear button
$clearBtn = New-Object System.Windows.Forms.Button
$clearBtn.Text = "Clear Log"
$clearBtn.Location = New-Object System.Drawing.Point(10,350)
$clearBtn.Add_Click({
    $listBox.Items.Clear()
})
$form.Controls.Add($clearBtn)

# Timer for checking keys
$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 50
$timer.Add_Tick({
    0..255 | ForEach-Object {
        $k = $_
        $state = [KeyState]::GetAsyncKeyState($k)
        if (($state -band 0x8000) -and (-not $pressed[$k])) {
            # Get key name if possible
            try {
                $keyName = [Enum]::GetName([System.Windows.Forms.Keys], $k)
                if (-not $keyName) { $keyName = "VK_$k" }
            } catch { $keyName = "VK_$k" }

            $msg = "$(Get-Date -Format 'HH:mm:ss') - $keyName"

            # Show in listbox
            $listBox.Items.Insert(0,$msg)
            if ($listBox.Items.Count -gt 1000) { $listBox.Items.RemoveAt($listBox.Items.Count-1) }

            # Save in log file
            "$((Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) - $keyName" | Out-File -FilePath $logFile -Append

            # Mark as pressed
            $pressed[$k] = $true
        }
        elseif (($state -band 0x8000) -eq 0) {
            $pressed[$k] = $false
        }
    }
})

# Start timer
$timer.Start()

# Run form
[void]$form.ShowDialog()
