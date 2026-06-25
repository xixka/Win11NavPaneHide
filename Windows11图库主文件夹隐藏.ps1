<#
.SYNOPSIS
    Windows 11 导航栏管理工具
.DESCRIPTION
    管理图库的显示/隐藏，并支持开启/恢复主文件夹。
    自动提权，内嵌 C# 代码处理 TrustedInstaller 权限。
#>

# 1. 自动申请管理员权限
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

$regExePath = "HKEY_CLASSES_ROOT\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"
$subKeyPath = "CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}"
$valueName = "System.IsPinnedToNameSpaceTree"

# 2. 定义启用高级权限的 C# 代码
$privilegeCode = @"
using System;
using System.Runtime.InteropServices;

public class PrivilegeManager
{
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TOKEN_PRIVILEGES newst, int len, IntPtr prev, IntPtr relen);

    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }

    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

    public static void EnablePrivilege(string privilege)
    {
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref hToken))
        {
            throw new Exception("OpenProcessToken failed");
        }

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!LookupPrivilegeValue(null, privilege, ref tp.Luid))
        {
            throw new Exception("LookupPrivilegeValue failed for " + privilege);
        }

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            throw new Exception("AdjustTokenPrivileges failed for " + privilege);
        }
    }
}
"@

# 编译并加载 C# 代码
Add-Type -TypeDefinition $privilegeCode

function Write-Msg {
    param ([string]$Type, [string]$Message)
    switch ($Type) {
        "Info"    { Write-Host "[i] $Message" -ForegroundColor Cyan }
        "Success" { Write-Host "[✅ 成功] $Message" -ForegroundColor Green }
        "Error"   { Write-Host "[❌ 失败] $Message" -ForegroundColor Red }
        "Warn"    { Write-Host "[⚠️ 警告] $Message" -ForegroundColor Yellow }
    }
}

function Get-CurrentState {
    try {
        $val = (Get-ItemProperty -Path "Registry::$regExePath" -Name $valueName -ErrorAction SilentlyContinue).$valueName
        if ($val -eq 0) { return "Closed" }
        elseif ($val -eq 1) { return "Open" }
        else { return "Unknown" }
    } catch {
        return "Unknown"
    }
}

function Modify-Gallery {
    param ([string]$Action) # "Set0" 或 "Set1"
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  开始执行操作..." -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    try {
        # 强制启用系统底层权限
        [PrivilegeManager]::EnablePrivilege("SeTakeOwnershipPrivilege")
        [PrivilegeManager]::EnablePrivilege("SeRestorePrivilege")
        [PrivilegeManager]::EnablePrivilege("SeSecurityPrivilege")

        Write-Msg -Type Info "步骤 1/3: 获取注册表权限..."
        $baseKey = [Microsoft.Win32.Registry]::ClassesRoot
        
        # 备份原始权限
        $keyBackup = $baseKey.OpenSubKey($subKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree, [System.Security.AccessControl.RegistryRights]::ReadPermissions)
        $originalAcl = $keyBackup.GetAccessControl()
        $keyBackup.Close()
        
        $admins = New-Object System.Security.Principal.NTAccount("Administrators")

        # 取得所有权
        $keyOwner = $baseKey.OpenSubKey($subKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::TakeOwnership)
        $tempAcl = $keyOwner.GetAccessControl()
        $tempAcl.SetOwner($admins)
        $keyOwner.SetAccessControl($tempAcl)
        $keyOwner.Close()

        # 添加完全控制权限
        $keyPerm = $baseKey.OpenSubKey($subKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $tempAcl2 = $keyPerm.GetAccessControl()
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($admins, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
        $tempAcl2.AddAccessRule($rule)
        $keyPerm.SetAccessControl($tempAcl2)
        $keyPerm.Close()
        
        Write-Msg -Type Success "权限获取完毕"

        Write-Msg -Type Info "步骤 2/3: 修改注册表值..."
        $keyWrite = $baseKey.OpenSubKey($subKeyPath, $true)
        $targetValue = if ($Action -eq "Set0") { 0 } else { 1 }
        $keyWrite.SetValue($valueName, $targetValue, [Microsoft.Win32.RegistryValueKind]::DWord)
        $keyWrite.Close()
        Write-Msg -Type Success "注册表值已修改为 $targetValue"
    }
    catch {
        Write-Msg -Type Error "操作失败: $_"
        return $false
    }

    Write-Msg -Type Info "步骤 3/3: 恢复原始注册表权限..."
    try {
        $keyRestore = $baseKey.OpenSubKey($subKeyPath, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::ChangePermissions)
        $keyRestore.SetAccessControl($originalAcl)
        $keyRestore.Close()
        Write-Msg -Type Success "权限已完美还原"
    }
    catch {
        Write-Msg -Type Warn "权限还原失败，可能需要手动检查: $_"
    }
    
    return $true
}

function Toggle-HomeFolder {
    param ([string]$Action) # "Close" 或 "Restore"
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "  操作主文件夹" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan

    # HKCU 路径用于隐藏当前用户的主文件夹
    $hkcuPath = "HKCU:\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"
    # HKLM 路径用于恢复系统级的主文件夹注册项
    $hklmPath = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}"

    try {
        if ($Action -eq "Close") {
            Write-Msg -Type Info "正在关闭主文件夹..."
            if (-not (Test-Path $hkcuPath)) {
                New-Item -Path $hkcuPath -Force | Out-Null
            }
            Set-ItemProperty -Path $hkcuPath -Name "System.IsPinnedToNameSpaceTree" -Value 0 -Type DWord
            Write-Msg -Type Success "主文件夹已关闭！"
        }
        elseif ($Action -eq "Restore") {
            Write-Msg -Type Info "正在恢复主文件夹..."
            # 1. 删除 HKCU 下的隐藏覆盖项
            if (Test-Path $hkcuPath) {
                Remove-Item -Path $hkcuPath -Recurse -Force
            }
            # 2. 确保 HKLM 下的系统默认项存在
            if (-not (Test-Path $hklmPath)) {
                New-Item -Path $hklmPath -Force | Out-Null
                Set-ItemProperty -Path $hklmPath -Name "(default)" -Value "Home" -Type String
            }
            Write-Msg -Type Success "主文件夹已恢复！"
        }
    } catch {
        Write-Msg -Type Error "操作失败: $_"
    }
}

function Restart-Explorer {
    Write-Msg -Type Info "正在重启 Windows 资源管理器..."
    try {
        Stop-Process -Name explorer -Force -ErrorAction Stop
        Start-Sleep -Seconds 2
        if (-not (Get-Process -Name explorer -ErrorAction SilentlyContinue)) {
            Start-Process explorer.exe
        }
        Write-Msg -Type Success "资源管理器已重启。"
    } catch {
        Write-Msg -Type Error "重启失败，可能需要手动重启电脑: $_"
    }
}

# --- 主程序入口 (循环菜单) ---
while ($true) {
    Clear-Host
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "      Windows 11 导航栏管理工具" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan

    $state = Get-CurrentState
    $currentStateText = switch ($state) {
        "Closed" { "已关闭 (隐藏)" }
        "Open"   { "已开启 (显示)" }
        default  { "未知" }
    }

    Write-Host "`n当前图库状态: $currentStateText`n" -ForegroundColor Yellow

    Write-Host "请选择要执行的操作：" -ForegroundColor White
    Write-Host "  [1] 关闭图库 (隐藏)" -ForegroundColor White
    Write-Host "  [2] 开启图库 (显示)" -ForegroundColor White
    Write-Host "  [3] 关闭主文件夹" -ForegroundColor White
    Write-Host "  [4] 恢复主文件夹" -ForegroundColor White
    Write-Host "  [5] 重启资源管理器 (使更改立即生效)" -ForegroundColor White
    Write-Host "  [6] 退出脚本" -ForegroundColor White
    $choice = Read-Host "`n请输入选项 (1/2/3/4/5/6)"

    switch ($choice) {
        "1" {
            $result = Modify-Gallery -Action "Set0"
            if ($result) { Write-Host "`n🎉 图库已成功关闭！建议选择 [5] 重启资源管理器。" -ForegroundColor Green }
        }
        "2" {
            $result = Modify-Gallery -Action "Set1"
            if ($result) { Write-Host "`n🎉 图库已成功开启！建议选择 [5] 重启资源管理器。" -ForegroundColor Green }
        }
        "3" {
            Toggle-HomeFolder -Action "Close"
        }
        "4" {
            Toggle-HomeFolder -Action "Restore"
        }
        "5" {
            Restart-Explorer
        }
        "6" {
            Write-Host "已退出脚本。" -ForegroundColor Cyan
            exit
        }
        default {
            Write-Msg -Type Error "无效的输入，请重新选择。"
        }
    }

    Write-Host "`n按任意键返回菜单..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
