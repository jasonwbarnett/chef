#
# Author:: Doug Ireton <doug@1strategy.com>
# Copyright:: 2012-2018, Nordstrom, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# See here for more info:
# http://msdn.microsoft.com/en-us/library/windows/desktop/aa394492(v=vs.85).aspx

require "chef/resource"

class Chef
  class Resource
    class WindowsPrinterPort < Chef::Resource
      require "resolv"

      resource_name :windows_printer_port
      provides(:windows_printer_port) { true }

      description "Use the windows_printer_port resource to create and delete TCP/IPv4 printer ports on Windows."
      introduced "14.0"

      property :ipv4_address, String,
               name_property: true,
               regex: Resolv::IPv4::Regex,
               validation_message: "The ipv4_address property must be in the format of WWW.XXX.YYY.ZZZ!",
               description: "An optional property for the IPv4 address of the printer if it differs from the resource block's name."

      property :port_name, String,
               description: "The port name.",
               default: lazy { "IP_#{ipv4_address}" }

      property :port_number, Integer,
               description: "The port number.",
               default: 9100

      property :port_description, String,
               description: "The description of the port."

      property :snmp_enabled, [TrueClass, FalseClass],
               description: "Determines if SNMP is enabled on the port.",
               default: false

      property :port_protocol, Symbol,
               description: "The printer port protocol: :raw or :lpr",
               validation_message: "port_protocol must be either :raw or :lpr",
               default: :raw, equal_to: [:raw, :lpr],
               coerce: proc { |x|
                 if x.is_a?(String)
                   x.to_sym
                 elsif x.is_a?(Integer)
                   if x == 1
                     :raw
                   elsif x ==2
                     :lpr
                   else
                     x
                   end
                 else
                   x
                 end
               }

      PRINTING_ADMIN_SCRIPTS_DIR = 'C:\\windows\\system32\\Printing_Admin_Scripts\\en-US'.freeze unless defined?(PRINTING_ADMIN_SCRIPTS_DIR)

      def port_names
        so = shell_out!("cscript.exe \"#{PRINTING_ADMIN_SCRIPTS_DIR}\\prnport.vbs\" -l")
        port_names = []
        so.stdout.encode(universal_newline: true).each_line do |line|
          port_names << line[/Port name (.+)$/, 1] if line =~ /^Port name .+$/
        end
        port_names
      end

      def port_configuration
        so = shell_out!("cscript.exe \"#{PRINTING_ADMIN_SCRIPTS_DIR}\\prnport.vbs\" -g -r \"#{port_name}\"")
        so.stdout.encode(universal_newline: true)
      end

      def port_exists?
        port_names.include?(port_name)
      end

      # @todo Set @current_resource port properties from registry
      load_current_value do |desired|
        current_value_does_not_exist! unless port_exists?

        name desired.name
        ipv4_address desired.ipv4_address
        port_name desired.port_name
        exists port_exists?
      end

      action :create do
        description "Create the new printer port if it does not already exist."

        if current_resource.exists
          Chef::Log.info "#{@new_resource} already exists - nothing to do."
        else
          converge_by("Create #{@new_resource}") do
            create_printer_port
          end
        end
      end

      action :delete do
        description "Delete an existing printer port."

        if current_resource.exists
          converge_by("Delete #{@new_resource}") do
            delete_printer_port
          end
        else
          Chef::Log.info "#{@current_resource} doesn't exist - can't delete."
        end
      end

      action_class do
        def create_printer_port
          # create the printer port using PowerShell
          declare_resource(:powershell_script, "Creating printer port #{new_resource.port_name}") do
            code <<-EOH

              Set-WmiInstance -class Win32_TCPIPPrinterPort `
                -EnableAllPrivileges `
                -Argument @{ HostAddress = "#{new_resource.ipv4_address}";
                            Name        = "#{new_resource.port_name}";
                            Description = "#{new_resource.port_description}";
                            PortNumber  = "#{new_resource.port_number}";
                            Protocol    = "#{new_resource.port_protocol}";
                            SNMPEnabled = "$#{new_resource.snmp_enabled}";
                          }
            EOH
          end
        end

        def delete_printer_port
          declare_resource(:powershell_script, "Deleting printer port: #{new_resource.port_name}") do
            code <<-EOH
              $port = Get-WMIObject -class Win32_TCPIPPrinterPort -EnableAllPrivileges -Filter "name = '#{new_resource.port_name}'"
              $port.Delete()
            EOH
          end
        end
      end
    end
  end
end
