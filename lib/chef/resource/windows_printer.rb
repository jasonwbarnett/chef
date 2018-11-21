#
# Author:: Doug Ireton (<doug@1strategy.com>)
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
    class WindowsPrinter < Chef::Resource
      require "resolv"

      resource_name :windows_printer
      provides(:windows_printer) { true }

      description "Use the windows_printer resource to setup Windows printers. Note that this doesn't currently install a printer driver. You must already have the driver installed on the system."
      introduced "14.0"

      property :device_id, String,
               description: "Printer queue name, such as 'HP LJ 5200 in fifth floor copy room'.",
               name_property: true

      property :comment, String,
               description: "Optional descriptor for the printer queue."

      property :default, [TrueClass, FalseClass],
               description: "Determines whether or not this should be the system's default printer.",
               default: false

      property :driver_name, String,
               description: "The exact name of printer driver installed on the system.",
               required: true

      property :location, String,
               description: "Printer location, such as 'Fifth floor copy room'."

      property :shared, [TrueClass, FalseClass],
               description: "Determines whether or not the printer is shared.",
               default: false

      property :share_name, String,
               description: "The name used to identify the shared printer."

      property :ipv4_address, String,
               description: "The IPv4 address of the printer, such as '10.4.64.23'",
               validation_message: "The ipv4_address property must be in the IPv4 format of WWW.XXX.YYY.ZZZ",
               regex: Resolv::IPv4::Regex

      property :exists, [TrueClass, FalseClass],
               skip_docs: true

      PRINTING_ADMIN_SCRIPTS_DIR = 'C:\\windows\\system32\\Printing_Admin_Scripts\\en-US'.freeze unless defined?(PRINTING_ADMIN_SCRIPTS_DIR)

      def printer_names
        so = shell_out!("cscript.exe \"#{PRINTING_ADMIN_SCRIPTS_DIR}\\prnmngr.vbs\" -l")
        printers = []
        so.stdout.each_line do |line|
          printer << line[/Printer name (.*)$/, 1] if line =~ /^Printer name /
        end
        printers
      end

      def default_printer
        # PS C:\windows\system32\Printing_Admin_Scripts\en-US> & cscript .\prnmngr.vbs -g
        # Microsoft (R) Windows Script Host Version 5.8
        # Copyright (C) Microsoft Corporation. All rights reserved.
        #
        # The default printer is HP LaserJet 5th Floor
        so = shell_out!("cscript.exe \"#{PRINTING_ADMIN_SCRIPTS_DIR}\\prnmngr.vbs\" -g")
        so.stdout[/The default printer is (.*)$/, 1]
      end

      # does the printer exist
      #
      # @param [String] name the name of the printer
      # @return [Boolean]
      def printer_exists?(name)
        printer_names.include?(name)
      end

      # @todo Set @current_resource printer properties from registry
      load_current_value do |desired|
        name desired.name
        exists printer_exists?(desired.name)
      end

      action :create do
        description "Create a new printer and a printer port if one doesn't already exist."

        if @current_resource.exists
          Chef::Log.info "#{@new_resource} already exists - nothing to do."
        else
          converge_by("Create #{@new_resource}") do
            create_printer
          end
        end
      end

      action :delete do
        description "Delete an existing printer. Note this does not delete the associated printer port."

        if @current_resource.exists
          converge_by("Delete #{@new_resource}") do
            delete_printer
          end
        else
          Chef::Log.info "#{@current_resource} doesn't exist - can't delete."
        end
      end

      action_class do
        # creates the printer port and then the printer
        def create_printer
          # Create the printer port first
          windows_printer_port new_resource.ipv4_address do
          end

          port_name = "IP_#{new_resource.ipv4_address}"

          declare_resource(:powershell_script, "Creating printer: #{new_resource.name}") do
            code <<-EOH

              Set-WmiInstance -class Win32_Printer `
                -EnableAllPrivileges `
                -Argument @{ DeviceID   = "#{new_resource.device_id}";
                            Comment    = "#{new_resource.comment}";
                            Default    = "$#{new_resource.default}";
                            DriverName = "#{new_resource.driver_name}";
                            Location   = "#{new_resource.location}";
                            PortName   = "#{port_name}";
                            Shared     = "$#{new_resource.shared}";
                            ShareName  = "#{new_resource.share_name}";
                          }
            EOH
          end
        end

        def delete_printer
          declare_resource(:powershell_script, "Deleting printer: #{new_resource.name}") do
            code <<-EOH
              $printer = Get-WMIObject -class Win32_Printer -EnableAllPrivileges -Filter "name = '#{new_resource.name}'"
              $printer.Delete()
            EOH
          end
        end
      end
    end
  end
end
